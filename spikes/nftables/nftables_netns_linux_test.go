//go:build linux

// Package nftablesspike is a THROWAWAY Phase 0.5 spike (Task M4). It proves that
// the rung-1 network boundary (Task 13c — nftables ADDRESS filtering) can be
// built with the pure-Go, no-cgo `github.com/google/nftables` netlink library:
// inside a fresh network namespace it installs an `inet filter` table whose
// `output` chain has policy DROP and a small ACCEPT allowlist, and then a probe
// confirms the ruleset is SCOPED — a loopback listener is reachable while the
// cloud metadata IP 169.254.169.254 is dropped.
//
// It is NOT shipped code. It lives in its own package, isolated from the root
// `package sandbox`, and runs only as a capability-gated test.
//
// # How the netns + CAP_NET_ADMIN is obtained
//
// Applying an nftables ruleset needs CAP_NET_ADMIN *in the target network
// namespace*. The self-contained, backend-shaped way to get that as an
// unprivileged user is to re-exec this test binary into a child created with
// SysProcAttr.Cloneflags = CLONE_NEWUSER|CLONE_NEWNET (plus a uid/gid map that
// makes the child root inside the new user namespace). That is exactly what the
// real backend (Task 13a/c) does to its stage-2 child. Because the WHOLE child
// process — every thread — lives in the new netns, the default `nftables.New()`
// netlink socket, the `lo` ioctls, and the probe dials all target that netns
// with no per-thread setns juggling.
//
// # Why it may SKIP (a skip is never a pass)
//
// The enforcement path only runs where the host permits BOTH (a) unprivileged
// user+net namespace creation and (b) an *effective* CAP_NET_ADMIN inside the
// new netns. On a host with `apparmor_restrict_unprivileged_userns=1` (Ubuntu
// 24.04+ default) the child namespace is created — the child even sees uid 0 —
// but the apparmor-restricted userns grants no usable CAP_NET_ADMIN, so the very
// first privileged op (bringing `lo` UP) returns EPERM. Either failure mode is
// detected and turned into a recorded t.Skip; the spike therefore runs for real
// only in CI (a privileged / userns-permitting container).
//
// # Anti-fail-open: what CI asserts
//
// A test that only checked "metadata unreachable" could pass in a sealed netns
// that has no routing at all (everything unreachable) — that is fail-open. So
// the assertions are paired around the SAME metadata IP:port to prove the
// nftables rule — not a blanket blackhole — is what blocks it:
//
//	METACONTROL: dial 169.254.169.254:80 BEFORE the ruleset is applied. The IP is
//	  assigned locally (lo alias), nothing listens, so connect() gets a RST =>
//	  REFUSED. This proves the address is routable/local, i.e. NOT a blackhole.
//	LOOPBACK (positive): dial the 127.0.0.1 listener AFTER the ruleset is applied
//	  => CONNECTED. Proves the DROP policy is scoped, not a blanket deny.
//	METADATA (negative): dial the SAME 169.254.169.254:80 AFTER the ruleset =>
//	  TIMEOUT (SYN silently dropped at the OUTPUT hook). The behaviour flipped
//	  from REFUSED to TIMEOUT with nothing changed but the ruleset — so nftables
//	  is provably the cause of the drop.
package nftablesspike

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// envChild is the sentinel that puts the re-exec'd binary into child mode: it is
// already inside the new user+net namespace and runs the setup + probes.
const envChild = "LRSANDBOX_NFT_CHILD"

// Marker keys the child prints (one "KEY=VALUE" line each) and the parent parses.
// Shared constants keep the two halves from drifting.
const (
	keyChild   = "CHILD"       // "STARTED": the child began running inside the ns
	keyCap     = "CAP"         // "OK" or "DENIED:<detail>": CAP_NET_ADMIN in netns
	keyLo      = "LO"          // "UP": loopback up + addresses assigned
	keyControl = "METACONTROL" // pre-ruleset dial of the metadata IP
	keyApply   = "APPLY"       // "OK": nftables ruleset flushed into the netns
	keyLoop    = "LOOPBACK"    // post-ruleset dial of the loopback listener
	keyMeta    = "METADATA"    // post-ruleset dial of the metadata IP
)

// Marker values.
const (
	valStarted   = "STARTED"
	valCapOK     = "OK"
	valLoUp      = "UP"
	valApplyOK   = "OK"
	dialRefused  = "REFUSED"   // connect() got a RST (reached the local stack)
	dialTimeout  = "TIMEOUT"   // no response before the deadline (dropped)
	dialConnect  = "CONNECTED" // handshake completed
	dialUnreach  = "UNREACH"   // no route to host / network unreachable
	capDenyPfx   = "DENIED:"   // prefix for the CAP=DENIED:<detail> marker
	applyErrPfx  = "ERR:"      // prefix for APPLY=ERR:<detail>
	dialErrPfx   = "ERR:"      // prefix for an unclassified dial error
	loErrPrefix  = "ERR:"      // prefix for LO=ERR:<detail>
	metadataAddr = "169.254.169.254:80"
)

// Network setup constants. The loopback listener binds 127.0.0.1; the cloud
// metadata IP 169.254.169.254 is assigned to the `lo:1` alias so that a dial to
// it is locally routed (traverses the OUTPUT hook) rather than failing at
// routing — that is what makes the negative assertion attributable to nftables.
var (
	loopbackIP    = [4]byte{127, 0, 0, 1}
	loopbackMask  = [4]byte{255, 0, 0, 0}
	metadataIP    = [4]byte{169, 254, 169, 254}
	metadataMask  = [4]byte{255, 255, 255, 255}
	metadataAlias = "lo:1"
)

// reg1 is nftables register 1 — the scratch register every match below loads
// into and compares against (register 0 is the verdict register).
const reg1 = uint32(1)

// Timeouts bound each probe dial so the test can never hang. They are dial
// deadlines only — never used in assertions (assertions compare marker strings).
const (
	metaDialTimeout = 500 * time.Millisecond // long enough to be sure DROP != slow
	loopDialTimeout = 2 * time.Second
)

// TestMain multiplexes the single re-exec hop. In child mode it runs the
// setup+probe flow inside the new namespace; otherwise it runs the normal suite.
func TestMain(m *testing.M) {
	if os.Getenv(envChild) != "" {
		os.Exit(runChild())
	}
	os.Exit(m.Run())
}

// TestNftablesNetnsEgressFilter drives the full backend-shaped flow: it re-execs
// this binary into a CLONE_NEWUSER|CLONE_NEWNET child, the child applies the
// egress ruleset and runs the paired probes, and the parent asserts the markers.
// On a host that cannot create the namespace, or creates it without an effective
// CAP_NET_ADMIN, the test records a specific t.Skip.
func TestNftablesNetnsEgressFilter(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), envChild+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		// Map the invoking uid/gid to root inside the new user namespace so the
		// child holds (subject to host policy) CAP_NET_ADMIN in the new netns.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// GidMappingsEnableSetgroups defaults to false, so Go writes "deny" to
		// /proc/<pid>/setgroups before gid_map — required for an unprivileged map.
	}

	out, runErr := cmd.CombinedOutput()
	markers := parseMarkers(out)

	// Gate 1: the child never started => the kernel/host refused the namespace
	// creation (e.g. userns disabled, or uid_map write denied). Skip, don't fail.
	if markers[keyChild] != valStarted {
		t.Skipf("nftables netns spike requires unprivileged userns + netns creation "+
			"(CAP_NET_ADMIN in a new netns): user+net namespace creation failed on this "+
			"host (e.g. apparmor_restrict_unprivileged_userns=1 blocks unprivileged "+
			"userns): %v\nchild output:\n%s", runErr, out)
	}

	// Gate 2: the namespace WAS created but grants no effective CAP_NET_ADMIN, so
	// the first privileged op (loopback UP) returned EPERM and the child printed
	// CAP=DENIED:<detail>. This is the observed mode under
	// apparmor_restrict_unprivileged_userns=1. Skip ONLY on that explicit denial —
	// never on a merely-absent CAP marker, which would misclassify a genuine setup
	// regression (a socket() failure, a non-EPERM ioctl bug, a panic between
	// CHILD=STARTED and the capability probe) as a green environment skip. A skip
	// is never a pass, so those cases must fail loudly.
	capMark := markers[keyCap]
	switch {
	case strings.HasPrefix(capMark, capDenyPfx):
		t.Skipf("nftables netns spike requires unprivileged userns + netns creation "+
			"(CAP_NET_ADMIN in a new netns): the user+net namespace was created but grants "+
			"no effective CAP_NET_ADMIN inside the new netns "+
			"(apparmor_restrict_unprivileged_userns=1 restricts capabilities in "+
			"unprivileged user namespaces): %s\nchild output:\n%s", capMark, out)
	case capMark != valCapOK:
		t.Fatalf("child started but did not resolve the CAP_NET_ADMIN probe "+
			"(no CAP=OK and no CAP=DENIED — it died before the capability was determined): "+
			"CAP=%q, exit=%v\nchild output:\n%s", capMark, runErr, out)
	}

	// Past the gates the child had the capability, so any nonzero exit or missing
	// marker is a genuine failure, not an environment limitation.
	if runErr != nil {
		t.Fatalf("child exited nonzero after acquiring CAP_NET_ADMIN: %v\nchild output:\n%s", runErr, out)
	}

	checks := []struct {
		name string
		key  string
		want string
	}{
		{"loopback brought up and addresses assigned", keyLo, valLoUp},
		{"control: metadata IP refused BEFORE ruleset (routable, not a blackhole)", keyControl, dialRefused},
		{"nftables ruleset applied to the netns", keyApply, valApplyOK},
		{"positive: loopback listener reachable AFTER ruleset (policy is scoped)", keyLoop, dialConnect},
		{"negative: metadata IP dropped AFTER ruleset (SYN silently dropped)", keyMeta, dialTimeout},
	}
	for _, tt := range checks {
		t.Run(tt.name, func(t *testing.T) {
			if got := markers[tt.key]; got != tt.want {
				t.Errorf("child marker %s = %q, want %q\nfull child output:\n%s", tt.key, got, tt.want, out)
			}
		})
	}
}

// runChild is the re-exec'd body running INSIDE the new user+net namespace. It
// prints CHILD=STARTED, brings loopback up (the CAP_NET_ADMIN probe), assigns
// the loopback + metadata addresses, runs the pre-ruleset control dial, applies
// the egress ruleset, then runs the positive and negative dials — emitting one
// KEY=VALUE marker per step. It always returns 0: outcomes are carried in the
// markers so the parent can make precise assertions (and CAP=DENIED drives the
// skip). It returns nonzero only for an unexpected internal error the parent
// should surface as a failure.
func runChild() int {
	fmt.Printf("%s=%s\n", keyChild, valStarted)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("%s=%s%s\n", keyLo, loErrPrefix, "socket:"+err.Error())
		return 1
	}
	defer func() { _ = unix.Close(fd) }()

	// The first CAP_NET_ADMIN-requiring op. Under a restricted userns this is
	// where EPERM surfaces, so we classify it as the capability probe.
	if err := bringLoopbackUp(fd); err != nil {
		if errors.Is(err, syscall.EPERM) {
			fmt.Printf("%s=%s%s\n", keyCap, capDenyPfx, "loopback up: "+err.Error())
			return 0 // parent turns CAP=DENIED into a t.Skip
		}
		fmt.Printf("%s=%s%s\n", keyLo, loErrPrefix, "loopback up: "+err.Error())
		return 0
	}
	fmt.Printf("%s=%s\n", keyCap, valCapOK)

	// Assign 127.0.0.1/8 (primary) and 169.254.169.254/32 (alias) to loopback so
	// both are local: the listener binds the former, the metadata probe targets
	// the latter, and both traverse the OUTPUT hook where the ruleset acts.
	if err := assignIPv4(fd, "lo", loopbackIP, loopbackMask); err != nil {
		fmt.Printf("%s=%s%s\n", keyLo, loErrPrefix, "assign lo: "+err.Error())
		return 0
	}
	if err := assignIPv4(fd, metadataAlias, metadataIP, metadataMask); err != nil {
		fmt.Printf("%s=%s%s\n", keyLo, loErrPrefix, "assign alias: "+err.Error())
		return 0
	}
	fmt.Printf("%s=%s\n", keyLo, valLoUp)

	// Control: dial the metadata IP BEFORE any ruleset exists. It is local with
	// nothing listening => RST => REFUSED, proving the address is routable.
	fmt.Printf("%s=%s\n", keyControl, classifyDial(metadataAddr, metaDialTimeout))

	// Bring up the loopback listener before applying the ruleset.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("%s=%s%s\n", keyLoop, dialErrPfx, "listen: "+err.Error())
		return 0
	}
	defer func() { _ = ln.Close() }()
	go acceptLoop(ln)

	// Apply the egress ruleset to THIS netns (default conn targets current netns).
	conn, err := nftables.New()
	if err != nil {
		fmt.Printf("%s=%s%s\n", keyApply, applyErrPfx, "conn: "+err.Error())
		return 0
	}
	table := buildEgressRuleset(conn)
	if err := conn.Flush(); err != nil {
		fmt.Printf("%s=%s%s\n", keyApply, applyErrPfx, "flush: "+err.Error())
		return 0
	}
	defer func() {
		// Best-effort teardown; the netns (and its ruleset) also dies with the
		// process, so a failure here is not fatal.
		conn.DelTable(table)
		_ = conn.Flush()
	}()
	fmt.Printf("%s=%s\n", keyApply, valApplyOK)

	// Positive: the loopback listener must remain reachable under the ruleset.
	fmt.Printf("%s=%s\n", keyLoop, classifyDial(ln.Addr().String(), loopDialTimeout))

	// Negative: the SAME metadata IP:port must now be dropped (TIMEOUT), flipping
	// from the REFUSED seen in the control dial — nftables is the only change.
	fmt.Printf("%s=%s\n", keyMeta, classifyDial(metadataAddr, metaDialTimeout))

	return 0
}

// buildEgressRuleset installs the rung-1 egress filter into the netns via conn
// (not yet flushed). Structure:
//
//	table inet filter
//	chain output { type filter hook output priority filter; policy drop;
//	  ct state established,related accept   # return traffic for allowed flows
//	  oif lo ip daddr 127.0.0.0/8 accept    # loopback, ADDRESS-scoped
//	  tcp dport 443 accept                  # the one allowed egress port
//	  udp dport 53 accept                   # DNS
//	  tcp dport 53 accept                   # DNS over TCP
//	  # everything else (incl. 169.254.169.254:80) hits policy drop
//	}
//
// The loopback ACCEPT is deliberately ADDRESS-scoped (oif lo AND ip daddr
// 127.0.0.0/8) rather than a blanket "oif lo accept": because the metadata IP is
// also a local address it egresses oif lo too, so a blanket loopback-accept would
// wrongly permit it. Address-scoping is exactly the rung-1 property under test.
func buildEgressRuleset(conn *nftables.Conn) *nftables.Table {
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	})
	policyDrop := nftables.ChainPolicyDrop
	output := conn.AddChain(&nftables.Chain{
		Name:            "output",
		Table:           table,
		Type:            nftables.ChainTypeFilter,
		Hooknum:         nftables.ChainHookOutput,
		Priority:        nftables.ChainPriorityFilter,
		effectivePolicy: &policyDrop,
	})

	// ct state established,related accept.
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: output,
		Exprs: []expr.Any{
			// [ ct load state => reg 1 ]
			&expr.Ct{Register: reg1, Key: expr.CtKeySTATE},
			// [ bitwise reg 1 = (reg 1 & (ESTABLISHED|RELATED)) ^ 0 ]
			&expr.Bitwise{
				SourceRegister: reg1,
				DestRegister:   reg1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			// [ cmp neq reg 1 0 ]  => at least one of the two state bits set
			&expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: []byte{0x00, 0x00, 0x00, 0x00}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// oif lo ip daddr 127.0.0.0/8 accept.
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: output,
		Exprs: []expr.Any{
			// [ meta load oifname => reg 1 ] ; [ cmp eq reg 1 "lo" ]
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: ifname("lo")},
			// [ meta load nfproto => reg 1 ] ; [ cmp eq reg 1 IPv4 ]
			// (inet table carries v4+v6; guard before indexing the IPv4 header)
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{unix.NFPROTO_IPV4}},
			// [ payload load 4b @ network header + 16 => reg 1 ]  (IPv4 daddr)
			&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			// [ bitwise reg 1 = (reg 1 & 255.0.0.0) ^ 0 ]  (apply the /8 mask)
			&expr.Bitwise{
				SourceRegister: reg1,
				DestRegister:   reg1,
				Len:            4,
				Mask:           []byte{0xff, 0x00, 0x00, 0x00},
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			// [ cmp eq reg 1 127.0.0.0 ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{127, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// tcp dport 443 accept ; udp dport 53 accept ; tcp dport 53 accept.
	conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_TCP, 443))
	conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_UDP, 53))
	conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_TCP, 53))

	return table
}

// dportAcceptRule builds a "meta l4proto <proto> <proto> dport <port> accept"
// rule. The transport-header destination port lives at offset 2, length 2, and
// is matched in network byte order (raw payload bytes) — hence the big-endian
// split of port below.
func dportAcceptRule(table *nftables.Table, chain *nftables.Chain, proto byte, port uint16) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// [ meta load l4proto => reg 1 ] ; [ cmp eq reg 1 <proto> ]
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{proto}},
			// [ payload load 2b @ transport header + 2 => reg 1 ]  (dport)
			&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			// [ cmp eq reg 1 <port, big-endian> ]
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// bringLoopbackUp sets IFF_UP|IFF_RUNNING on the `lo` link via SIOCGIFFLAGS /
// SIOCSIFFLAGS. A fresh netns starts with loopback DOWN and unaddressed, so this
// is mandatory before any loopback traffic — and it is the first op that needs
// CAP_NET_ADMIN, so its EPERM is the capability signal.
func bringLoopbackUp(fd int) error {
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("NewIfreq(lo): %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP | unix.IFF_RUNNING)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS: %w", err)
	}
	return nil
}

// assignIPv4 assigns addr/mask to the named interface (or alias label, e.g.
// "lo:1") via SIOCSIFADDR + SIOCSIFNETMASK. Assigning a local address makes the
// kernel add an RTN_LOCAL host route for it, so traffic to that address is
// delivered locally and traverses the OUTPUT hook where the nft chain acts.
func assignIPv4(fd int, name string, addr, mask [4]byte) error {
	ifa, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("NewIfreq(%s): %w", name, err)
	}
	if err := ifa.SetInet4Addr(addr[:]); err != nil {
		return fmt.Errorf("SetInet4Addr(%s): %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifa); err != nil {
		return fmt.Errorf("SIOCSIFADDR(%s): %w", name, err)
	}
	ifm, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("NewIfreq(%s) mask: %w", name, err)
	}
	if err := ifm.SetInet4Addr(mask[:]); err != nil {
		return fmt.Errorf("SetInet4Addr mask(%s): %w", name, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, ifm); err != nil {
		return fmt.Errorf("SIOCSIFNETMASK(%s): %w", name, err)
	}
	return nil
}

// classifyDial performs a bounded TCP dial and reports the outcome as a marker
// value, distinguishing the outcomes the assertions rely on: CONNECTED (handshake
// completed), REFUSED (RST — reached the local stack), TIMEOUT (no response —
// dropped), UNREACH (no route), or ERR:<detail> for anything else.
func classifyDial(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		_ = conn.Close()
		return dialConnect
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return dialRefused
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return dialTimeout
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return dialUnreach
	}
	return dialErrPfx + err.Error()
}

// acceptLoop drains the loopback listener so client connects complete cleanly.
// It exits when the listener is closed (best-effort; errors are the shutdown
// signal, not a fault to surface).
func acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

// ifname pads an interface name to the fixed 16-byte IFNAMSIZ field that the
// nftables `meta oifname` match compares against (unpadded names never match).
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

// parseMarkers turns the child's "KEY=VALUE" lines into a map.
func parseMarkers(out []byte) map[string]string {
	markers := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		markers[key] = val
	}
	return markers
}
