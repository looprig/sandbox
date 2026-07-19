//go:build linux

package sandbox

import (
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// This file compiles a effectivePolicy's network axis into the RUNG-1 in-netns nftables
// ADDRESS filter (SPEC §7.2 rung 1, §5.2, §5.4) and carries the stage-2
// mechanism that installs it. Unlike rung 2 (net_linux.go — Landlock TCP-port
// rules, no address scoping), rung 1 runs inside a private network namespace and
// can express address-scoped rules: loopback by destination address, RFC1918/ULA
// private ranges, UDP DNS, and — critically — the §5.4 cloud-metadata hard-deny
// (169.254.0.0/16 + fd00:ec2::254 DROP whenever any egress is allowed). It
// mirrors the proven M4 spike ruleset (spikes/nftables), using the pure-Go,
// no-cgo google/nftables netlink library.
//
// CRITICAL — CI-verified, not host-verified. Installing an nftables ruleset
// needs an effective CAP_NET_ADMIN in the target netns, blocked on the authoring
// host by apparmor_restrict_unprivileged_userns=1. The pure compilation
// (compileNftPlan / toNftSpec) is unit-tested and runs everywhere; the actual
// netlink install (applyNftRules) is exercised only in CI (which also needs
// nf_conntrack for the ct-state match).
//
// Ruleset shape (inet filter table, output chain policy DROP):
//   1. metadata DROP (169.254.0.0/16, fd00:ec2::254) — FIRST, so it beats the
//      Private accept below (fd00:ec2::254 is inside fc00::/7, which Private
//      would otherwise allow).
//   2. ct state established,related accept — return traffic for allowed flows.
//   3. oif lo, address-scoped loopback accept (127.0.0.0/8, ::1) — when Loopback.
//   4. tcp dport <port> accept — one per allowed egress port.
//   5. udp/tcp dport 53 accept — when DNS (rung 1 CAN do UDP DNS; rung 2 cannot).
//   6. RFC1918/ULA accept (10/8, 172.16/12, 192.168/16, fc00::/7) — when Private.
// Everything else hits the DROP policy.

// nftablesOp is the stage2Error.Op for every rung-1 nftables failure (SPEC §7.2).
const nftablesOp = "nftables"

// reg1 is nftables scratch register 1 (register 0 is the verdict register); every
// match loads into and compares against it. Mirrors the M4 spike.
const nftReg1 = uint32(1)

// dnsPort is the DNS service port (udp+tcp) accepted when effectiveNetPolicy.DNS is set.
const dnsPort uint16 = 53

// privateCIDRs are the RFC1918 + ULA ranges accepted when effectiveNetPolicy.Private is
// set (SPEC §5.2). Metadata (§5.4) is dropped BEFORE these, so fd00:ec2::254
// inside fc00::/7 is still denied.
var privateCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

// loopbackCIDRs are the destination ranges accepted for loopback egress (oif lo)
// when effectiveNetPolicy.Loopback is set. Address-scoped (not a blanket oif-lo accept) so
// a locally-routed metadata alias cannot slip through the loopback rule.
var loopbackCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
}

// compiledNftPlan is the rung-1 network intent distilled from a effectiveNetPolicy at
// compile time. It flows (via toNftSpec) into the gob-encoded stage2Spec.NftRules
// and is installed by the stage-2 child inside the netns.
type compiledNftPlan struct {
	// confined reports whether the stage-2 child installs a ruleset (and thus
	// whether the netns is created). It is true whenever the policy does NOT grant
	// open egress (!effectiveNetPolicy.Open); false leaves host networking untouched (the
	// unconfined passthrough — the netns is not even created, so connectivity is
	// preserved).
	confined bool
	// tcpPorts are the accepted egress TCP ports (deduped).
	tcpPorts []uint16
	// loopback / private / dns mirror the effectiveNetPolicy flags that gate the
	// corresponding accept rules.
	loopback bool
	private  bool
	dns      bool
	// metadataCIDRs are the §5.4 hard-deny endpoints, dropped whenever confined.
	metadataCIDRs []string
}

// compileNftPlan distils a effectiveNetPolicy into a compiledNftPlan (SPEC §5.2, §5.4,
// §7.2 rung 1). Fail-closed: an Open policy yields confined=false (no netns, no
// ruleset — the unconfined passthrough); otherwise every accept is gated by its
// effectiveNetPolicy flag and the metadata deny is always included.
func compileNftPlan(n effectiveNetPolicy) compiledNftPlan {
	if n.Open {
		return compiledNftPlan{confined: false}
	}
	var ports []uint16
	for _, p := range n.Ports {
		if !containsPort(ports, p) {
			ports = append(ports, p)
		}
	}
	return compiledNftPlan{
		confined:      true,
		tcpPorts:      ports,
		loopback:      n.Loopback,
		private:       n.Private,
		dns:           n.DNS,
		metadataCIDRs: metadataDenyCIDRs(),
	}
}

// NftSpec is the gob-encoded rung-1 nftables plan carried on the stage2Spec
// (exported concrete type). Confined=false means no ruleset is installed.
type NftSpec struct {
	Confined      bool
	TCPPorts      []uint16
	Loopback      bool
	Private       bool
	DNS           bool
	MetadataCIDRs []string
}

// toNftSpec projects the compile-time plan into its gob-encodable form.
func (p compiledNftPlan) toNftSpec() NftSpec {
	return NftSpec{
		Confined:      p.confined,
		TCPPorts:      p.tcpPorts,
		Loopback:      p.loopback,
		Private:       p.private,
		DNS:           p.dns,
		MetadataCIDRs: p.metadataCIDRs,
	}
}

// applyNftRules installs the rung-1 egress filter inside the stage-2 child's
// network namespace (SPEC §7.2 rung 1, §5.2, §5.4). It brings loopback up +
// addressed, builds the inet filter output chain (policy DROP), and flushes it
// over netlink. Every step fails CLOSED via stage2Error{Op: nftables} so the
// target never runs with an unfiltered netns. A false Confined is a no-op (the
// netns was not created; host networking is intact).
//
// CI-verified: needs CAP_NET_ADMIN in the netns (blocked on the authoring host)
// and nf_conntrack for the ct-state match.
func applyNftRules(spec NftSpec) error {
	if !spec.Confined {
		return nil
	}
	if err := setupLoopback(); err != nil {
		return &stage2Error{Op: nftablesOp, Err: err}
	}
	conn, err := nftables.New()
	if err != nil {
		return &stage2Error{Op: nftablesOp, Err: fmt.Errorf("netlink conn: %w", err)}
	}
	if err := buildRung1Ruleset(conn, spec); err != nil {
		return &stage2Error{Op: nftablesOp, Err: err}
	}
	if err := conn.Flush(); err != nil {
		return &stage2Error{Op: nftablesOp, Err: fmt.Errorf("flush: %w", err)}
	}
	return nil
}

// buildRung1Ruleset stages the inet filter table + output chain (policy DROP)
// and its rules into conn (not yet flushed), in the order that keeps the
// metadata deny ahead of the Private accept (§5.4). It returns an error only when
// a CIDR fails to parse (a programming error in the fixed CIDR lists), so the
// stage-2 child fails closed rather than flushing a partial ruleset.
func buildRung1Ruleset(conn *nftables.Conn, spec NftSpec) error {
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "filter"})
	policyDrop := nftables.ChainPolicyDrop
	output := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policyDrop,
	})

	// 1. Metadata hard-deny FIRST (beats the Private accept for fd00:ec2::254).
	for _, cidr := range spec.MetadataCIDRs {
		rule, err := cidrVerdictRule(table, output, cidr, expr.VerdictDrop)
		if err != nil {
			return fmt.Errorf("metadata deny rule: %w", err)
		}
		conn.AddRule(rule)
	}

	// 2. Return traffic for allowed flows.
	conn.AddRule(ctEstablishedRule(table, output))

	// 3. Address-scoped loopback (oif lo AND daddr in loopback range).
	if spec.Loopback {
		for _, cidr := range loopbackCIDRs {
			rule, err := loopbackRule(table, output, cidr)
			if err != nil {
				return fmt.Errorf("loopback rule: %w", err)
			}
			conn.AddRule(rule)
		}
	}

	// 4. Allowed egress TCP ports.
	for _, port := range spec.TCPPorts {
		conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_TCP, port))
	}

	// 5. DNS over UDP and TCP (rung 1 can address/UDP-scope; rung 2 cannot).
	if spec.DNS {
		conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_UDP, dnsPort))
		conn.AddRule(dportAcceptRule(table, output, unix.IPPROTO_TCP, dnsPort))
	}

	// 6. RFC1918 / ULA private ranges (after the metadata deny).
	if spec.Private {
		for _, cidr := range privateCIDRs {
			rule, err := cidrVerdictRule(table, output, cidr, expr.VerdictAccept)
			if err != nil {
				return fmt.Errorf("private accept rule: %w", err)
			}
			conn.AddRule(rule)
		}
	}
	return nil
}

// ctEstablishedRule builds "ct state established,related accept" — return
// traffic for flows an accept rule already permitted. Mirrors the M4 spike.
func ctEstablishedRule(table *nftables.Table, chain *nftables.Chain) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: nftReg1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: nftReg1,
				DestRegister:   nftReg1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: nftReg1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// dportAcceptRule builds "meta l4proto <proto> <proto> dport <port> accept". The
// transport-header destination port is at offset 2 length 2, matched in network
// byte order. Mirrors the M4 spike.
func dportAcceptRule(table *nftables.Table, chain *nftables.Chain, proto byte, port uint16) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: nftReg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: []byte{proto}},
			&expr.Payload{DestRegister: nftReg1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	}
}

// loopbackRule builds an address-scoped loopback accept: "oif lo AND ip[6] daddr
// in <cidr> accept". Scoping by destination address (not a blanket oif-lo accept)
// is the rung-1 property under test — a locally-routed metadata alias egresses
// oif lo too, so a blanket accept would wrongly permit it (M4 spike rationale).
func loopbackRule(table *nftables.Table, chain *nftables.Chain, cidr string) (*nftables.Rule, error) {
	ipnet, err := parseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: nftReg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: ifname("lo")},
	}
	exprs = append(exprs, daddrMatchExprs(ipnet)...)
	exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
	return &nftables.Rule{Table: table, Chain: chain, Exprs: exprs}, nil
}

// cidrVerdictRule builds "ip[6] daddr in <cidr> <verdict>" — the shared shape for
// the metadata DROP and Private ACCEPT rules. It guards on nfproto (the inet
// table carries v4+v6) before indexing the address, then masks and compares the
// destination address against the network.
func cidrVerdictRule(table *nftables.Table, chain *nftables.Chain, cidr string, kind expr.VerdictKind) (*nftables.Rule, error) {
	ipnet, err := parseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	exprs := daddrMatchExprs(ipnet)
	exprs = append(exprs, &expr.Verdict{Kind: kind})
	return &nftables.Rule{Table: table, Chain: chain, Exprs: exprs}, nil
}

// daddrMatchExprs builds the "nfproto == family; daddr & mask == network" match
// for an IPv4 or IPv6 destination network. IPv4 daddr is 4 bytes at network-header
// offset 16; IPv6 daddr is 16 bytes at offset 24.
func daddrMatchExprs(ipnet *net.IPNet) []expr.Any {
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: nftReg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: nftReg1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: nftReg1, DestRegister: nftReg1, Len: 4, Mask: ipnet.Mask, Xor: []byte{0, 0, 0, 0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: ip4.Mask(ipnet.Mask)},
		}
	}
	ip16 := ipnet.IP.To16()
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: nftReg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Payload{DestRegister: nftReg1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
		&expr.Bitwise{SourceRegister: nftReg1, DestRegister: nftReg1, Len: 16, Mask: ipnet.Mask, Xor: make([]byte, 16)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: nftReg1, Data: ip16.Mask(ipnet.Mask)},
	}
}

// parseCIDR parses a CIDR or a bare IP (treated as a host /32 or /128) into a
// normalized *net.IPNet. A bare IP is how the §5.4 EC2 IPv6 endpoint
// (fd00:ec2::254) is expressed in metadataDenyCIDRs.
func parseCIDR(s string) (*net.IPNet, error) {
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid CIDR/IP %q", s)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}, nil
}

// ifname pads an interface name to the fixed 16-byte IFNAMSIZ field the nftables
// meta oifname match compares against (unpadded names never match). Mirrors the
// M4 spike.
func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

// setupLoopback brings the netns loopback interface UP and assigns 127.0.0.1/8
// (SPEC §7.2 rung 1). A fresh netns starts with lo DOWN and unaddressed; the
// kernel auto-adds ::1/128 once lo is UP, so only the IPv4 address needs an
// explicit ioctl. This is CAP_NET_ADMIN work in the netns (CI-verified).
func setupLoopback() error {
	if err := bringLoopbackUp(); err != nil {
		return fmt.Errorf("loopback up: %w", err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := assignLoopbackV4(fd, [4]byte{127, 0, 0, 1}, [4]byte{255, 0, 0, 0}); err != nil {
		return fmt.Errorf("assign 127.0.0.1/8: %w", err)
	}
	return nil
}

// assignLoopbackV4 assigns addr/mask to lo via SIOCSIFADDR + SIOCSIFNETMASK,
// making the address locally routed so loopback traffic traverses the OUTPUT
// hook where the nft chain acts. Mirrors the M4 spike's assignIPv4.
func assignLoopbackV4(fd int, addr, mask [4]byte) error {
	ifa, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := ifa.SetInet4Addr(addr[:]); err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFADDR, ifa); err != nil {
		return err
	}
	ifm, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := ifm.SetInet4Addr(mask[:]); err != nil {
		return err
	}
	return unix.IoctlIfreq(fd, unix.SIOCSIFNETMASK, ifm)
}
