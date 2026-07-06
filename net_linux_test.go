//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// --- Runtime proof through the REAL stage-2 backend ---------------------------
//
// Like the seccomp e2e, these tests re-run THIS test binary as the stage-2
// TARGET: the linuxBackend re-execs /proc/self/exe, the stage-2 helper installs
// Landlock FS + seccomp + the Landlock TCP-port allowlist and execve's
// /proc/self/exe. In the target the net-probe sentinel is set (via Env.Set) and
// the dispatch sentinel is NOT (scrubbed out), so netTargetDispatch runs a
// CLASSIC-TCP connect probe under the inherited Landlock net ruleset and prints
// markers the parent asserts on. The probe uses a raw AF_INET/SOCK_STREAM socket
// (proto 0) and unix.Connect — NOT net.Dial — so it exercises the classic-TCP
// Landlock ConnectTCP path, never MPTCP (which 12b's seccomp separately blocks).

// netTargetEnv marks a process that should run the connect probes and exit. It is
// injected into the TARGET env via Env.Set, so it is present only after the
// stage-2 execve — not in the stage-2 helper (which additionally carries
// stage2SentinelEnv, the distinguisher checked below).
const netTargetEnv = "LRSANDBOX_NET_PROBE"

// netProbePortAEnv / netProbePortBEnv carry the two TCP ports the target probes.
// Tests set port A as an ALLOWED (allowlisted) port and port B as a BLOCKED one;
// the net-zero test lists neither in the allowlist so both come back DENIED.
const (
	netProbePortAEnv = "LRSANDBOX_NET_PORT_A"
	netProbePortBEnv = "LRSANDBOX_NET_PORT_B"
)

// Marker keys/values the target prints (one KEY=VALUE line each).
const (
	netKeyPortA    = "PORTA"
	netKeyPortB    = "PORTB"
	netValAllowed  = "ALLOWED" // Landlock permitted the connect syscall (OK / ECONNREFUSED)
	netValDenied   = "DENIED"  // Landlock blocked the connect syscall (EACCES / EPERM)
	netProbeAllowP = 59595     // port A: the allowlisted port in the positive test
	netProbeBlockP = 59596     // port B: never allowlisted — must be Landlock-denied
)

// netTargetDispatch runs at package init in the re-exec'd TARGET only: the probe
// sentinel is set AND the stage-2 dispatch sentinel is NOT (the latter is present
// in the stage-2 helper but scrubbed out of the target env). It probes the two
// env-named ports under the inherited Landlock net ruleset, prints the markers,
// and exits — it never returns to the test framework. In the parent or a stage-2
// helper it is a no-op.
func netTargetDispatch() {
	if os.Getenv(netTargetEnv) != "1" {
		return // not a probe target
	}
	if os.Getenv(stage2SentinelEnv) == stage2SentinelValue {
		return // this is the stage-2 helper (pre-execve); let Init()/runStage2 run
	}
	portA := netProbePortFromEnv(netProbePortAEnv)
	portB := netProbePortFromEnv(netProbePortBEnv)
	fmt.Printf("%s=%s\n", netKeyPortA, classifyNetConnect(portA))
	fmt.Printf("%s=%s\n", netKeyPortB, classifyNetConnect(portB))
	os.Exit(0)
}

// netProbePortFromEnv parses a port from env; an unparseable/absent value yields
// 0, which classifyNetConnect will still probe (and Landlock will deny unless 0
// is allowlisted — it never is), keeping a misconfigured probe fail-closed.
func netProbePortFromEnv(key string) uint16 {
	n, err := strconv.Atoi(os.Getenv(key))
	if err != nil || n < 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

// init dispatches the net probe target. It runs before TestMain (which calls
// Init()); guarding on the two sentinels keeps it inert in every process except
// the intended post-execve probe target.
func init() { netTargetDispatch() }

// classifyNetConnect attempts a CLASSIC-TCP connect to 127.0.0.1:port on a raw
// AF_INET/SOCK_STREAM socket (protocol 0 — never MPTCP) and classifies the
// outcome by what Landlock's ConnectTCP boundary produces:
//
//   - EACCES/EPERM     -> DENIED  (Landlock blocked the connect syscall)
//   - OK / ECONNREFUSED -> ALLOWED (Landlock permitted it; a refused connect to a
//     port nobody listens on is the NETWORK saying no, not Landlock)
//
// The ECONNREFUSED=ALLOWED mapping is what lets the positive control work without
// a listener: an allowlisted port with nothing behind it refuses fast on loopback,
// proving Landlock let the connect through. Any other errno is surfaced verbatim.
func classifyNetConnect(port uint16) string {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return "SOCKET_ERR:" + err.Error()
	}
	defer func() { _ = unix.Close(fd) }()

	sa := &unix.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
	err = unix.Connect(fd, sa)
	if err == nil {
		return netValAllowed
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return netValDenied
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return netValAllowed
	}
	return "ERR:" + err.Error()
}

// parseNetMarkers turns the target's KEY=VALUE lines into a map.
func parseNetMarkers(out []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

// runNetProbe builds a rung-2 executor for the given net policy, re-execs the
// test binary as the confined target, and returns the parsed probe markers. It
// injects the probe sentinel and the two probe ports into the TARGET env.
func runNetProbe(t *testing.T, netOpt PolicyOption) map[string]string {
	t.Helper()
	ws := t.TempDir()
	e := newFSExecutor(t, PolicyFor(Write, ws,
		netOpt,
		WithEnv(EnvPolicy{Set: map[string]string{
			netTargetEnv:     "1",
			netProbePortAEnv: strconv.Itoa(netProbeAllowP),
			netProbePortBEnv: strconv.Itoa(netProbeBlockP),
		}}),
	))
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/proc/self/exe"})
	if err != nil {
		t.Fatalf("RunArgv(/proc/self/exe): err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("net probe target exit = %d, want 0 (out=%q)", code, out)
	}
	return parseNetMarkers(out)
}

// TestLinuxNetPortAllowlist is the headline anti-fail-open proof: with an
// allowlist of exactly port A, a classic-TCP connect to port A is PERMITTED by
// Landlock (ALLOWED — refused by the network, not the sandbox) while a connect to
// the non-allowlisted port B is DENIED (EACCES/EPERM). BOTH halves matter — a
// blanket net deny would satisfy the negative half but (correctly) fail the
// positive half, so it cannot masquerade as a working port allowlist. MPTCP is
// avoided (raw SOCK_STREAM proto 0), so this measures the Landlock TCP path.
func TestLinuxNetPortAllowlist(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)

	got := runNetProbe(t, WithNet(NetPolicy{Ports: []uint16{netProbeAllowP}}))

	if got[netKeyPortA] != netValAllowed {
		t.Errorf("allowlisted port %d = %q, want %q (Landlock must permit the connect) — full output:\n%v",
			netProbeAllowP, got[netKeyPortA], netValAllowed, got)
	}
	if got[netKeyPortB] != netValDenied {
		t.Errorf("non-allowlisted port %d = %q, want %q — FAIL-OPEN: the port allowlist leaked; output:\n%v",
			netProbeBlockP, got[netKeyPortB], netValDenied, got)
	}
}

// TestLinuxNetAllDeniedWhenZero proves the fail-closed shape: PolicyFor(Write) has
// Net{} (empty allowlist), so RestrictNet() with no rules denies ALL TCP connect —
// both probed ports come back DENIED.
func TestLinuxNetAllDeniedWhenZero(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)

	// A no-op net option keeps Write's zero NetPolicy (all TCP denied).
	got := runNetProbe(t, func(*policyBuilder) {})

	for _, k := range []string{netKeyPortA, netKeyPortB} {
		if got[k] != netValDenied {
			t.Errorf("with net zero, %s = %q, want %q (all TCP must be denied) — output:\n%v",
				k, got[k], netValDenied, got)
		}
	}
}

// TestLinuxNetDNSForcedOverTCP proves the DNS-over-TCP compilation end to end: a
// DNS-enabled policy injects RES_OPTIONS=use-vc into the TARGET env (asserted by
// running the real `env` binary under the sandbox) and records the dns/narrowed
// report entry. Port 53's presence in the allowlist is covered by the
// compileNetPolicy unit test below.
func TestLinuxNetDNSForcedOverTCP(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ws := t.TempDir()

	e := newFSExecutor(t, PolicyFor(Write, ws, WithNet(NetPolicy{DNS: true})))

	// The report must record DNS narrowed to TCP.
	if !reportHas(e.Report(), "dns", "narrowed") {
		t.Errorf("CompileReport missing dns/narrowed entry; report=%+v", e.Report())
	}

	// Run the real `env` under the sandbox and assert RES_OPTIONS=use-vc is present
	// in the confined target's environment.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/usr/bin/env"})
	if err != nil {
		t.Fatalf("RunArgv(env): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("env exit = %d, want 0 (out=%q)", code, out)
	}
	if !strings.Contains(string(out), resOptionsEnvKey+"="+resOptionUseVC) {
		t.Errorf("target env missing %s=%s; env output:\n%s", resOptionsEnvKey, resOptionUseVC, out)
	}
}

// TestLinuxNetGuarantees asserts the rung-2 network level/guarantee/report posture
// (§6, §5.2, §7.5): a confined-net policy earns NetworkBoundary but NOT
// AddressNetwork, stays LevelDegraded, records network-boundary/enforced, and — when
// it requests Loopback/Private — records address-network/unenforced.
func TestLinuxNetGuarantees(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()

	t.Run("confined port policy earns NetworkBoundary, not AddressNetwork", func(t *testing.T) {
		e := newFSExecutor(t, PolicyFor(Write, ws, WithNet(NetPolicy{Ports: []uint16{443}})))
		g := e.Guarantees()
		if !g.NetworkBoundary {
			t.Errorf("Guarantees().NetworkBoundary = false, want true (confined TCP allowlist)")
		}
		if g.AddressNetwork {
			t.Errorf("Guarantees().AddressNetwork = true, want false (rung 2 cannot address-scope)")
		}
		if lvl := e.Level(); lvl != LevelDegraded {
			t.Errorf("Level() = %d, want LevelDegraded (%d)", lvl, LevelDegraded)
		}
		if !reportHas(e.Report(), "network-boundary", "enforced") {
			t.Errorf("CompileReport missing network-boundary/enforced entry; report=%+v", e.Report())
		}
	})

	t.Run("Loopback/Private records address-network unenforced", func(t *testing.T) {
		e := newFSExecutor(t, PolicyFor(Trusted, ws))
		g := e.Guarantees()
		if !g.NetworkBoundary {
			t.Errorf("Guarantees().NetworkBoundary = false, want true (Trusted is net-confined at port level)")
		}
		if g.AddressNetwork {
			t.Errorf("Guarantees().AddressNetwork = true, want false")
		}
		if !reportHas(e.Report(), "address-network", "unenforced") {
			t.Errorf("CompileReport missing address-network/unenforced entry; report=%+v", e.Report())
		}
	})

	t.Run("open egress does not earn NetworkBoundary", func(t *testing.T) {
		// Net.Open makes the policy unconfined; AckUnconfined is required to build.
		p := PolicyFor(Write, ws, WithNet(NetPolicy{Open: true}), WithAckUnconfined())
		e := newFSExecutor(t, p)
		if e.Guarantees().NetworkBoundary {
			t.Errorf("Guarantees().NetworkBoundary = true for open egress, want false")
		}
		if !reportHas(e.Report(), "network", "unenforced") {
			t.Errorf("CompileReport missing network/unenforced entry for open egress; report=%+v", e.Report())
		}
	})
}

// --- Pure compile unit tests (no Landlock) -----------------------------------

// TestCompileNetPolicy asserts the NetPolicy -> compiledNet mapping: Open is a
// passthrough (unconfined), everything else is confined, DNS folds port 53 in,
// duplicates are collapsed, and Loopback/Private never widen the port set.
func TestCompileNetPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		in           NetPolicy
		wantConfined bool
		wantPorts    []uint16
		wantDNS      bool
	}{
		{"zero denies all (confined, empty)", NetPolicy{}, true, nil, false},
		{"open is unconfined passthrough", NetPolicy{Open: true}, false, nil, false},
		{"ports only", NetPolicy{Ports: []uint16{443}}, true, []uint16{443}, false},
		{"dns folds in port 53", NetPolicy{DNS: true}, true, []uint16{dnsTCPPort}, true},
		{"ports plus dns", NetPolicy{Ports: []uint16{443}, DNS: true}, true, []uint16{443, dnsTCPPort}, true},
		{"dns does not duplicate an explicit 53", NetPolicy{Ports: []uint16{53}, DNS: true}, true, []uint16{53}, true},
		{"duplicate ports collapsed", NetPolicy{Ports: []uint16{443, 443}}, true, []uint16{443}, false},
		{"loopback/private do not widen ports", NetPolicy{Loopback: true, Private: true}, true, nil, false},
		{"open wins even with ports", NetPolicy{Ports: []uint16{443}, Open: true}, false, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := compileNetPolicy(tt.in)
			if got.confined != tt.wantConfined {
				t.Errorf("confined = %v, want %v", got.confined, tt.wantConfined)
			}
			if got.dns != tt.wantDNS {
				t.Errorf("dns = %v, want %v", got.dns, tt.wantDNS)
			}
			if !equalPorts(got.tcpPorts, tt.wantPorts) {
				t.Errorf("tcpPorts = %v, want %v", got.tcpPorts, tt.wantPorts)
			}
		})
	}
}

// equalPorts compares two port slices treating nil and empty as equal.
func equalPorts(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestEnsureResOptionsUseVC asserts the glibc use-vc env injection: a fresh set, a
// merge onto an existing RES_OPTIONS, and a no-op when use-vc is already present.
func TestEnsureResOptionsUseVC(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   []string
		want string // the expected RES_OPTIONS=... entry
	}{
		{"fresh set", []string{"PATH=/bin"}, "RES_OPTIONS=use-vc"},
		{"merge onto existing", []string{"RES_OPTIONS=timeout:1"}, "RES_OPTIONS=timeout:1 use-vc"},
		{"already present is no-op", []string{"RES_OPTIONS=use-vc"}, "RES_OPTIONS=use-vc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ensureResOptionsUseVC(append([]string(nil), tt.in...))
			found := false
			for _, kv := range got {
				if kv == tt.want {
					found = true
				}
			}
			if !found {
				t.Errorf("ensureResOptionsUseVC(%v) = %v, want to contain %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNetCompileReport asserts the per-feature network report entries for the
// confined, open, and DNS shapes.
func TestNetCompileReport(t *testing.T) {
	t.Parallel()
	has := func(entries []ReportEntry, feature, status string) bool {
		for _, e := range entries {
			if e.Feature == feature && e.Status == status {
				return true
			}
		}
		return false
	}
	tests := []struct {
		name          string
		in            NetPolicy
		wantEnforced  bool // network-boundary/enforced
		wantOpen      bool // network/unenforced
		wantAddrUnenf bool // address-network/unenforced
		wantDNS       bool // dns/narrowed
	}{
		{"write zero: boundary enforced, no address entry", NetPolicy{}, true, false, false, false},
		{"ports only: boundary + address unenforced", NetPolicy{Ports: []uint16{443}}, true, false, true, false},
		{"trusted-shape: boundary + address + dns", NetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true}, true, false, true, true},
		{"open: unenforced only", NetPolicy{Open: true}, false, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entries := netCompileReport(tt.in, compileNetPolicy(tt.in))
			if has(entries, "network-boundary", "enforced") != tt.wantEnforced {
				t.Errorf("network-boundary/enforced presence = %v, want %v; entries=%+v", !tt.wantEnforced, tt.wantEnforced, entries)
			}
			if has(entries, "network", "unenforced") != tt.wantOpen {
				t.Errorf("network/unenforced presence = %v, want %v; entries=%+v", !tt.wantOpen, tt.wantOpen, entries)
			}
			if has(entries, "address-network", "unenforced") != tt.wantAddrUnenf {
				t.Errorf("address-network/unenforced presence = %v, want %v; entries=%+v", !tt.wantAddrUnenf, tt.wantAddrUnenf, entries)
			}
			if has(entries, "dns", "narrowed") != tt.wantDNS {
				t.Errorf("dns/narrowed presence = %v, want %v; entries=%+v", !tt.wantDNS, tt.wantDNS, entries)
			}
		})
	}
}
