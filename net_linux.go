//go:build linux

package sandbox

import (
	"github.com/looprig/sandbox/internal/policy"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
)

// This file compiles a policy.Effective's network axis into a go-landlock TCP-port
// allowlist for the rung-2 backend (SPEC §7.2, §5.2, §7.5), completing rung 2's
// network boundary (Task 12c). Landlock's net rules are PORT-based, not
// address-based: V4.RestrictNet(ConnectTCP(port), ...) confines TCP connect to
// the listed ports and denies ALL other TCP connect; with NO rules,
// RestrictNet() denies all TCP. The stage-2 child applies this AFTER seccomp and
// BEFORE chdir/execve, so the port boundary is inherited across the execve.
//
// Why the port allowlist is a SOUND boundary and earns GuaranteeNetworkBoundary:
// the 12b seccomp filter already denies UDP sockets (no address scoping possible)
// and IPPROTO_MPTCP (which Landlock's TCP port rules do NOT cover and which Go
// defaults net.Dial to). With UDP + MPTCP closed, classic TCP is the only egress
// path and it is confined to the allowlist — so the boundary is not bypassable.
//
// What rung 2 canNOT express (recorded unenforced in the CompileReport, §7.5):
// address-scoped rules. Loopback/Private allowances and the §5.4 cloud-metadata
// hard-deny are all ADDRESS predicates; Landlock TCP rules are port-only, so a
// port on the allowlist reaches ANY host on that port (metadata included). Real
// address boundaries need rung 1 (netns/nftables). GuaranteeAddressNetwork is
// therefore never set at rung 2.
//
// DNS is forced over TCP (Task 12b denies UDP): port 53 is added to the allowlist
// and RES_OPTIONS=use-vc is injected into the target env so glibc's resolver
// skips its initial UDP attempt and uses TCP. This is glibc-dependent (musl and
// Go's pure-Go resolver may not honor use-vc / fall back to TCP), recorded as a
// `dns`/`narrowed` report entry — DNS is not claimed to work universally.

// dnsTCPPort is the TCP port DNS-over-TCP resolution uses. Added to the net
// allowlist whenever policy.NetPolicy.DNS is set, alongside the RES_OPTIONS=use-vc env
// injection that forces glibc to use it.
const dnsTCPPort uint16 = 53

// resOptionsEnvKey is the glibc resolver options environment variable. Setting it
// to include use-vc forces the stub resolver to use TCP (virtual circuit) rather
// than UDP — required because rung-2 seccomp (12b) denies UDP sockets.
const resOptionsEnvKey = "RES_OPTIONS"

// resOptionUseVC is the glibc resolver option that forces DNS over TCP.
const resOptionUseVC = "use-vc"

// compiledNet is the rung-2 network intent distilled from a policy.NetPolicy at compile
// time: whether to apply a Landlock net restriction at all, the TCP ports the
// target may connect to, and whether DNS-over-TCP env forcing is requested. It
// crosses no boundary itself (the wrap closure closes over it); its fields flow
// into the gob-encoded stage2Spec (NetConfined/NetTCPPorts) and the target env.
type compiledNet struct {
	// confined reports whether the stage-2 child applies RestrictNet at all. It is
	// true whenever the policy does NOT grant open egress (!policy.NetPolicy.Open); false
	// leaves TCP unrestricted (the unconfined/trusted-with-open passthrough).
	confined bool
	// tcpPorts are the TCP ports ConnectTCP is granted for. Empty (with confined)
	// means the allowlist is empty and ALL TCP connect is denied — the fail-closed
	// direction (never wider than policy).
	tcpPorts []uint16
	// dns reports whether DNS-over-TCP forcing is requested (port 53 already folded
	// into tcpPorts; this drives the RES_OPTIONS=use-vc target-env injection).
	dns bool
}

// compileNetPolicy distils a policy.NetPolicy into a compiledNet (SPEC §5.2, §7.2). The
// mapping is deliberately fail-closed — never WIDER than the policy:
//
//   - Open egress (policy.NetPolicy.Open): confined=false. The stage-2 child does NOT
//     call RestrictNet, leaving TCP unrestricted. This is the unconfined case
//     (Open is set only by an explicitly acknowledged unconfined profile), so the
//     backend does not claim a network boundary for it.
//   - Otherwise: confined=true. The TCP allowlist is policy.NetPolicy.Ports, plus port
//     53 when policy.NetPolicy.DNS (DNS over TCP). An empty result denies all TCP —
//     a completely blocked posture. Loopback/Private are NOT foldable into
//     a port allowlist (they are address predicates), so they do not widen the
//     ports; they are recorded unenforced by netCompileReport.
func compileNetPolicy(n policy.NetPolicy) compiledNet {
	if n.Open {
		return compiledNet{confined: false}
	}
	var ports []uint16
	for _, p := range n.Ports {
		if !policy.ContainsPort(ports, p) {
			ports = append(ports, p)
		}
	}
	if n.DNS && !policy.ContainsPort(ports, dnsTCPPort) {
		ports = append(ports, dnsTCPPort)
	}
	return compiledNet{confined: true, tcpPorts: ports, dns: n.DNS}
}

// applyLandlockNet restricts the CURRENT process (and everything it subsequently
// execve's) to TCP-connect on the given ports, denying all other TCP bind/connect
// (SPEC §7.2 rung 2). It builds one landlock.ConnectTCP rule per port — egress
// ports, so ConnectTCP only, not BindTCP — and calls landlock.V4.RestrictNet.
// With NO ports the RestrictNet() call denies ALL TCP (the fail-closed shape).
//
// The exact landlock.V4 config (not BestEffort) mirrors applyLandlockRules: a
// kernel missing ABI v4 makes RestrictNet error — a hard fail-closed — rather
// than silently no-op'ing. Rung 2 is only selected when ABI >= 4, so on the
// selecting host this always enforces. A non-nil return makes the stage-2 child
// fail closed so the target never runs with unrestricted egress.
//
// RestrictNet clears the FS handled-set, so this is INDEPENDENT of the FS
// RestrictPaths call (Task 12a): the stage-2 child applies BOTH and they stack —
// both the FS ruleset and the net ruleset are enforced on the target.
func applyLandlockNet(ports []uint16) error {
	rules := make([]landlock.Rule, 0, len(ports))
	for _, p := range ports {
		rules = append(rules, landlock.ConnectTCP(p))
	}
	return landlock.V4.RestrictNet(rules...)
}

// ensureResOptionsUseVC forces glibc's stub resolver onto TCP by guaranteeing
// RES_OPTIONS contains use-vc in the target environment (SPEC §7.2, Task 12c).
// UDP is seccomp-blocked (12b), so without use-vc glibc's initial UDP query fails
// before it would fall back to TCP. It appends use-vc to an existing RES_OPTIONS
// value (space-separated, as glibc parses it) or sets a fresh one, and is a no-op
// when use-vc is already present. env is the target env (a fresh per-spawn copy),
// so mutating it in place is safe.
func ensureResOptionsUseVC(env []string) []string {
	for i, kv := range env {
		if v, ok := strings.CutPrefix(kv, resOptionsEnvKey+"="); ok {
			if strings.Contains(v, resOptionUseVC) {
				return env
			}
			env[i] = resOptionsEnvKey + "=" + strings.TrimSpace(v+" "+resOptionUseVC)
			return env
		}
	}
	return append(env, resOptionsEnvKey+"="+resOptionUseVC)
}

// netCompileReport records how the rung-2 network compilation treated each policy
// feature (SPEC §7.5). It is appended to the backend's CompileReport:
//
//   - confined: the TCP port allowlist is enforced (network-boundary). An empty
//     allowlist is still a boundary — it denies all TCP.
//   - open egress: no restriction applied (network / unenforced) — the unconfined
//     passthrough; the backend also withholds GuaranteeNetworkBoundary.
//   - Loopback/Private requested, or any egress allowed: address scoping is
//     unenforced (address-network) — Landlock TCP rules are port-only, so
//     loopback/private/metadata are not address-scopable at rung 2 (§7.5); use
//     rung 1 for real address boundaries.
//   - DNS: forced over TCP, glibc-dependent (dns / narrowed).
func netCompileReport(n policy.NetPolicy, cnet compiledNet) []ReportEntry {
	var entries []ReportEntry
	if !cnet.confined {
		entries = append(entries, ReportEntry{
			Feature: "network",
			Status:  "unenforced",
			Detail:  "Net.Open grants unrestricted egress; the stage-2 child applies no Landlock net restriction (unconfined passthrough, §5.2)",
		})
		return entries
	}

	entries = append(entries, ReportEntry{
		Feature: "network-boundary",
		Status:  "enforced",
		Detail:  "TCP egress confined to the compiled port allowlist via Landlock ConnectTCP (rung 2, ABI v4); UDP and MPTCP are seccomp-blocked (12b), so classic TCP is the only egress path and the port boundary is not bypassable (§7.2, §5.2)",
	})

	if n.Loopback || n.Private || len(cnet.tcpPorts) > 0 {
		entries = append(entries, ReportEntry{
			Feature: "address-network",
			Status:  "unenforced",
			Detail:  "address-scoped rules are inexpressible at rung 2: Landlock TCP rules are port-only, so Loopback/Private allowances and the §5.4 cloud-metadata hard-deny cannot be enforced — an allowed port reaches ANY host on that port (metadata included). Use rung 1 (netns/nftables) for a real address boundary (§7.5)",
		})
	}

	if n.DNS {
		entries = append(entries, ReportEntry{
			Feature: "dns",
			Status:  "narrowed",
			Detail:  "DNS forced over TCP: port 53 added to the TCP allowlist and RES_OPTIONS=use-vc injected into the target env (UDP is seccomp-blocked). glibc honors use-vc, but musl and Go's pure-Go resolver may not fall back to TCP, so resolution is glibc-dependent (§7.5)",
		})
	}

	return entries
}
