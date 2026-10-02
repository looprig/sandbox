//go:build linux

package linux

import (
	"fmt"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Backend is the Linux OS-enforcement backend (SPEC §7.2). It compiles a
// policy into a enforce.Spec whose wrap re-execs THIS binary (/proc/self/exe) into
// a stage-2 helper (Init -> RunStage2) that becomes the Confined target.
//
// Task 12a wires the RUNG-2 filesystem axis: compile distils the policy's FS
// entries into a policy.CompiledFS, the per-spawn wrap enumerates that into a flat
// Landlock allowlist against the live filesystem (snapshot semantics), and the
// stage-2 child applies the ruleset before execve. Rung 1 (namespaces/cgroup,
// Task 13), Seccomp (Task 14), and network scoping (Task 12c) still fill in
// later; until then the backend reports profile.LevelDegraded with the write-boundary +
// read-deny + env-scrub guarantees a Rung-2 FS confinement genuinely upholds.
type Backend struct {
	// CgroupPids is the writable cgroup v2 Ancestor distributing the pids
	// controller, probed ONCE at construction (Task 14, SPEC §7.4), or "" when no
	// such Ancestor exists. It decides — at compile time — whether the
	// ResourceLimits guarantee holds; each spawn creates its transient scope under
	// it. Probing at construction (not per spawn) makes the guarantee a stable
	// property of the executor: availability is measured once, the same value the
	// per-spawn configure uses.
	CgroupPids string
	// Rung is the confinement tier this backend compiles for (Task 13, SPEC §7.2):
	// RungTwo (Landlock + Seccomp, no namespaces) or RungOne (namespaces + mount
	// view + nftables, then Landlock + Seccomp). compile branches on it. The zero
	// value would be RungNone, but the constructors always set a re-exec Rung, so a
	// backend selected by platformBackend is never RungNone.
	Rung Rung
}

// NewBackend constructs the RUNG-2 Linux backend. It keeps its no-argument
// signature (existing callers and tests rely on it — withBackend(NewBackend())
// pins Rung 2) and probes the delegated cgroup v2 pids Ancestor here so compile
// can decide the ResourceLimits guarantee (SPEC §7.4). Rung-2 FS confinement is
// compiled from the policy alone.
func NewBackend() *Backend {
	return &Backend{CgroupPids: ProbeDelegatedPidsAncestor(), Rung: RungTwo}
}

// NewBackendRung1 constructs the RUNG-1 (full-isolation) Linux enforce.Backend
// (Task 13, SPEC §7.2 Rung 1): user+mount+pid+net namespaces via the stage-2
// SysProcAttr cloneflags, a bind-mount view (restricted-read + deny-by-mask),
// in-Netns nftables address filtering, then Landlock + Seccomp + cgroup. It is
// selected by platformBackend only on a host whose probe confirmed a usable
// Userns+Mountns+Netns (SelectRung -> RungOne). It shares the cgroup probe with
// Rung 2.
func NewBackendRung1() *Backend {
	return &Backend{CgroupPids: ProbeDelegatedPidsAncestor(), Rung: RungOne}
}

// compile dispatches on the backend's Rung (SPEC §7.2): Rung 1 compiles the full
// namespace/mount/nftables tier (compileRung1); Rung 2 (and the no-arg
// NewBackend, which existing tests pin) compiles the Landlock+Seccomp tier
// (compileRung2). It never errors — a policy that compiles to a narrower ruleset
// is reported via level/bits/report, not via err.
func (b Backend) Compile(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	return b.CompileWithPathHandles(p, nil)
}

func (b Backend) CompileWithPathHandles(p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if b.Rung == RungOne {
		return b.compileRung1WithGrantPaths(p, handles)
	}
	return b.compileRung2WithGrantPaths(p, handles)
}

// compileRung2 builds the re-exec enforce.Spec and applies Rung-2 FS confinement. It
// distils the policy's FS axis into a policy.CompiledFS (literal allows + literal
// denies; globs dropped), which the per-spawn wrap enumerates into a Landlock
// allowlist. It reports profile.LevelDegraded (Rung 2 enforces the write boundary and
// fixed-path denies but cannot express glob denies or address-scoped network for
// subprocesses, §7.5) with profile.GuaranteeWriteBoundary, profile.GuaranteeReadBoundary (when the
// policy carries an enforceable fixed-path deny), and profile.GuaranteeEnvScrub (when
// !Env.Inherit). The profile.CompileReport records what was Enforced vs narrowed vs
// unenforced.
func (b Backend) compileRung2(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	return b.compileRung2WithGrantPaths(p, nil)
}

func (b Backend) compileRung2WithGrantPaths(p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if err := policy.ValidateLandlockExactPaths(p.FS, handles); err != nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, err
	}
	// Review M13: Landlock compiles from the policy's FS axis plus a fixed
	// write carveout over the cgroup v2 hierarchy whenever the policy would
	// otherwise grant write there (HostWrite Allow). The guarantee bits and
	// the mount view below still read p.FS: the carveout narrows Landlock
	// only and must never manufacture a write-boundary claim the policy did
	// not make.
	cgroupCarveouts := cgroupWriteCarveouts(p.FS, b.CgroupPids)
	cfs := policy.CompileFSWithPathHandles(appendCgroupWriteCarveouts(p.FS, cgroupCarveouts), handles)
	cnet := CompileNetPolicy(p.Net)
	// Review C2: the AF_UNIX escape hatch. Rung 2 has no view and no Netns,
	// so the zero MountViewPlan / netns=false are the honest inputs.
	cu := compileUnixSockets(p.UnixSockets, RungTwo, ProbeLandlockABI(), MountViewPlan{}, false)
	// Task 14: resolve the cgroup v2 resource-limit plan against the Ancestor
	// probed at construction. Enforced() decides the ResourceLimits guarantee at
	// COMPILE time; each spawn creates the transient scope at SPAWN time (see
	// linuxWrap). Resource limits never change the isolation Level — they are
	// containment-of-cost, not authority (§7.4), so profile.LevelDegraded is unchanged.
	cg := CompileCgroupPolicy(p.Limits, b.CgroupPids)

	var bits uint64
	if policy.IsAccessRestricted(p.FS, policy.WriteAccess) {
		bits |= profile.GuaranteeWriteBoundary
	}
	if policy.IsAccessRestricted(p.FS, policy.ReadAccess|policy.ExecAccess) {
		bits |= profile.GuaranteeReadBoundary
	}
	if !p.Env.Inherit {
		bits |= profile.GuaranteeEnvScrub
	}
	// Task 12c: the TCP-port allowlist earns profile.GuaranteeNetworkBoundary whenever the
	// policy is net-Confined (!Net.Open). The port boundary is honest because 12b's
	// Seccomp socket() allowlist admits only plain inet TCP (plus NETLINK_ROUTE,
	// which carries no egress) on a Confined spawn — UDP, MPTCP, SCTP, SMC,
	// AF_UNIX, AF_VSOCK and every other family are refused — so classic TCP is
	// the only egress path and it is Confined to the allowlist. profile.GuaranteeAddressNetwork is NOT set — Rung 2 cannot
	// address-scope (Loopback/Private/metadata), recorded unenforced in the report.
	if cnet.Confined {
		bits |= profile.GuaranteeNetworkBoundary
	}
	// Task 14: the ResourceLimits guarantee holds iff a transient cgroup scope will
	// be created (cgroup v2 pids delegation available AND not policy-Disabled).
	// When unavailable the bit stays clear (fail-secure) and the spawn still runs,
	// just uncapped — recorded below.
	if cg.Enforced() {
		bits |= profile.GuaranteeResourceLimits
	}

	spec := enforce.Spec{Wrap: linuxWrapTransform(cfs, cnet, cg, nil, cu, handles), Release: nil}
	report := fsCompileReport(p, cfs)
	report.Entries = append(report.Entries, cgroupCarveoutReport(cgroupCarveouts)...)
	// Task 12b: record the Rung-2 Seccomp hardening. It does not by itself earn a
	// guarantee bit — it hardens the confinement by soft-denying dangerous syscalls
	// in every Rung-2 target, and its socket() allowlist load-bearingly refuses
	// every non-TCP egress family/protocol so the 12c TCP port allowlist is a
	// sound, non-bypassable network boundary.
	report.Entries = append(report.Entries, seccompReportEntry(!cnet.Confined, cu.allow))
	// Review C2: the AF_UNIX escape hatch's outcome (nothing for the default
	// denial). Rung 2 never claims GuaranteeProcessBoundary and is already
	// Degraded, so the entries are the whole of its effect here.
	report.Entries = append(report.Entries, cu.entries...)
	// Task 12c: record the Rung-2 network compilation (port allowlist Enforced,
	// DNS narrowed to TCP, address scoping unenforced).
	report.Entries = append(report.Entries, NetCompileReport(p.Net, cnet)...)
	// Task 14: record the cgroup v2 resource-limit outcome (Enforced when a
	// transient pids-capped scope will be created; unenforced — distinguishing a
	// policy opt-out from absent delegation — otherwise). It never changes Level.
	report.Entries = append(report.Entries, CgroupCompileReport(cg))
	return spec, report, profile.LevelDegraded, bits, nil
}

// compileRung1 builds the RUNG-1 (full-isolation) enforce.Spec (SPEC §7.2 Rung 1,
// §7.5). It compiles four mechanisms that COMPOSE on the stage-2 child:
//   - the bind-mount view (CompileMountView): rw/ro binds for writable/read
//     roots, ro re-mask binds for carveouts, empty-mask binds for fixed-path
//     secret denies and glob-deny matches, then pivot_root — so host paths NOT
//     bound are INVISIBLE (restricted-read, the Rung-1 property Rung 2 lacks);
//   - the in-Netns nftables address filter (CompileNftPlan): address-scoped
//     Loopback/Private, UDP+TCP DNS, and the §5.4 metadata hard-deny;
//   - the Landlock FS allowlist (policy.CompileFS, shared with Rung 2) — applied
//     on top of the mount view as defense-in-depth (SPEC §7.2 "then Landlock");
//   - the cgroup v2 scope (CompileCgroupPolicy, shared) for resource limits.
//
// Because the mount view enforces the write boundary, restricted-read and fixed
// denies, and nftables enforces the full address-scoped network semantics, a
// Rung-1 full policy reaches profile.LevelFull with every guarantee the
// mechanisms apply. Glob denies are masked by a depth-bounded spawn-time scan of
// the workspace, $HOME and the bound roots other than "/" and are reported
// "narrowed" (review M6): a match below GlobScanMaxDepth, one reachable only
// through a "/" host-read bind, or a file the command itself creates mid-run is
// not masked (§7.5). That residual does NOT demote Level. A feature the mechanism cannot reach would lower to
// Degraded and be recorded; for the standard tested profile shapes the mechanisms reach all of
// them, so Rung 1 is profile.LevelFull. Resource limits are containment-of-cost and never
// change Level (§7.4).
func (b Backend) compileRung1(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	return b.compileRung1WithGrantPaths(p, nil)
}

func (b Backend) compileRung1WithGrantPaths(p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if err := policy.ValidateLandlockExactPaths(p.FS, handles); err != nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, err
	}
	// Review M13: as at Rung 2, Landlock (layered on the view) withholds
	// write from the cgroup v2 hierarchy a "/" rw bind would expose.
	cgroupCarveouts := cgroupWriteCarveouts(p.FS, b.CgroupPids)
	landlockFS := appendCgroupWriteCarveouts(p.FS, cgroupCarveouts)
	cfs := policy.CompileFSWithPathHandles(landlockFS, handles)
	cg := CompileCgroupPolicy(p.Limits, b.CgroupPids)
	mvp := compileMountViewWithGrantPaths(p, handles)
	nft := CompileNftPlan(p.Net)
	// Review C2: the AF_UNIX escape hatch, confined by this view and (when
	// egress is Confined) this spawn's network namespace.
	cu := compileUnixSockets(p.UnixSockets, RungOne, ProbeLandlockABI(), mvp, nft.Confined)

	// The process boundary holds unless the AF_UNIX escape hatch admits an
	// endpoint outside it (review C2: an unconfined endpoint namespace or a
	// dangerous named socket); filesystem guarantees are reported only for
	// axes the effective policy actually restricts.
	var bits uint64
	if !cu.withholdProcessBoundary {
		bits |= profile.GuaranteeProcessBoundary
	}
	if policy.IsAccessRestricted(p.FS, policy.WriteAccess) {
		bits |= profile.GuaranteeWriteBoundary
	}
	if policy.IsAccessRestricted(p.FS, policy.ReadAccess|policy.ExecAccess) {
		bits |= profile.GuaranteeReadBoundary
	}
	if !p.Env.Inherit {
		bits |= profile.GuaranteeEnvScrub
	}
	if nft.Confined {
		// nftables address-scopes egress AND enforces the metadata hard-deny, so
		// Rung 1 earns BOTH the port-level network boundary and the address-network
		// guarantee (which Rung 2 can never set). An open policy sets neither.
		bits |= profile.GuaranteeNetworkBoundary | profile.GuaranteeAddressNetwork
	}
	if cg.Enforced() {
		bits |= profile.GuaranteeResourceLimits
	}

	r1 := &rung1Plan{mount: mvp, nft: nft}
	// cnet is empty: Rung 1 does NOT use the Landlock TCP-port net (nftables covers
	// egress), so linuxWrap sets NetConfined=false and injects no RES_OPTIONS.
	spec := enforce.Spec{Wrap: linuxWrapTransform(cfs, CompiledNet{}, cg, r1, cu, handles), Release: nil}
	report := rung1CompileReport(p, landlockFS, mvp, nft, cu)
	report.Entries = append(report.Entries, cgroupCarveoutReport(cgroupCarveouts)...)
	report.Entries = append(report.Entries, CgroupCompileReport(cg))
	// An endpoint the view cannot confine lowers the tier: Rung 1's Full
	// level is a statement about the process boundary it then cannot make.
	level := uint8(profile.LevelFull)
	if cu.withholdProcessBoundary {
		level = profile.LevelDegraded
	}
	return spec, report, level, bits, nil
}

// rung1CompileReport records how the Rung-1 mechanisms compiled each policy
// feature (SPEC §7.5). At Rung 1 the mount view + nftables enforce features Rung
// 2 can only narrow or drop: restricted-read invisibility and address-scoped
// network with the metadata hard-deny — "Enforced" — and glob denies, which the
// bounded spawn-time scan narrows rather than drops. It also discloses the
// shared per-axis Landlock snapshot narrowing and the glob-mask residual
// (§7.5); neither demotes Level.
func rung1CompileReport(p policy.Effective, landlockFS []policy.FSEntry, mvp MountViewPlan, nft compiledNftPlan, cu compiledUnix) profile.CompileReport {
	processBoundary := profile.ReportEntry{
		Feature: "process-boundary",
		Status:  "Enforced",
		Detail:  "target runs in fresh user+mount+pid+net namespaces via SysProcAttr cloneflags on the stage-2 re-exec (Rung 1, §7.2)",
	}
	if cu.withholdProcessBoundary {
		processBoundary.Status = "narrowed"
		processBoundary.Detail += "; the AF_UNIX escape hatch admits an endpoint outside it (see unix-sockets), so GuaranteeProcessBoundary is withheld"
	}
	entries := []profile.ReportEntry{
		processBoundary,
		{
			Feature: "write-boundary",
			Status:  "Enforced",
			Detail:  "writes Confined to policy writable roots by rw bind mounts (read roots are ro binds) plus a Landlock allowlist, in the mount-namespace view (Rung 1, §7.2)",
		},
		{
			Feature: "restricted-read",
			Status:  "Enforced",
			Detail:  "the mount view pivot_roots into a new root holding only the policy's bound roots; host paths not bound are INVISIBLE (not merely unreadable) — the Rung-1 property Rung 2 cannot provide (§7.2, §7.5)",
		},
	}
	if snapshot, ok := filesystemAxisSnapshotEntry(policy.CompileFS(landlockFS)); ok {
		entries = append(entries, snapshot)
	}
	if mvp.hasLiteralDeny {
		entries = append(entries, profile.ReportEntry{
			Feature: "fixed-path-deny",
			Status:  "Enforced",
			Detail:  "fixed-path denies without restorations use empty read-only mount masks; higher-precedence literal restorations compose through the enumerated Landlock rules without a coarse mask that would hide the restored path (§5.1, §7.5)",
		})
	}
	if mountPlanHasReadOnlyCarveout(mvp) {
		entries = append(entries, profile.ReportEntry{
			Feature: "carveout",
			Status:  "Enforced",
			Detail:  "read-only carveouts (.git/.looprig) Enforced as ro re-mask binds applied on top of their writable root in the mount view (§7.5)",
		})
	}
	if len(mvp.GlobDenies) > 0 {
		entries = append(entries, profile.ReportEntry{
			Feature: "glob-deny",
			Status:  "narrowed",
			Detail: fmt.Sprintf("glob denies (e.g. **/.env*) are masked with empty read-only binds by a spawn-time bounded enumeration of the workspace, $HOME and every bound writable or read-only root except the filesystem root \"/\", to a depth of %d below each root; "+
				"a match deeper than that, a match reachable only through a \"/\" host-read bind outside those roots, and a file the command itself creates mid-run are not masked (§7.5)", GlobScanMaxDepth),
		})
	}
	if !p.Env.Inherit {
		entries = append(entries, profile.ReportEntry{
			Feature: "env-scrub",
			Status:  "Enforced",
			Detail:  "target execve'd with the policy.EnvPolicy baseline; the harness process environment (secrets) is absent (§5.5)",
		})
	}
	entries = append(entries, allowPathsReportEntry())
	// Rung 1 installs the same stage-2 Seccomp filter, with UDP always admitted
	// (linuxWrap): nftables scopes UDP in the Netns, or the policy is Open.
	entries = append(entries, seccompReportEntry(true, cu.allow))
	entries = append(entries, cu.entries...)
	entries = append(entries, rung1NetReport(nft)...)
	return profile.CompileReport{Entries: entries}
}

// seccompReportEntry records the stage-2 Seccomp filter (review C2/H1/H2/M12):
// the socket() allowlist, whether UDP and AF_UNIX are admitted for this
// compile, and the nr/argument denials. Both rungs install the same filter
// shape.
func seccompReportEntry(allowUDP, allowUnix bool) profile.ReportEntry {
	udp := "UDP is refused (no Landlock address/port scoping for it; DNS is forced over TCP)"
	if allowUDP {
		udp = "UDP (protocol 0/IPPROTO_UDP) is admitted because egress is Open or scoped by the Rung-1 nftables filter"
	}
	unixSockets := "; AF_UNIX pathname/abstract sockets (D-Bus, ssh-agent, docker.sock) are refused"
	if allowUnix {
		unixSockets = "; AF_UNIX stream/datagram/seqpacket sockets are admitted by the profile's UnixSocketPolicy escape hatch, with their reachable endpoints reported under unix-sockets"
	}
	return profile.ReportEntry{
		Feature: "Seccomp-hardening",
		Status:  "Enforced",
		Detail: "Seccomp-BPF filter in the stage-2 target allows socket() only for AF_INET/AF_INET6 SOCK_STREAM TCP and AF_NETLINK NETLINK_ROUTE; " + udp + unixSockets +
			"; every other family or protocol (AF_VSOCK, AF_SMC, AF_RDS, MPTCP, SCTP, SMC, raw) is refused, socketpair() stays allowed, " +
			"ptrace, io_uring and keyctl/add_key/request_key are denied, and ioctl TIOCSTI/TIOCLINUX (terminal input injection) is denied (EACCES); the target also starts in its own session, without the harness's controlling terminal; installed after Landlock, inherited across execve (§7.2)",
	}
}

func filesystemAxisSnapshotEntry(cfs policy.CompiledFS) (profile.ReportEntry, bool) {
	axes := cfs.SnapshotAxes()
	if axes == 0 {
		return profile.ReportEntry{}, false
	}
	var names []string
	for _, axis := range []struct {
		bit  policy.FSAccess
		name string
	}{
		{policy.ReadAccess, "read"},
		{policy.ExecAccess, "execute"},
		{policy.WriteAccess, "write"},
	} {
		if axes&axis.bit != 0 {
			names = append(names, axis.name)
		}
	}
	detail := "protected path scopes within a recursive allow require shared Landlock child enumeration on denied axes: " +
		strings.Join(names, ", ") + "; pre-existing unaffected children retain policy-allowed access"
	if axes&policy.WriteAccess != 0 {
		detail += ", while withholding directory write at snapshot boundaries and throughout recursive read/execute-denied scopes (except where a narrower recursive allow restores the denied read/execute over the writable path) blocks new entries and prevents rename/link pathname replacement (§7.5)"
	} else {
		detail += "; write authority is not withheld, so creation may remain permitted, but new entries lack denied-axis authority (§7.5)"
	}
	return profile.ReportEntry{
		Feature: "filesystem-axis-snapshot",
		Status:  "narrowed",
		Detail:  detail,
	}, true
}

func mountPlanHasReadOnlyCarveout(mvp MountViewPlan) bool {
	for _, writable := range mvp.RWBinds {
		for _, readOnly := range mvp.ROBinds {
			if policy.PathUnder(writable, readOnly) {
				return true
			}
		}
	}
	return false
}

// rung1NetReport records the Rung-1 network compilation (SPEC §5.2, §5.4, §7.5).
// Confined egress earns both the port boundary and address scoping (nftables);
// an open policy applies no filter (the Netns is not even created).
func rung1NetReport(nft compiledNftPlan) []profile.ReportEntry {
	if !nft.Confined {
		return []profile.ReportEntry{{
			Feature: "network",
			Status:  "unenforced",
			Detail:  "Net.Open grants unrestricted egress; the Rung-1 net namespace is not created and no nftables filter is installed (unconfined passthrough, §5.2)",
		}}
	}
	entries := []profile.ReportEntry{
		{
			Feature: "network-boundary",
			Status:  "Enforced",
			Detail:  "egress Confined by an in-Netns nftables inet filter (output chain policy DROP) to the allowed TCP ports; UDP is dropped except DNS (Rung 1, §5.2)",
		},
		{
			Feature: "address-network",
			Status:  "Enforced",
			Detail:  "address-scoped rules Enforced in-Netns: Loopback (oif lo + daddr 127/8, ::1), RFC1918/ULA Private ranges, and UDP+TCP DNS — the address boundary Rung 2 cannot express (§5.2, §7.2 Rung 1)",
		},
		{
			Feature: "metadata-deny",
			Status:  "Enforced",
			Detail:  "cloud-metadata endpoints (169.254.0.0/16, fd00:ec2::254) hard-dropped ahead of the Private accept, so ULA-matching metadata is still denied (§5.4)",
		},
	}
	return entries
}

// fsCompileReport records how the Rung-2 FS compilation treated each policy
// feature (SPEC §7.5): the write boundary and fixed-path denies are Enforced;
// per-axis sibling enumeration and read-only carveouts are narrowed (snapshot
// semantics on their covering allow); glob denies are unenforced (inexpressible
// in Landlock's additive model, left to the in-process ReadGuard for native
// tools). It also notes that nonexistent allow paths are dropped at spawn (fail
// secure).
func fsCompileReport(p policy.Effective, cfs policy.CompiledFS) profile.CompileReport {
	entries := []profile.ReportEntry{{
		Feature: "write-boundary",
		Status:  "Enforced",
		Detail:  "writes Confined to policy writable roots via Landlock (Rung 2, ABI v4)",
	}}
	if cfs.HasLiteralDeny() {
		entries = append(entries, profile.ReportEntry{
			Feature: "fixed-path-deny",
			Status:  "Enforced",
			Detail:  "fixed-path secret deny-reads Enforced by enumerated sibling allows, snapshot at spawn (§7.5)",
		})
	}
	if cfs.HasCarveout() {
		entries = append(entries, profile.ReportEntry{
			Feature: "carveout",
			Status:  "narrowed",
			Detail:  "read-only carveouts (.git/.looprig) Enforced by enumerating a writable root's children at spawn; the root itself is not granted, so files created at the root after spawn are inaccessible (snapshot semantics, §7.5 — errs narrow)",
		})
	}
	if snapshot, ok := filesystemAxisSnapshotEntry(cfs); ok {
		entries = append(entries, snapshot)
	}
	if policyHasGlobDeny(p) {
		entries = append(entries, profile.ReportEntry{
			Feature: "glob-deny",
			Status:  "unenforced",
			Detail:  "glob deny-reads (e.g. **/.env*) are not expressible in Landlock's additive model at Rung 2; the in-process ReadGuard still enforces them for native tools — subprocess reads are the gap (§7.5)",
		})
	}
	entries = append(entries, allowPathsReportEntry())
	return profile.CompileReport{Entries: entries}
}

func allowPathsReportEntry() profile.ReportEntry {
	return profile.ReportEntry{
		Feature: "allow-paths",
		Status:  "narrowed",
		Detail: "allow paths are stat'd at spawn; a nonexistent path, a symlink out of an enumerated tree, or a direct regular-file rule with multiple hard links is dropped rather than granted " +
			"(fail secure; directory ancestor rules are unaffected)",
	}
}

// policyHasGlobDeny reports whether the policy carries any glob DENY entry, which
// Rung 2 cannot enforce for subprocesses (recorded unenforced in the report).
func policyHasGlobDeny(p policy.Effective) bool {
	for _, e := range p.FS {
		if e.Access == policy.DenyAccess && strings.ContainsAny(e.Path, policy.GlobMeta) {
			return true
		}
	}
	return false
}

// linuxWrapTransform returns the per-spawn transform for a compiled FS + net
// policy: it re-execs /proc/self/exe and, on each spawn, enumerates cfs into a
// fresh Landlock allowlist (a snapshot of the live filesystem) and seals it plus
// the net allowlist (cnet) into the stage-2 child. Fresh closures per call are
// load-bearing — each closes over its own (dir, innerArgv), its own enumerated
// rules, and its own pipe, so concurrent spawns never share per-spawn state or a
// file descriptor.
func linuxWrapTransform(cfs policy.CompiledFS, cnet CompiledNet, cg CompiledCgroup, r1 *rung1Plan, cu compiledUnix, handles []*policy.PathHandle) func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
	return func(dir string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
		return linuxWrap(cfs, cnet, cg, r1, cu, handles, dir, innerArgv)
	}
}

// linuxWrap is the per-spawn transform body. It re-execs /proc/self/exe and
// returns a fresh configure/cleanup pair that enumerates the FS rules at spawn,
// seals THIS spawn's spec (FS allowlist + net allowlist) into the stage-2 child
// over a Private pipe, and — when the policy forces DNS over TCP — injects
// RES_OPTIONS=use-vc into the target env.
// When r1 is non-nil the spawn is RUNG 1 (Task 13): configure enumerates the
// bind-mount view at spawn (a fresh snapshot), sets the namespace cloneflags +
// uid/gid maps on the SysProcAttr, and tags the spec Stage2RungOne so the child
// applies the mount view + nftables before Landlock. The cloneflags, the spec
// pipe, and the cgroup UseCgroupFD all coexist on the one SysProcAttr. r1 == nil
// is the Rung-2 path (no namespaces), unchanged.
func linuxWrap(cfs policy.CompiledFS, cnet CompiledNet, cg CompiledCgroup, r1 *rung1Plan, cu compiledUnix, handles []*policy.PathHandle, dir string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
	// Re-exec THIS binary (/proc/self/exe, NOT os.Args[0]): the kernel resolves it
	// even for a deleted binary, and it is the exact image whose Init() dispatches
	// the stage-2 child.
	finalArgv := []string{"/proc/self/exe"}

	// pipeR/pipeW are this spawn's Private spec pipe, captured so cleanup can close
	// both ends after the spawn completes.
	var pipeR, pipeW *os.File
	// tcg is this spawn's transient cgroup v2 scope (Task 14), captured so cleanup
	// can tear it down unconditionally. It is nil when limits are not applied (no
	// delegation / policy-Disabled) or when scope creation failed best-effort.
	var tcg *transientCgroup

	var grantRuleFiles []*os.File
	configure := func(cmd *exec.Cmd) error {
		// Capture the TARGET environment BEFORE adding the dispatch sentinel, so the
		// execve'd target never observes LRSANDBOX_STAGE2. The executor has already
		// set cmd.Env to the scrubbed child environment at this point.
		targetEnv := append([]string(nil), cmd.Env...)
		// Task 12c: when the policy forces DNS over TCP, ensure the target's glibc
		// resolver uses TCP (RES_OPTIONS=use-vc) — UDP is Seccomp-blocked (12b), so
		// without this glibc's initial UDP query fails. Mutating targetEnv (a fresh
		// copy) is safe and never touches the parent's cmd.Env.
		if cnet.Dns {
			targetEnv = EnsureResOptionsUseVC(targetEnv)
		}
		// Enumerate the FS allowlist NOW (per spawn) so it is a fresh snapshot of
		// the live filesystem: a secret that exists when the command starts is
		// carved out; a file the command later creates is not (§7.5 snapshot
		// semantics). The stage-2 child rebuilds the Landlock ruleset from this.
		fsRules, relativeFiles, err := policy.EnumerateFSRulesWithPathHandles(cfs, handles)
		if err != nil {
			return err
		}
		grantRuleFiles = relativeFiles
		// Seccomp is unconditionally requested: both rungs are only selected when
		// the Seccomp capability was probed present (SelectRung requires
		// c.Seccomp), so the stage-2 install cannot be a surprise failure. Its
		// socket() allowlist admits UDP only when nothing else would scope it
		// anyway: an Open Rung-2 network here, and every Rung-1 spawn below
		// (nftables scopes UDP in the Netns) — review H2.
		spec := Stage2Spec{
			Dir:             dir,
			Argv:            innerArgv,
			Env:             targetEnv,
			FSRules:         fsRules,
			Seccomp:         true,
			SeccompAllowUDP: !cnet.Confined,
			// Review C2: AF_UNIX only under the profile's escape hatch, with
			// Landlock's abstract-socket scope whenever the compile found
			// ABI >= 6 (compileUnixSockets).
			SeccompAllowUnix:          cu.allow,
			LandlockScopeAbstractUnix: cu.scopeAbstract,
			NetConfined:               cnet.Confined,
			NetTCPPorts:               cnet.TcpPorts,
			Rung:                      stage2RungTwo,
		}
		for index := range handles {
			spec.GrantFDs = append(spec.GrantFDs, policy.FirstPathHandleChildFD+index)
		}
		for index := range grantRuleFiles {
			spec.GrantFDs = append(spec.GrantFDs, policy.FirstPathHandleChildFD+len(handles)+index)
		}
		// Task 13: a Rung-1 spawn additionally enumerates the bind-mount view (a
		// fresh snapshot, like the FS allowlist above) and carries the nftables plan.
		// It uses nftables for egress, so it leaves NetConfined false (no Landlock TCP
		// net) — the Netns filter is the network boundary.
		if r1 != nil {
			spec.Rung = Stage2RungOne
			mountView, err := enumerateMountViewWithGrantPaths(r1.mount, fsRules, handles)
			if err != nil {
				policy.CloseRuleFiles(grantRuleFiles)
				grantRuleFiles = nil
				return err
			}
			spec.MountView = mountView
			// Review C2: each named socket that is a socket NOW is bound
			// into the view as that one file; stage 2 re-resolves it.
			spec.MountView.Sockets = enumerateSocketBinds(cu.socketBinds)
			spec.NftRules = r1.nft.toNftSpec()
			spec.NetConfined = false
			spec.NetTCPPorts = nil
			// SPEC §6.1: Rung 1 permits UDP/TCP 53 and nftables drops every
			// other UDP datagram inside the Netns (and an Open policy creates no
			// Netns at all), so the filter must not refuse the socket itself.
			spec.SeccompAllowUDP = true
		}

		r, w, err := os.Pipe()
		if err != nil {
			// Fail closed: with no spec pipe the child's fd 3 is absent, its decode
			// fails, and RunStage2 exits non-zero rather than running the target.
			// Still add the sentinel so the child dispatches into that fail-closed
			// path instead of running the re-exec'd program as itself.
			cmd.Env = append(cmd.Env, Stage2SentinelEnv+"="+Stage2SentinelValue)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			return nil
		}
		pipeR, pipeW = r, w

		// The read end becomes fd 3 in the child (ExtraFiles[0], since 0/1/2 are
		// stdio) — Stage2SpecFD.
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		for _, handle := range handles {
			cmd.ExtraFiles = append(cmd.ExtraFiles, handle.File())
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, grantRuleFiles...)
		// Add the dispatch sentinel to the CHILD's env only (after capturing the
		// target env above), so the child's Init() runs RunStage2.
		cmd.Env = append(cmd.Env, Stage2SentinelEnv+"="+Stage2SentinelValue)
		// Base SysProcAttr; the cgroup join (UseCgroupFD) below extends it. For a
		// Rung-1 spawn, set the namespace cloneflags + uid/gid maps here (Task 13):
		// user+mount+pid namespaces always, plus a net namespace only when egress is
		// Confined (an open policy must keep host networking). These coexist with the
		// spec pipe and the cgroup fd on the one struct.
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		// Review M12/L1: every target starts in its own session, so it never
		// holds the harness's controlling terminal: /dev/tty fails ENXIO and a
		// TIOCSTI aimed at the user's shell has no terminal to reach (the
		// Seccomp rule refuses the ioctl itself as a second layer). setsid(2)
		// also makes the child its own process-group leader, the
		// pgid-equals-pid shape processTree's group signalling keys on, so
		// newProcessTree sees Setsid and skips Setpgid (POSIX forbids both);
		// a TTY spawn adds Setctty onto its own PTY after this configure.
		// Stage 2 re-checks the invariant and fails closed without it.
		cmd.SysProcAttr.Setsid = true
		if r1 != nil {
			ConfigureRung1SysProcAttr(cmd.SysProcAttr, r1.nft.Confined)
		}

		// Task 14: create this spawn's transient cgroup v2 scope and join the stage-2
		// child to it at clone time via CLONE_INTO_CGROUP (UseCgroupFD). The scope
		// carries the policy's resource limits (pids.max is the fork-bomb cap), so the
		// child — and everything it forks — is capped from its first fork. Resource
		// limits are containment-of-cost, not authority (§7.4): if the scope cannot be
		// created this spawn still runs, just UNCAPPED (fail-secure, best-effort — the
		// compile-time guarantee already reflected availability). CreateTransientCgroup
		// returns (nil, nil) when the plan applies no limits, so the join is simply
		// left unset. It EXTENDS the SysProcAttr above rather than replacing it.
		tc, cgErr := CreateTransientCgroup(cg)
		switch {
		case cgErr != nil:
			// Best-effort: this spawn runs without a cgroup cap (§7.4); not fatal.
			tcg = nil
		case tc != nil:
			tcg = tc
			cmd.SysProcAttr.UseCgroupFD = true
			cmd.SysProcAttr.CgroupFD = tc.fd
		}

		// Encode the spec on a goroutine: the gob payload is small (fits the pipe
		// buffer), so this completes without blocking even before the child reads,
		// but the goroutine keeps the spawn non-blocking regardless. Best-effort:
		// on an encode failure the child's decode fails closed.
		go func() {
			_ = EncodeStage2Spec(w, spec)
			_ = w.Close() // signal EOF so the child's gob decode terminates
		}()
		return nil
	}

	cleanup := func() {
		// Task 14: tear down this spawn's transient cgroup FIRST (kill any survivors
		// in the scope, then rmdir). Unconditional and safe — it only ever touches
		// the scope this spawn created, and is a no-op when none was created.
		if tcg != nil {
			tcg.Teardown()
		}
		// Release this spawn's pipe ends after the spawn completes. The child holds
		// its own dup of the read end; closing the parent's copies here frees the
		// fds. w may already be closed by the encode goroutine — a double close is a
		// harmless best-effort no-op.
		if pipeR != nil {
			_ = pipeR.Close()
		}
		if pipeW != nil {
			_ = pipeW.Close()
		}
		policy.CloseRuleFiles(grantRuleFiles)
	}

	return finalArgv, configure, cleanup
}
