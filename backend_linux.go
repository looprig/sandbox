//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// linuxBackend is the Linux OS-enforcement backend (SPEC §7.2). It compiles a
// policy into a spawnSpec whose wrap re-execs THIS binary (/proc/self/exe) into
// a stage-2 helper (Init -> runStage2) that becomes the confined target.
//
// Task 12a wires the RUNG-2 filesystem axis: compile distils the policy's FS
// entries into a compiledFS, the per-spawn wrap enumerates that into a flat
// Landlock allowlist against the live filesystem (snapshot semantics), and the
// stage-2 child applies the ruleset before execve. Rung 1 (namespaces/cgroup,
// Task 13), seccomp (Task 14), and network scoping (Task 12c) still fill in
// later; until then the backend reports LevelDegraded with the write-boundary +
// read-deny + env-scrub guarantees a rung-2 FS confinement genuinely upholds.
type linuxBackend struct {
	// cgroupPids is the writable cgroup v2 ancestor distributing the pids
	// controller, probed ONCE at construction (Task 14, SPEC §7.4), or "" when no
	// such ancestor exists. It decides — at compile time — whether the
	// ResourceLimits guarantee holds; each spawn creates its transient scope under
	// it. Probing at construction (not per spawn) makes the guarantee a stable
	// property of the executor: availability is measured once, the same value the
	// per-spawn configure uses.
	cgroupPids string
	// rung is the confinement tier this backend compiles for (Task 13, SPEC §7.2):
	// rungTwo (Landlock + seccomp, no namespaces) or rungOne (namespaces + mount
	// view + nftables, then Landlock + seccomp). compile branches on it. The zero
	// value would be rungNone, but the constructors always set a re-exec rung, so a
	// backend selected by platformBackend is never rungNone.
	rung rung
}

// newLinuxBackend constructs the RUNG-2 Linux backend. It keeps its no-argument
// signature (existing callers and tests rely on it — withBackend(newLinuxBackend())
// pins rung 2) and probes the delegated cgroup v2 pids ancestor here so compile
// can decide the ResourceLimits guarantee (SPEC §7.4). rung-2 FS confinement is
// compiled from the policy alone.
func newLinuxBackend() *linuxBackend {
	return &linuxBackend{cgroupPids: probeDelegatedPidsAncestor(), rung: rungTwo}
}

// newLinuxBackendRung1 constructs the RUNG-1 (full-isolation) Linux backend
// (Task 13, SPEC §7.2 rung 1): user+mount+pid+net namespaces via the stage-2
// SysProcAttr cloneflags, a bind-mount view (restricted-read + deny-by-mask),
// in-netns nftables address filtering, then Landlock + seccomp + cgroup. It is
// selected by platformBackend only on a host whose probe confirmed a usable
// userns+mountns+netns (selectRung -> rungOne). It shares the cgroup probe with
// rung 2.
func newLinuxBackendRung1() *linuxBackend {
	return &linuxBackend{cgroupPids: probeDelegatedPidsAncestor(), rung: rungOne}
}

// compile dispatches on the backend's rung (SPEC §7.2): rung 1 compiles the full
// namespace/mount/nftables tier (compileRung1); rung 2 (and the no-arg
// newLinuxBackend, which existing tests pin) compiles the Landlock+seccomp tier
// (compileRung2). It never errors — a policy that compiles to a narrower ruleset
// is reported via level/bits/report, not via err.
func (b linuxBackend) compile(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	if b.rung == rungOne {
		return b.compileRung1(p)
	}
	return b.compileRung2(p)
}

// compileRung2 builds the re-exec spawnSpec and applies rung-2 FS confinement. It
// distils the policy's FS axis into a compiledFS (literal allows + literal
// denies; globs dropped), which the per-spawn wrap enumerates into a Landlock
// allowlist. It reports LevelDegraded (rung 2 enforces the write boundary and
// fixed-path denies but cannot express glob denies or address-scoped network for
// subprocesses, §7.5) with GuaranteeWriteBoundary, GuaranteeReadBoundary (when the
// policy carries an enforceable fixed-path deny), and GuaranteeEnvScrub (when
// !Env.Inherit). The CompileReport records what was enforced vs narrowed vs
// unenforced.
func (b linuxBackend) compileRung2(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	cfs := compileFSPolicy(p.FS)
	cnet := compileNetPolicy(p.Net)
	// Task 14: resolve the cgroup v2 resource-limit plan against the ancestor
	// probed at construction. enforced() decides the ResourceLimits guarantee at
	// COMPILE time; each spawn creates the transient scope at SPAWN time (see
	// linuxWrap). Resource limits never change the isolation Level — they are
	// containment-of-cost, not authority (§7.4), so LevelDegraded is unchanged.
	cg := compileCgroupPolicy(p.limits, b.cgroupPids)

	bits := GuaranteeWriteBoundary
	if cfs.hasLiteralDeny() {
		bits |= GuaranteeReadBoundary
	}
	if !p.Env.Inherit {
		bits |= GuaranteeEnvScrub
	}
	// Task 12c: the TCP-port allowlist earns GuaranteeNetworkBoundary whenever the
	// policy is net-confined (!Net.Open). The port boundary is honest because 12b's
	// seccomp filter blocks UDP (no address scoping) and MPTCP (which Landlock's
	// port rules do not cover), so classic TCP is the only egress path and it is
	// confined to the allowlist. GuaranteeAddressNetwork is NOT set — rung 2 cannot
	// address-scope (loopback/private/metadata), recorded unenforced in the report.
	if cnet.confined {
		bits |= GuaranteeNetworkBoundary
	}
	// Task 14: the ResourceLimits guarantee holds iff a transient cgroup scope will
	// be created (cgroup v2 pids delegation available AND not policy-disabled).
	// When unavailable the bit stays clear (fail-secure) and the spawn still runs,
	// just uncapped — recorded below.
	if cg.enforced() {
		bits |= GuaranteeResourceLimits
	}

	spec := spawnSpec{wrap: linuxWrapTransform(cfs, cnet, cg, nil)}
	report := fsCompileReport(p, cfs)
	// Task 12b: record the rung-2 seccomp hardening. It does not by itself earn a
	// guarantee bit — it hardens the confinement by soft-denying dangerous syscalls
	// in every rung-2 target, and load-bearingly blocks UDP/MPTCP so the 12c TCP
	// port allowlist is a sound, non-bypassable network boundary.
	report.Entries = append(report.Entries, ReportEntry{
		Feature: "seccomp-hardening",
		Status:  "enforced",
		Detail:  "rung-2 seccomp-BPF filter denies UDP/MPTCP sockets, ptrace, and io_uring in the stage-2 target (EACCES); installed after Landlock, inherited across execve (§7.2)",
	})
	// Task 12c: record the rung-2 network compilation (port allowlist enforced,
	// DNS narrowed to TCP, address scoping unenforced).
	report.Entries = append(report.Entries, netCompileReport(p.Net, cnet)...)
	// Task 14: record the cgroup v2 resource-limit outcome (enforced when a
	// transient pids-capped scope will be created; unenforced — distinguishing a
	// policy opt-out from absent delegation — otherwise). It never changes Level.
	report.Entries = append(report.Entries, cgroupCompileReport(cg))
	return spec, report, LevelDegraded, bits, nil
}

// compileRung1 builds the RUNG-1 (full-isolation) spawnSpec (SPEC §7.2 rung 1,
// §7.5). It compiles four mechanisms that COMPOSE on the stage-2 child:
//   - the bind-mount view (compileMountView): rw/ro binds for writable/read
//     roots, ro re-mask binds for carveouts, empty-mask binds for fixed-path
//     secret denies and glob-deny matches, then pivot_root — so host paths NOT
//     bound are INVISIBLE (restricted-read, the rung-1 property rung 2 lacks);
//   - the in-netns nftables address filter (compileNftPlan): address-scoped
//     loopback/private, UDP+TCP DNS, and the §5.4 metadata hard-deny;
//   - the Landlock FS allowlist (compileFSPolicy, shared with rung 2) — applied
//     on top of the mount view as defense-in-depth (SPEC §7.2 "then Landlock");
//   - the cgroup v2 scope (compileCgroupPolicy, shared) for resource limits.
//
// Because the mount view enforces the write boundary, restricted-read, fixed AND
// glob denies, and nftables enforces the full address-scoped network semantics,
// a rung-1 full policy reaches LevelFull with every guarantee the mechanisms
// apply. The one accepted residual — a file the command itself creates mid-run
// escaping a spawn-time glob mask (§7.5) — is sound (never wider than policy) and
// does NOT demote Level. A feature the mechanism cannot reach would lower to
// Degraded and be recorded; for the standard presets the mechanisms reach all of
// them, so rung 1 is LevelFull. Resource limits are containment-of-cost and never
// change Level (§7.4).
func (b linuxBackend) compileRung1(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	cfs := compileFSPolicy(p.FS)
	cg := compileCgroupPolicy(p.limits, b.cgroupPids)
	mvp := compileMountView(p)
	nft := compileNftPlan(p.Net)

	// ProcessBoundary + WriteBoundary are unconditional at rung 1: the child runs
	// inside user+mount+pid(+net) namespaces (process boundary) and writes are
	// confined to the rw binds + Landlock (write boundary).
	bits := GuaranteeProcessBoundary | GuaranteeWriteBoundary
	if mvp.hasDenies() {
		// The mount masks enforce BOTH fixed-path and glob denies for subprocesses
		// (unlike rung 2, which cannot express globs) — the ReadBoundary guarantee.
		bits |= GuaranteeReadBoundary
	}
	if !p.Env.Inherit {
		bits |= GuaranteeEnvScrub
	}
	if nft.confined {
		// nftables address-scopes egress AND enforces the metadata hard-deny, so
		// rung 1 earns BOTH the port-level network boundary and the address-network
		// guarantee (which rung 2 can never set). An open policy sets neither.
		bits |= GuaranteeNetworkBoundary | GuaranteeAddressNetwork
	}
	if cg.enforced() {
		bits |= GuaranteeResourceLimits
	}

	r1 := &rung1Plan{mount: mvp, nft: nft}
	// cnet is empty: rung 1 does NOT use the Landlock TCP-port net (nftables covers
	// egress), so linuxWrap sets NetConfined=false and injects no RES_OPTIONS.
	spec := spawnSpec{wrap: linuxWrapTransform(cfs, compiledNet{}, cg, r1)}
	report := rung1CompileReport(p, mvp, nft)
	report.Entries = append(report.Entries, cgroupCompileReport(cg))
	return spec, report, LevelFull, bits, nil
}

// rung1CompileReport records how the rung-1 mechanisms compiled each policy
// feature (SPEC §7.5). At rung 1 the mount view + nftables enforce features rung
// 2 can only narrow or drop: restricted-read invisibility, glob denies, and
// address-scoped network with the metadata hard-deny — all "enforced". The one
// recorded residual is the self-created-file glob-mask gap (§7.5), which does not
// demote Level.
func rung1CompileReport(p effectivePolicy, mvp mountViewPlan, nft compiledNftPlan) CompileReport {
	entries := []ReportEntry{
		{
			Feature: "process-boundary",
			Status:  "enforced",
			Detail:  "target runs in fresh user+mount+pid+net namespaces via SysProcAttr cloneflags on the stage-2 re-exec (rung 1, §7.2)",
		},
		{
			Feature: "write-boundary",
			Status:  "enforced",
			Detail:  "writes confined to policy writable roots by rw bind mounts (read roots are ro binds) plus a Landlock allowlist, in the mount-namespace view (rung 1, §7.2)",
		},
		{
			Feature: "restricted-read",
			Status:  "enforced",
			Detail:  "the mount view pivot_roots into a new root holding only the policy's bound roots; host paths not bound are INVISIBLE (not merely unreadable) — the rung-1 property rung 2 cannot provide (§7.2, §7.5)",
		},
	}
	if len(mvp.denyMasks) > 0 {
		entries = append(entries, ReportEntry{
			Feature: "fixed-path-deny",
			Status:  "enforced",
			Detail:  "fixed-path secret denies masked by empty read-only bind mounts on top of any covering allow (deny-inside-allow via mount re-masking, §7.5 — no sibling enumeration, unlike rung 2)",
		})
	}
	if len(mvp.roBinds) > 0 {
		entries = append(entries, ReportEntry{
			Feature: "carveout",
			Status:  "enforced",
			Detail:  "read-only carveouts (.git/.looprig) enforced as ro re-mask binds applied on top of their writable root in the mount view (§7.5)",
		})
	}
	if len(mvp.globDenies) > 0 {
		entries = append(entries, ReportEntry{
			Feature: "glob-deny",
			Status:  "enforced",
			Detail:  "glob denies (e.g. **/.env*) enforced by spawn-time bounded enumeration (scan workspace + $HOME to a max depth) masking each match with an empty read-only bind; the only residual is a file the command itself creates mid-run, which holds no pre-existing secret and does not demote Level (§7.5)",
		})
	}
	if !p.Env.Inherit {
		entries = append(entries, ReportEntry{
			Feature: "env-scrub",
			Status:  "enforced",
			Detail:  "target execve'd with the effectiveEnvPolicy baseline; the harness process environment (secrets) is absent (§5.5)",
		})
	}
	entries = append(entries, rung1NetReport(nft)...)
	return CompileReport{Entries: entries}
}

// rung1NetReport records the rung-1 network compilation (SPEC §5.2, §5.4, §7.5).
// Confined egress earns both the port boundary and address scoping (nftables);
// an open policy applies no filter (the netns is not even created).
func rung1NetReport(nft compiledNftPlan) []ReportEntry {
	if !nft.confined {
		return []ReportEntry{{
			Feature: "network",
			Status:  "unenforced",
			Detail:  "Net.Open grants unrestricted egress; the rung-1 net namespace is not created and no nftables filter is installed (unconfined passthrough, §5.2)",
		}}
	}
	entries := []ReportEntry{
		{
			Feature: "network-boundary",
			Status:  "enforced",
			Detail:  "egress confined by an in-netns nftables inet filter (output chain policy DROP) to the allowed TCP ports; UDP is dropped except DNS (rung 1, §5.2)",
		},
		{
			Feature: "address-network",
			Status:  "enforced",
			Detail:  "address-scoped rules enforced in-netns: loopback (oif lo + daddr 127/8, ::1), RFC1918/ULA private ranges, and UDP+TCP DNS — the address boundary rung 2 cannot express (§5.2, §7.2 rung 1)",
		},
		{
			Feature: "metadata-deny",
			Status:  "enforced",
			Detail:  "cloud-metadata endpoints (169.254.0.0/16, fd00:ec2::254) hard-dropped ahead of the Private accept, so ULA-matching metadata is still denied (§5.4)",
		},
	}
	return entries
}

// fsCompileReport records how the rung-2 FS compilation treated each policy
// feature (SPEC §7.5): the write boundary and fixed-path denies are enforced;
// read-only carveouts are narrowed (snapshot semantics on their writable root);
// glob denies are unenforced (inexpressible in Landlock's additive model, left
// to the in-process ReadGuard for native tools). It also notes that nonexistent
// allow paths are dropped at spawn (fail secure).
func fsCompileReport(p effectivePolicy, cfs compiledFS) CompileReport {
	entries := []ReportEntry{{
		Feature: "write-boundary",
		Status:  "enforced",
		Detail:  "writes confined to policy writable roots via Landlock (rung 2, ABI v4)",
	}}
	if cfs.hasLiteralDeny() {
		entries = append(entries, ReportEntry{
			Feature: "fixed-path-deny",
			Status:  "enforced",
			Detail:  "fixed-path secret deny-reads enforced by enumerated sibling allows, snapshot at spawn (§7.5)",
		})
	}
	if cfs.hasCarveout() {
		entries = append(entries, ReportEntry{
			Feature: "carveout",
			Status:  "narrowed",
			Detail:  "read-only carveouts (.git/.looprig) enforced by enumerating a writable root's children at spawn; the root itself is not granted, so files created at the root after spawn are inaccessible (snapshot semantics, §7.5 — errs narrow)",
		})
	}
	if policyHasGlobDeny(p) {
		entries = append(entries, ReportEntry{
			Feature: "glob-deny",
			Status:  "unenforced",
			Detail:  "glob deny-reads (e.g. **/.env*) are not expressible in Landlock's additive model at rung 2; the in-process ReadGuard still enforces them for native tools — subprocess reads are the gap (§7.5)",
		})
	}
	entries = append(entries, ReportEntry{
		Feature: "allow-paths",
		Status:  "narrowed",
		Detail:  "allow paths are stat'd at spawn; a nonexistent path or a symlink out of an enumerated tree is dropped rather than granted (fail secure)",
	})
	return CompileReport{Entries: entries}
}

// policyHasGlobDeny reports whether the policy carries any glob DENY entry, which
// rung 2 cannot enforce for subprocesses (recorded unenforced in the report).
func policyHasGlobDeny(p effectivePolicy) bool {
	for _, e := range p.FS {
		if e.Access == denyFSAccess && strings.ContainsAny(e.Path, globMeta) {
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
func linuxWrapTransform(cfs compiledFS, cnet compiledNet, cg compiledCgroup, r1 *rung1Plan) func(string, []string) ([]string, func(*exec.Cmd), func()) {
	return func(dir string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
		return linuxWrap(cfs, cnet, cg, r1, dir, innerArgv)
	}
}

// linuxWrap is the per-spawn transform body. It re-execs /proc/self/exe and
// returns a fresh configure/cleanup pair that enumerates the FS rules at spawn,
// seals THIS spawn's spec (FS allowlist + net allowlist) into the stage-2 child
// over a private pipe, and — when the policy forces DNS over TCP — injects
// RES_OPTIONS=use-vc into the target env.
// When r1 is non-nil the spawn is RUNG 1 (Task 13): configure enumerates the
// bind-mount view at spawn (a fresh snapshot), sets the namespace cloneflags +
// uid/gid maps on the SysProcAttr, and tags the spec stage2RungOne so the child
// applies the mount view + nftables before Landlock. The cloneflags, the spec
// pipe, and the cgroup UseCgroupFD all coexist on the one SysProcAttr. r1 == nil
// is the rung-2 path (no namespaces), unchanged.
func linuxWrap(cfs compiledFS, cnet compiledNet, cg compiledCgroup, r1 *rung1Plan, dir string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
	// Re-exec THIS binary (/proc/self/exe, NOT os.Args[0]): the kernel resolves it
	// even for a deleted binary, and it is the exact image whose Init() dispatches
	// the stage-2 child.
	finalArgv := []string{"/proc/self/exe"}

	// pipeR/pipeW are this spawn's private spec pipe, captured so cleanup can close
	// both ends after the spawn completes.
	var pipeR, pipeW *os.File
	// tcg is this spawn's transient cgroup v2 scope (Task 14), captured so cleanup
	// can tear it down unconditionally. It is nil when limits are not applied (no
	// delegation / policy-disabled) or when scope creation failed best-effort.
	var tcg *transientCgroup

	configure := func(cmd *exec.Cmd) {
		// Capture the TARGET environment BEFORE adding the dispatch sentinel, so the
		// execve'd target never observes LRSANDBOX_STAGE2. The executor has already
		// set cmd.Env to the scrubbed child environment at this point.
		targetEnv := append([]string(nil), cmd.Env...)
		// Task 12c: when the policy forces DNS over TCP, ensure the target's glibc
		// resolver uses TCP (RES_OPTIONS=use-vc) — UDP is seccomp-blocked (12b), so
		// without this glibc's initial UDP query fails. Mutating targetEnv (a fresh
		// copy) is safe and never touches the parent's cmd.Env.
		if cnet.dns {
			targetEnv = ensureResOptionsUseVC(targetEnv)
		}
		// Enumerate the FS allowlist NOW (per spawn) so it is a fresh snapshot of
		// the live filesystem: a secret that exists when the command starts is
		// carved out; a file the command later creates is not (§7.5 snapshot
		// semantics). The stage-2 child rebuilds the Landlock ruleset from this.
		fsRules := enumerateFSRules(cfs)
		// Seccomp is unconditionally requested for this rung-2 backend: rung 2 is
		// only selected when the seccomp capability was probed present (selectRung
		// requires c.seccomp), so the stage-2 install cannot be a surprise failure.
		// It denies UDP/MPTCP sockets, ptrace, and io_uring in the target (Task 12b).
		spec := stage2Spec{
			Dir:         dir,
			Argv:        innerArgv,
			Env:         targetEnv,
			FSRules:     fsRules,
			Seccomp:     true,
			NetConfined: cnet.confined,
			NetTCPPorts: cnet.tcpPorts,
			Rung:        stage2RungTwo,
		}
		// Task 13: a rung-1 spawn additionally enumerates the bind-mount view (a
		// fresh snapshot, like the FS allowlist above) and carries the nftables plan.
		// It uses nftables for egress, so it leaves NetConfined false (no Landlock TCP
		// net) — the netns filter is the network boundary.
		if r1 != nil {
			spec.Rung = stage2RungOne
			spec.MountView = enumerateMountView(r1.mount)
			spec.NftRules = r1.nft.toNftSpec()
			spec.NetConfined = false
			spec.NetTCPPorts = nil
		}

		r, w, err := os.Pipe()
		if err != nil {
			// Fail closed: with no spec pipe the child's fd 3 is absent, its decode
			// fails, and runStage2 exits non-zero rather than running the target.
			// Still add the sentinel so the child dispatches into that fail-closed
			// path instead of running the re-exec'd program as itself.
			cmd.Env = append(cmd.Env, stage2SentinelEnv+"="+stage2SentinelValue)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			return
		}
		pipeR, pipeW = r, w

		// The read end becomes fd 3 in the child (ExtraFiles[0], since 0/1/2 are
		// stdio) — stage2SpecFD.
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		// Add the dispatch sentinel to the CHILD's env only (after capturing the
		// target env above), so the child's Init() runs runStage2.
		cmd.Env = append(cmd.Env, stage2SentinelEnv+"="+stage2SentinelValue)
		// Base SysProcAttr; the cgroup join (UseCgroupFD) below extends it. For a
		// rung-1 spawn, set the namespace cloneflags + uid/gid maps here (Task 13):
		// user+mount+pid namespaces always, plus a net namespace only when egress is
		// confined (an open policy must keep host networking). These coexist with the
		// spec pipe and the cgroup fd on the one struct.
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		if r1 != nil {
			configureRung1SysProcAttr(cmd.SysProcAttr, r1.nft.confined)
		}

		// Task 14: create this spawn's transient cgroup v2 scope and join the stage-2
		// child to it at clone time via CLONE_INTO_CGROUP (UseCgroupFD). The scope
		// carries the policy's resource limits (pids.max is the fork-bomb cap), so the
		// child — and everything it forks — is capped from its first fork. Resource
		// limits are containment-of-cost, not authority (§7.4): if the scope cannot be
		// created this spawn still runs, just UNCAPPED (fail-secure, best-effort — the
		// compile-time guarantee already reflected availability). createTransientCgroup
		// returns (nil, nil) when the plan applies no limits, so the join is simply
		// left unset. It EXTENDS the SysProcAttr above rather than replacing it.
		tc, cgErr := createTransientCgroup(cg)
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
			_ = encodeStage2Spec(w, spec)
			_ = w.Close() // signal EOF so the child's gob decode terminates
		}()
	}

	cleanup := func() {
		// Task 14: tear down this spawn's transient cgroup FIRST (kill any survivors
		// in the scope, then rmdir). Unconditional and safe — it only ever touches
		// the scope this spawn created, and is a no-op when none was created.
		if tcg != nil {
			tcg.teardown()
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
	}

	return finalArgv, configure, cleanup
}
