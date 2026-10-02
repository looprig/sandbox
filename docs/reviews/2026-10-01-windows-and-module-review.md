# Module review and Windows audit — 2026-10-01

Scope: `github.com/looprig/sandbox` at `fb57ecb` (v0.9.3), reviewed on a macOS host.
Linux findings were additionally exercised inside a privileged `golang:1.26`
Docker container (kernel 7.0.12-linuxkit, Landlock + seccomp live) where noted.
Windows code could only be read, vetted and compiled (`GOOS=windows` amd64 +
arm64, every package's test binary, plain and `-tags integration`); nothing ran
on Windows. **VERIFIED** means the failure was reproduced or the code path was
traced end to end with no ambiguity; **SUSPECTED** means it depends on
platform behaviour that must be confirmed on the real OS.

The review was split across four independent readers (Linux/policy, Windows
restricted tier + launch machinery, Windows elevated tier, cross-platform
core/macOS/tests) and then cross-checked against the source by the author of
this document. Items marked `[fixed]` were addressed on `feat/sandbox-windows`;
see §4 for what was and was not changed.

## 1. Findings, severity ranked

### Critical

**C1. Windows elevated tier claims `ReadBoundary` with a WRITE_RESTRICTED token.** VERIFIED.
`internal/windows/token_windows.go:14-19` defines `restrictedTokenFlags =
DISABLE_MAX_PRIVILEGE|LUA_TOKEN|WRITE_RESTRICTED` and `issueRestrictedToken`
(:127) always uses it; `createBrokerRestrictedToken`
(`broker_adapters_windows.go:890`) reuses it, so the elevated broker issues a
write-restricted token. Design §9.2 requires full restriction ("runs the
second SID-list access check for reads as well as writes"). With
WRITE_RESTRICTED the restricting-SID list is consulted only for write access
checks, so every deny-read ACE the broker projects is inert and the offline /
online sandbox reads anything `Users`/`Authenticated Users`/`Everyone` can
read (other drives, ProgramData, sibling workspaces, denied carveouts).
`elevatedGuaranteeBits` (`elevated_backend_windows.go:618-632`) still sets
`GuaranteeReadBoundary` unconditionally, and every validator
(`validateBrokerTokenHandle`, `VerifyToken`) checks only `IsRestricted()`,
which is true for both flavours. Scenario: profile `HostRead: Deny`, elevated
mode, `LevelFull` reported; `type C:\Users\Public\secret.txt` succeeds.
`[fixed]` — broker path uses its own full-restriction flag set and both the
issuer and the client-side token validators refuse a write-restricted token.

**C2. Linux: a confined target can reach same-user Unix-domain sockets (D-Bus
session bus, systemd user manager, ssh/gpg agents, docker.sock, abstract X11)
and run commands outside the sandbox.** VERIFIED in code; runtime SUSPECTED
(needs a host with a user D-Bus session, which is every desktop/dev box).
`internal/linux/seccomp.go:160-161` allows every non-AF_INET socket family;
Landlock ≤ ABI 8 does not mediate pathname `connect()`; Rung 2 has no mount or
network namespace (`backend.go:472-479`), and Rung 1 reaches `/run/user/$UID`
whenever host read is `Allow` (the `/` rbind). `systemd-run --user` or a raw
`StartTransientUnit` over `/run/user/$UID/bus` launches an arbitrary command
with none of Landlock, seccomp or the cgroup. SPEC §1 scopes out "an
unsandboxed process running as the same host UID", but the Windows design
treats exactly this (a same-user COM/WMI broker) as grounds to withhold
`ProcessBoundary`/`WriteBoundary`, so Linux is claiming what Windows refuses
to claim. `[fixed]` — the seccomp `socket()` rule is now an allowlist that
refuses AF_UNIX (socketpair remains available), see H1.

### High

**H1. Linux `NetworkBoundary` is a denylist and misses SCTP, SMC, VSOCK, RDS.**
VERIFIED. `seccomp.go:149-179` denies only inet `SOCK_DGRAM` and
`IPPROTO_MPTCP`; `socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)` (module autoloads
on most distros), `AF_SMC` / `IPPROTO_SMC` (falls back to plain TCP), `AF_VSOCK`
and `AF_RDS` are all allowed while Landlock's TCP port rules cover only TCP.
`keyctl`/`add_key`/`request_key` are also unfiltered (user keyring readable at
Rung 2, no userns). `[fixed]` — `socket()` is now an allowlist (AF_INET/6
SOCK_STREAM with protocol 0/TCP; AF_NETLINK route; UDP only when the policy's
network is `Open`), and the key syscalls are denied.

**H2. Linux: UDP is seccomp-denied even when network is `Allow`.** VERIFIED in
code (same filter installed for `Net.Open`, `backend.go:482`, `init.go:255`),
runtime VERIFIED in Docker during Phase 2 (`getent hosts` failed under a
`Network: Allow` Rung-2 spawn before the fix). glibc's resolver issues UDP
first, `RES_OPTIONS=use-vc` is injected only when the policy forces DNS over
TCP, so name resolution is broken for every network-`Allow` sandboxed spawn.
Not a widening, but a correctness bug that makes the Linux backend unusable
for ordinary builds. `[fixed]` — the filter is parameterised on `Net.Open`.

**H3. Linux Rung 2 supervised spawns silently drop every policy resource
limit while `GuaranteeResourceLimits` is reported.** VERIFIED.
`backend.go:540-548` sets `CgroupFD` to the limits scope in `configure`; then
`exec/process_tree_linux.go:95` (`scope.Join`) overwrites it with a lifetime
scope created by `NewLifetimeScope` (`cgroup.go:434-447`) that carries only
`DefaultMaxPIDs`. `MaxMemBytes`, `MaxCPUPct` and a custom `MaxPIDs` never
apply to a `PrepareProcess`/`Start` spawn. `[fixed]` — the lifetime scope is
created from the compiled limits (`NewLifetimeScopeWithLimits`).

**H4. macOS `Restrict` drops a nested `Deny` root and turns it into `Allow`.**
VERIFIED by trace (`pkg/profile/profile.go:370`). A root is kept only when its
access differs from the *host* access, but a root nested under the workspace
(or another root) falls back to the enclosing allow when dropped. Scenario:
workspace `/w` RW `Allow`, host `Deny`, additional root `/w/secret` `Deny`;
`Restrict(p, p)` returns a profile where `/w/secret` is `Allow`. `[fixed]` —
roots are kept unless they are redundant with what the restricted profile
already resolves at that path.

**H5. macOS: a case-variant path lets a grant open a `Deny` root.** VERIFIED
by trace plus a live Seatbelt check (Seatbelt matches case-insensitively on
APFS; `fsresolve.go:22-26` already warns about it). `IssueGrant` for
`/R/SECRET/key` does not match root `/R/secret` (byte-exact compare in
`canonical_unix.go:36`), falls back to the workspace's `Gated`, is minted, and
the emitted `(allow file-read* (literal "/R/SECRET/key"))` wins over the
shorter `(deny ... (subpath "/R/secret"))`. `[fixed]` — Darwin canonicalization
now re-spells each component with its on-disk case, so the configured root and
the grant target compare equal.

**H6. macOS: `EnvScrub` is hollow against a same-user reader — the Seatbelt
preamble has unfiltered `(allow process-info*)` and `(allow sysctl-read)`.**
VERIFIED (reviewer reproduced `KERN_PROCARGS2` recovery of a parent secret
under the module's preamble; I reproduced that the cross-process sysctl
succeeds). Every child can read the supervisor's environment, including
sibling executions' `HTTP_PROXY=http://<execID>:<credential>@127.0.0.1:<port>`.
`ExecutorSet.For` puts `ProxyPort` into the *base* policy of every executor
when a route is configured, so a stolen credential is replayable. Not fixed:
Seatbelt cannot filter this sysctl; the fix is architectural (credential via
fd, not env; scrubbed intermediate supervisor). Documented in SPEC §7.

**H7. macOS: unfiltered `(allow mach-lookup)` reaches LaunchServices.**
Reachability VERIFIED (`open zzz://` gets a real LS answer). `open https://…`
would launch the unsandboxed default browser and defeat `Network: Deny`. Not
fixed (needs a global-name allowlist and a compatibility pass); documented.

**H8. Windows restricted tier: the pipe-backed child shares the host console
(Windows TIOCSTI).** SUSPECTED. `process_tree_windows.go:74` uses only
`CREATE_SUSPENDED|CREATE_NEW_PROCESS_GROUP`; the child can `WriteConsoleInput`
into the agent's TUI or `GenerateConsoleCtrlEvent(0)` the host. `sendInterrupt`
depends on the shared console. Not fixed (needs a design decision between a
private console per spawn and losing cooperative interrupt); documented in
the compile report.

**H9. Windows restricted tier: `WRITE_RESTRICTED` does not restrict DELETE /
WRITE_DAC / WRITE_OWNER, so the ACL narrowing is bypassable by the owner.**
SUSPECTED (Windows access-check semantics; the adversarial matrix probes only
create/overwrite). The tier already reports `LevelNone` and only `EnvScrub`, so
no guarantee is violated today, but the design's premise for ever promoting
`WriteBoundary` is wrong and the report text names only broker escape.
`[fixed: report text]`.

**H10. Windows elevated: the persistent installation SID is projected onto
user objects**, which lets concurrent leases cross and makes leftover ACEs
live forever (SID re-derived on reinstall). VERIFIED (`broker_windows.go:220`,
`broker_adapters_windows.go:640-648`). Not fixed (design change: per-lease
SIDs only).

**H11. Windows elevated: lease rollback wedges the broker.** VERIFIED. Identical
installation-SID ACEs from concurrent leases collide
(`errACLIdenticalCollision`), a sandbox deleting/replacing one of its own files
fails rollback with `ErrRestrictedTargetChanged`, and `newWindowsBroker` treats
any reconcile failure as fatal (`broker_windows.go:128-130`), so the service
never starts again. `[fixed: partially]` — reconcile continues past a lease whose rollback
fails and quarantines it (journal record kept, SID never reused, new leases
and tokens refused while anything is quarantined, retried on `Status`),
surfaced as `WindowsSetupProblemLeaseRecoveryPending`; an object that no
longer exists anywhere (looked up by file ID, not path) counts as rolled
back, a moved object stays quarantined. The identical-ACE collision itself
(H10's shared installation SID) is not fixed, so two concurrent leases on
one object can briefly quarantine each other instead of wedging.

**H12. Windows elevated `NetworkBoundary`: the firewall's enabled state is
never checked** (`firewall_adapter_windows.go:38-41` reads only
`LocalPolicyModifyState`), rules are not rechecked at launch, there is no
inbound block, and (SUSPECTED) Windows Firewall does not filter loopback and
system services (SMB redirector, WebClient, Dnscache) connect on the sandbox's
behalf. `[fixed: enabled-state check per profile]`; the rest is documented.

**H13. macOS CI lifetime proof is vacuous.** VERIFIED: `requireSetsidHelper`
needs a `setsid` binary macOS lacks, so the only darwin selector in the
`test-macos` integration step always skips. `[fixed]` — darwin uses `perl
-MPOSIX -e setsid` and the selector is widened.

### Medium

**M1. Grant single-use bypass via base64 malleability.** VERIFIED.
`grant.go:49` uses non-strict `RawURLEncoding`; `grantID` hashes the token
*text*. Flipping unused trailing pad bits yields a distinct token string that
decodes to the same body and MAC and passes `usedGrants`. `[fixed]` — strict
decoding plus a re-encode comparison; replay is keyed on the MAC.

**M2. Windows child environment is unusable.** VERIFIED. The baseline
allowlist (`policy/effective.go:154`) is Unix-only and matched
case-sensitively, Windows spells `Path`, so the child usually gets no PATH, no
`SystemRoot`/`windir`, no `TEMP`/`TMP`, no `PATHEXT`, no `USERPROFILE`; the
executor sets only `HOME`/`TMPDIR`. The ConPTY launch path
(`terminal_windows.go:410`) builds its block from `cmd.Env` without Go's
`SYSTEMROOT` injection or case-insensitive dedup. `[fixed]`.

**M3. `TestIntegrationConPTYRestricted` cannot pass.** VERIFIED: it builds a
`Network: Deny` profile (`process_conpty_integration_windows_test.go:86`), which
requires `NetworkBoundary`, which the restricted tier refuses. The "ConPTY
restricted containment proof" CI step would be red the day the runners exist.
`[fixed]`.

**M4. Windows CI never executes Windows code.** VERIFIED. `windows-restricted`
and `windows-elevated` are gated on `vars.SANDBOX_WINDOWS_RUNNERS == 'true'`
and need self-hosted runners labelled `sandbox-standard`/`sandbox-elevated`/
`sandbox-disposable` (a standard-user token, a second fixed volume, and a
disposable elevated image); no such runners are registered, so both jobs are
SKIPPED on every run. Even when enabled, their `-run` patterns never reach
`TestCreateRestrictedToken*`, `TestJob*`, the handle-list tests, the broker /
firewall / setup unit tests or the non-disposable ACL tests. `[fixed]` — a
GitHub-hosted `windows-hosted` job runs the whole default-tag suite (`-race`)
on `windows-latest`; the self-hosted evidence jobs stay as they are (the
workflow guard requires them to remain self-hosted).

**M5. `LifetimeContainment` is `Enforced` for the Windows restricted tier,
with the doc saying "No descendant can escape it".** VERIFIED
(`lifetime_containment.go:20-22`, `process_tree_windows.go:557`). Design §8
says `Win32_Process.Create`/COM brokers escape the Job; macOS was downgraded to
`BestEffort` for the same class. `[fixed]` — Wrap-backed Windows spawns report
`BestEffort` when sandboxed (restricted tier, and auto when it falls back)
and `Unspecified` when unconfined (previously `Enforced` there too); the
elevated tier's backend-owned `Launch` path keeps `Enforced`; SPEC §7 and
`docs/lifetime-containment.md` updated.

**M6. Linux Rung-1 glob denies are reported "Enforced" but read-only binds are
never scanned and nothing below depth 8 is.** VERIFIED
(`namespace.go:207-215`, `GlobScanMaxDepth = 8`, `backend.go:259-264`).
`[fixed]` — read-only binds other than `/` are scanned too (walking the
whole host on every spawn is not affordable) and the entry is reported
`narrowed`, naming the depth bound and the `/`-only residual.

**M7. Linux Rung 1 can be selected with Landlock ABI 1-3 and then every spawn
fails** (`probe.go:85` vs `landlock.go:58`). VERIFIED. `[fixed]` — Rung 1
requires ABI ≥ 4 like Rung 2.

**M8. Linux CI rung-1 job can pass with zero rung-1 coverage**: the sysctl /
modprobe steps are `|| true` and every rung-1 test self-skips; Rung-2 cgroup
delegation paths run in no job; `acceptance_linux_test.go:205` is an
unconditional skip. VERIFIED. `[fixed: partially]` — `LRSANDBOX_REQUIRE_RUNG1=1`
turns the rung-1 capability skip into a failure and the rung-1 job sets it.

**M9. Windows Auto mode does not forward `SupportsGrantClass`**, so
`network.broad.v1` and host-wide grants are consumed before the elevated
compile rejects them; elevated `Compile` ignores `Net.Ports/Loopback/Private/
DNS` and still claims `NetworkBoundary`. VERIFIED. `[fixed]`.

**M10. macOS `RunCommand` can hang `ExecutorSet.Close`** when a setsid'd
descendant keeps stdout open (no tracker on non-supervised spawns,
`drainWG.Wait()` unbounded). VERIFIED by trace. Not fixed; booked.

**M11. Real Seatbelt is never tested against proxy routing / `TargetNetwork`
/ `HostRead: Deny`** (only `captureBackend` and a golden string). Not fixed;
booked.

**M12. Linux: TIOCSTI into the harness terminal** (stage 2 never `setsid`s for
non-TTY spawns; Landlock `IOCTL_DEV` not handled). SUSPECTED; blocked where
`dev.tty.legacy_tiocsti=0`. Not fixed; booked.

**M13. Linux Rung 2 lifetime containment is escapable when host write is
`Allow`** (the target can write its pid into the delegated ancestor's
`cgroup.procs`). SUSPECTED. Not fixed; booked (needs `CLONE_NEWCGROUP`).

**M14. Windows elevated: no journal compaction (64 MiB cap wedges leases)**,
`reconcile` request from any client rolls back other clients' live leases,
removal does not reconcile leases and deletes the journal, no residue report.
VERIFIED. Not fixed; booked.

**M15. Windows elevated tier has, in all likelihood, never run**: the §9.3
runtime spike is "Pending and unverified", and several independent reasons
suggest the live suite cannot pass as written (restricted service SID vs
SY/BA-only state DACLs, `CreateProcessAsUser` from an unprivileged host needing
`SeAssignPrimaryTokenPrivilege`, pipe anchor DACL, no account-normal ACE,
session-0 token/desktop vs session-1 Job, firewall read-back canonicalisation).
All fail closed. SUSPECTED. Not fixable without a Windows host.

**M16. Windows restricted tier: projection retains a no-delete-sharing handle
on every workspace object** for the executor's lifetime (`acl_tree_windows.go:
299`, `acl_windows.go:307-350`), so compile fails if any file is open for
write and neither user nor sandbox can delete/rename pre-existing files. The
exclusion is load-bearing against rename-around-a-deny. VERIFIED (code),
impact SUSPECTED. Documented.

**M17. `TestCgroupLifetimeRetainsOnUnprovedEmpty` is flaky, and `KillAndWait`
could return an empty proof for an exhausted context.** VERIFIED in Docker
at the v0.9.3 baseline (1 failure in 3 runs once cgroup delegation exists,
which CI never has): `cgroup.kill` reaped the member before the loop's first
`cgroup.procs` read, so an already-expired context still produced a proof.
`[fixed]` — the context is checked before every read; 20/20 green.

### Low

- L1. Non-TTY Linux spawn keeps the controlling terminal (see M12).
- L2. Windows Job zero-proof depends solely on completion-port messages, which
  Microsoft documents as not guaranteed; a lost `ACTIVE_PROCESS_ZERO` blocks
  `ExecutorSet.Close` forever (fails closed). Booked.
- L3. `setDACL` uses `SetSecurityInfo` (auto-propagation outside the
  handle-bound discipline). Booked.
- L4. Plain-HTTP proxy does not reconcile `Host` with the request-URI authority
  (vhost confusion toward an approved IP on the direct route). Booked.
- L5. `(remote tcp "localhost:PORT")` matches every local address. Documented.
- L6. Grant expiry uses the wall clock. Booked.
- L7. Seatbelt tests skip when the `sandbox-exec` probe fails; `[fixed]` —
  `SANDBOX_REQUIRE_SEATBELT=1` makes that fatal and CI sets it.
- L8. Elevated token duplicated with `DUPLICATE_SAME_ACCESS`; pipe auth accepts
  restricted-tier tokens; desktop DACL grants the account rather than the
  lease SID; `broker.mu` held across whole acquires; compile report has no
  `windows.firewall` entry and hard-codes several `*Ready` flags; proxy ports
  not compared for staleness. Booked.
- L9. `SnapshotAxes` report text overclaims after `1760f0b`. `[fixed]`.
- L10. Mount targets resolved by path before pivot (`namespace.go:313-331`);
  Landlock barrier mitigates. Booked.

### Info

- Darwin lifetime containment is honestly `BestEffort`.
- Grant HMAC construction, proxy authentication/normalisation, hop-by-hop
  stripping, upstream credential confinement, SBPL string escaping, Linux
  pinned-bind TOCTOU closure (`2f89ebd`), pivot sequence, seccomp arch guard,
  nftables default-drop, env scrub never-nil, Windows suspended→Job→resume
  ordering on both launch paths, explicit handle lists, winpath
  canonicalisation and the ACL journal write-ahead discipline were all traced
  and found sound. The v0.9.3 policy fixes (`1760f0b`, `0f8d5d8`, `6ed2760`,
  `7965151`) introduce no widening.

## 2. Windows audit against SPEC.md and the design

SPEC.md mentions Windows only in passing (§4 `cmd.exe /D /S /C`, §7
`windows.runtime-baseline`, §7 "a Windows Job" for lifetime containment) and
otherwise says "On other operating systems `Sandboxed` is unavailable". The
actual Windows contract lives in `docs/plans/2026-07-21-windows-sandbox-design.md`.
A Windows section is added to SPEC §7 on this branch.

| Capability | Promised | Implemented | Status |
|---|---|---|---|
| Restricted token (DISABLE_MAX_PRIVILEGE, LUA, WRITE_RESTRICTED, restricting SIDs, dangerous groups deny-only) | design §9.1 | yes, with read-back | enforced |
| Restricted tier claims only `EnvScrub`, `LevelNone` | design §5 | yes | honest; report text now names console / DACL / memory-read channels |
| Job: suspended create → kill-on-close + UI limits + breakaway off → assign → resume; terminate on failure | design §8 | yes, pipe and ConPTY paths | enforced |
| Job zero-proof before release | design §8 | completion port | enforced (liveness caveat L2) |
| `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` on every launch | design §8 | pipe path yes; ConPTY inherits nothing | enforced |
| Lifetime containment reported honestly | SPEC §7 | was `Enforced` for both tiers | **fixed**: restricted → `BestEffort` |
| Write narrowing via restricting-SID ACL projection | design §10.3 | yes, journalled | withheld as a guarantee (correct); DELETE/WRITE_DAC gap documented |
| Scrubbed env usable on Windows (PATH, SystemRoot, TEMP) | SPEC §3 | no | **fixed** |
| Canonical System32 `cmd.exe`, never `%ComSpec%` | SPEC §4 | identity-pinned resolver | enforced |
| Path canonicalisation (`\\?\`, UNC, device, ADS, 8.3, case) | design §10.1 | yes | enforced |
| ConPTY (TTY) under the restricted token | design / Task 22 | yes | implemented; integration proof could not pass (**fixed**) |
| Auto refuses rather than downgrades | design §5 | yes | enforced; `SupportsGrantClass` forwarding **fixed** |
| Elevated: full-restriction token (reads checked) | design §9.2 | **no** (WRITE_RESTRICTED) | **fixed** in code; needs live proof |
| Elevated `ReadBoundary` | design §5 | claimed unconditionally | now gated on a non-write-restricted token |
| Elevated per-lease SIDs only on user objects | design §9.2/§10.3 | installation SID also projected | not fixed (H10) |
| Elevated firewall: account-scoped outbound blocks, read-back, GPO check | design §11.1 | rules modelled; enabled state not checked | enabled check **fixed**; loopback / service bypass undetermined |
| Elevated inbound block | not promised | no | gap |
| `network.broad.v1` → `ErrGrantUnsupported` | design §11.2 | elevated yes; auto no | **fixed** |
| Broker: pipe DACL, client PID/token from Windows, impersonation for ACL work, no arbitrary launch | design §7.3 | yes | enforced in code |
| Passwords only in LocalSystem DPAPI | design §7.3 | yes | enforced |
| Lease cleanup never blocks broker start; unhealthy-and-retry | design §13 | constructor hard-failed | **fixed** (quarantine + problem code) |
| Removal reconciles leases, reports residue | design §12 | no | not fixed |
| `windows.runtime-baseline` report entry | SPEC §7 | yes, gated on approved evidence | honest; evidence never collected |
| LPAC/AppContainer unelevated tier, per-execution WFP, `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` | explicitly deferred | no | documented v2 |

What cannot be enforced on Windows without a design change, and is now stated
in SPEC §7 and the compile reports: console sharing in the restricted tier,
same-user memory reads defeating `EnvScrub`, DELETE/WRITE_DAC under
WRITE_RESTRICTED, COM/WMI brokers escaping the Job, loopback/system-service
egress on the elevated tier.

## 3. CI: why `windows-restricted` / `windows-elevated` are skipped

Both jobs carry `if: vars.SANDBOX_WINDOWS_RUNNERS == 'true'` and target
`[self-hosted, Windows, X64, sandbox-standard|sandbox-elevated, sandbox-disposable]`.
The repository variable is unset and no self-hosted runners are registered;
the gate exists so the required check fails fast instead of queueing for 24h.
That is a deployment gap, not a workflow bug, and the jobs genuinely need what
GitHub-hosted runners cannot give (a standard-user token for the restricted
gate, a reimaged elevated box for the elevated gate). What *was* fixable: a
hosted `windows-latest` job that runs the entire default-tag suite under
`-race`, which exercises the live token, Job, handle-list, ConPTY and ACL unit
tests for the first time.

## 4. Fixed on this branch

Verification of the fixes: the darwin suite, `make lint` (gofmt, vet,
staticcheck, gosec) and the Darwin integration selector (3× under `-race`);
Windows amd64 and arm64 build + vet and every package's test binary (plain
and `-tags integration`); Linux amd64/arm64 vet, every test binary, and the
full suite plus the rung-1/rung-2 integration selectors executed in a
privileged Docker container with cgroup delegation and
`LRSANDBOX_REQUIRE_RUNG1=1`. Nothing ran on Windows. In short: elevated token flags
and validators (C1); seccomp socket allowlist, key syscalls, UDP under
`Net.Open` (C2/H1/H2); supervised Rung-2 limits (H3); `Restrict` nested roots
(H4); darwin on-disk-case canonicalisation (H5); perl-based setsid helper and
wider macOS selector (H13); strict grant decoding and MAC-keyed replay (M1);
Windows env baseline, case-insensitive matching, TEMP/TMP/USERPROFILE, ConPTY
env block (M2); ConPTY restricted test profile (M3); hosted Windows CI job
(M4); restricted-tier `BestEffort` (M5); Rung-1 glob scan roots and report
(M6); Rung-1 ABI ≥ 4 (M7); `LRSANDBOX_REQUIRE_RUNG1` (M8); auto
`SupportsGrantClass` and elevated net-grant refusal (M9); broker lease
quarantine (H11); firewall enabled-state check (H12); `SANDBOX_REQUIRE_SEATBELT`
(L7); cgroup proof ordering (M17); report wording (H9, L9); SPEC §7 Windows
section and limits.

## 5. Second round (2026-10-02, owner decisions)

The owner asked for an explicit AF_UNIX escape hatch and for every remaining
item fixable without a real Windows host or a kernel feature. Status per item:

**Escape hatch (shipped).** `ProfileConfig.UnixSockets UnixSocketPolicy{Mode,
Paths}`; `UnixSocketsDenied` (zero, unchanged default) / `UnixSocketsLocal`;
`Paths` are exact host sockets; `DangerousUnixSocket(path)` names D-Bus,
systemd, container-daemon and display sockets. `Restrict` intersects; the
fingerprint changes only for a non-default policy. Enforcement: Linux Rung 1
Local/Paths `Enforced` via the mount view + netns/Landlock abstract scoping,
narrowed (ProcessBoundary withheld, Degraded) when `/`, `/run`, `/var/run` or
`/tmp/.X11-unix` is in the view; Rung 2 flagged-not-refused (every same-user
pathname socket reachable, named in the report, Degraded); macOS Seatbelt
path-exact (`subpath` for Local roots, `path-literal` per path), and a
sandboxed `Network: Allow` profile no longer admits host sockets through
`(allow network*)`; Windows refuses a non-default policy (unmediated). All
proven live in Docker (Rung 1 and 2) and under sandbox-exec.

| Item | Status | Detail |
|---|---|---|
| H6 process-info env read (macOS) | **not fixable in SBPL** | eight variants measured (no process-info/sysctl at all, `(target self)`, pidinfo/listpids only, `deny sysctl-name kern.procargs2` before and after, regex, name-prefix allowlist): the secret leaked under every one; Seatbelt does not mediate `KERN_PROCARGS2`. Reported `env-scrub` narrowed, kept under test (`TestSeatbeltProcargsCrossProcessReadIsReported`), proxy credentials already reach only Allow-network and grant spawns. |
| H7 mach-lookup | **fixed** | measured allowlist (`opendirectoryd.libinfo`, `.membership`; `trustd.agent` only with egress); `open zzz://` and `open -a` now fail live. Compatibility costs documented in code and SPEC. |
| H8 shared console (Windows restricted) | **fixed (partial)** | `DETACHED_PROCESS` for sandboxed pipe-backed spawns, with explicit stdio pipes; interrupt returns `ErrProcessSignalUnsupported`. Hosted launch diagnostics showed `CREATE_NO_WINDOW` fails during restricted console initialization, so pipe spawns now avoid the implicit conhost. Console-dependent programs need TTY. |
| H10 installation SID on user objects | **fixed** | only the per-lease one-shot SID is projected; older ACEs still rolled back at recovery. |
| M10 darwin RunCommand hang | **fixed** | synchronous Seatbelt spawns arm the descendant tracker; drain bounded by `outputDrainGrace` with `ErrOutputDrainIncomplete`. |
| M11 live Seatbelt proxy/TargetNetwork/HostRead Deny | **fixed** | real-backend tests + `CheckClaimedImplications` on darwin. |
| M12 TIOCSTI / controlling terminal | **fixed** | setsid for every non-TTY spawn, TIOCSTI/TIOCLINUX denied, Landlock `IOCTL_DEV` handled (ABI 5). Cost: a target opening `/dev/tty` itself gets `EACCES`. |
| M13 Rung-2 lifetime escape via cgroup.procs | **fixed** | `/sys/fs/cgroup` write carveout on both rungs (escape reproduced in Docker with it disabled). `CLONE_NEWCGROUP` not used: needs CAP_SYS_ADMIN in a userns Rung 2 hosts lack (verified `unshare --cgroup` EPERM). |
| M14 journal compaction / reconcile scope / removal | **fixed** | compaction at start, past 32 MiB and on a full journal; reconcile touches only dead bindings, quarantined and previous-instance orphans; removal stops the service first, reconciles, reports `SetupResidueError`. |
| M16 no-delete-share handles | **fixed (restricted tier)** | only roots, deny targets and ancestors stay locked; others closed after read-back and reopened by file ID at rollback. The elevated client still retains read-only-share handles (same fix owed there; needs Windows to validate). |
| L1 controlling terminal | fixed with M12 | |
| L2 `localhost` proxy rule | **partial** | SBPL rejects IP literals; rule is `tcp4` (refuses ::1), reported `proxy-listener` narrowed. |
| L3 pid reuse in darwin tracker | **fixed** | anchor valid only while (pid, start time) matches. |
| L4 Host header vs URI | **fixed** | measured not exploitable (net/http normalises); outbound Host set explicitly, disagreeing Host refused 403. |
| L5 `localhost` matches all local addresses | documented (same as L2) | |
| L6 wall-clock grant expiry | **fixed** | monotonic per-grant deadline. |
| L8 a–f | **fixed** | token dup access mask; pipe auth refuses restricted tokens + Medium integrity; desktop DACL lease SID; `broker.mu` not held across projection; `windows.firewall` entry + derived Ready flags + ResourceLimits only when requested; proxy-port staleness (`WindowsSetupProblemProxyPortsStale`) and own-listener recognition. |
| L10 mount targets by path before pivot | **fixed** | targets resolved by descriptor with `RESOLVE_IN_ROOT\|RESOLVE_NO_SYMLINKS`; planted `ws/.looprig -> /etc` fails closed with ELOOP (the previous code escaped). |
| Lost intermittent Docker failure | **found and fixed** | 20/20 plain runs green; reproduced under CPU load (2/15): `TestIntegrationProcessTreeParentDeath`'s positive control scanned argv once, before the forked subshell exec'd `setsid`. The control now polls; 0/30 under load after. |

**Still booked (needs a real Windows host or a kernel feature):** M15 (the
elevated tier has never run live); the elevated client's retained handles
(M16, elevated half); H12 (b)–(e) (no
launch-time firewall recheck, no inbound block, loopback / system-service
egress); Landlock ABI 9 `RESOLVE_UNIX` for Rung-2 pathname-socket scoping
(kernel newer than the Docker image); H6 credential-by-fd transport (needs a
design decision, since proxy-aware clients read the credential from the
environment); the stricter runtime closure under `HostRead: Deny` on macOS
(`/usr/bin/curl` needs `/private/etc/ssl/openssl.cnf`, `git` needs
`/Library/Developer`).


## 5. Hosted Windows follow-up — 2026-10-02

The initial audit above predates Windows execution. The hosted job now runs
real Windows tests. Run `37017311503` (head `929ac51`) exposed Job read-back,
console initialization, ConPTY EOF/interrupt and lease-test failures. Run
`37042438148` (head `ba95cbd`) confirmed the Job, ConPTY and lease fixes, but
still failed console initialization and exposed a race in the new stack-sweep
test and three test helpers using `exec.Command` where the process-tree code
installs a `CommandContext` cancellation callback.

The launch matrix in the second run separates the console failure from Job
policy: unrestricted children succeed with `CREATE_NO_WINDOW`, restricted
children fail `0xC0000142` with or without the logon SID and with or without a
Job, and both restricted token shapes succeed with `DETACHED_PROCESS`.
Pipe-backed spawns therefore detach and retain explicit stdio pipes. This
avoids implicit console initialization and host-console inheritance; it is
not a claim that hostile same-user code cannot explicitly attach elsewhere.
Console-dependent applications must request TTY. The regression test requires
an actual detached child to observe `ERROR_INVALID_HANDLE` from
`GetConsoleProcessList`; unexpected errors fail. The API distinction is
specified in [Microsoft's console creation documentation](https://learn.microsoft.com/en-us/windows/console/creation-of-a-console).

The stack-sweep race was reproduced on macOS by copying the recursive helper
and notification order into a standalone `-race` test. Completion now follows
all recursive unwinding, which still touches the shared test sink. The three
Job launch tests now use `CommandContext(context.Background(), ...)`, matching
the production callers. No failing test was converted to a skip.

The self-hosted standard-user and elevated disposable gates remain unproven.
Hosted ConPTY tests use a fake policy backend with a real Job and pseudo
console; they do not prove restricted-token ConPTY or elevated broker
composition. Cooked-console EOF tests cover `findstr` and `sort`, not arbitrary
raw-mode terminal applications. Windows arm64 is compilation-only.

Run `37043430733` (head `297c781`) passed the root facade, `internal/exec`
and `internal/windows` race suites. Its sole failure was the policy example's
post-close assertion that the caller's scratch directory must be empty.
Windows intentionally retains `restricted-journal-v1` outside executor-owned
temporary trees for crash recovery and permanent SID retirement. The example
now requires exactly that journal directory, zero pending recovery records,
and a nonempty SID retirement ledger; it still fails on leaked executor
directories. This is a platform-specific test expectation, not a cleanup bug
or an unavailable runner capability. The dedicated ConPTY step was not reached
in either failed run because the preceding whole-suite step failed.
