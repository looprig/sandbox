# Sandbox Module Implementation Plan (v2)

> Historical implementation record. `SPEC.md` is the canonical current
> contract; its ExecutorSet-owned HOME/TMPDIR and grant APIs supersede the older
> `/tmp` and direct-constructor decisions below. Linux mechanism tests still
> require Linux CI as noted in Phase 0.5.

> **For Claude:** Execute with **superpowers:subagent-driven-development**
> (fresh implementer subagent per task → spec-compliance review → code-quality
> review). TDD each task. All paths below are **module-root relative** — the
> module root *is* `/Users/ipotter/code/looprig/sandbox/` (no nested module).

**Goal:** Build `github.com/looprig/sandbox` — an optional, near-stdlib module
that confines agent-spawned commands via OS-level enforcement (Seatbelt on
macOS; namespaces + Landlock + seccomp + nftables on Linux), with security
modes, a two-axis policy model, unforgeable grant-token escalation, and
structural harness seams — per `SPEC.md`.

**Architecture:** Leaf module, no looprig imports; harness couples to it
structurally (stdlib-only interface signatures). Enforcement is a stateless
per-spawn transform selected per platform. On Linux **every** spawn (both rungs)
goes through a stage-2 re-exec (`Init()`), because Go's `exec.Cmd` has no safe
post-fork/pre-exec hook and applying Landlock/seccomp in the parent would
confine the harness. Policy is compiled per backend under a soundness invariant
(compiled enforcement never wider than policy; every narrowing recorded in a
`CompileReport` and reflected in `Level()` and the fine-grained `Guarantees()`).
Build order: prove the hard OS mechanisms in tiny spikes → pure-Go policy/crypto
core (testable anywhere) → per-platform backends → harness seams → consumer
wiring → acceptance matrix.

**Tech Stack:** Go **1.26.4** (matches `harness`/`swe`), `golang.org/x/sys/unix`,
`github.com/landlock-lsm/go-landlock` (Landlock FS/net rules),
`github.com/google/nftables` (rung-1 address filtering over netlink), pure-Go
seccomp-BPF (hand-built filter, no cgo), macOS `/usr/bin/sandbox-exec` (SBPL),
cgroup v2. Test with `go test`; platform backends gated by build tags + runtime
capability probes.

**Dependency policy (Phase-0 decision):** `stdlib + x/sys + a tiny allowlist of
vetted pure-Go OS-primitive libs` (`go-landlock`, `google/nftables`). No cgo, no
external binaries, no looprig imports. (SPEC §2.)

**Spec reference:** `SPEC.md` (§ numbers cited per task). **Prior art:**
`../../codeagents/codex/codex-rs` (`sandboxing`, `linux-sandbox`, `bwrap`
crates) — read, don't copy.

---

## Changes from v1 (why this iteration exists)

1. **SPEC.md is canonical** (was drifting to a design doc under `docs/plans/`).
2. **`go 1.26.4`** (was `1.23` — would have lagged harness/swe).
3. **Deps relaxed** to allow `go-landlock` + `google/nftables` (design §2 said
   "x/sys only" while the plan pulled go-landlock — contradiction resolved).
4. **Full rung-1 address network in v1** via `google/nftables` (was ambiguous
   "pure-Go nftables").
5. **Stage-2 re-exec is the common Linux spawn path for BOTH rungs** — rung 2
   also needs it (can't hook pre-exec safely; parent-applied confinement would
   trap the harness). Task 11 now blocks Tasks 12 **and** 13.
6. **`Guarantees()` + `GuaranteeBits() uint64`** added — the load-bearing gate
   signal is now per-property, not the coarse `Level()`. `GuaranteeBits` is the
   stdlib seam form so harness needs no import. (SPEC §6, §10.3.)
7. **New Phase 0.5 — mechanism proofs** (small spikes) before backend impl.
8. **Oversized tasks split**: 12 → 12a/b/c, 13 → 13a/b/c/d, 17 → 17a/b/c/d.
9. **`BashRequest` path fixed**: `harness/pkg/tool/permission_request.go` (was
   wrongly `pkg/session`).
10. **Writable tmp = `/tmp` only** + forced `TMPDIR=/tmp` (was `/var/folders`
    carveouts).

---

## Phase 0 — Policy knobs — ✅ DONE

Recorded in `SPEC.md §13`: (1) `/tmp`-only writable tmp + forced `TMPDIR=/tmp`;
(2) `HardApproveRules` prefix classifier; (3) `WithSecurityMode` + per-role
static modes; (4) 15-min grant TTL, capability-granularity `GrantDeltas`. Plus
architecture decisions: relaxed deps (§2), full rung-1 net (§7.2). No commit
(pre-repo).

---

## Phase 0.5 — Mechanism proofs (spikes before backends)

Small, throwaway-quality spikes that prove each hard OS mechanism works *the way
the backend will use it* before we build the backend. Each writes findings to
`docs/spikes/<name>.md` and, where a mechanism is weaker than assumed, feeds a
soundness narrowing back into SPEC. **Only M1 runs on this macOS host; M2–M5 are
authored here as `//go:build linux` capability-gated tests and must pass in
Linux CI before their dependent backend task is marked done.**

### Task M1 — Seatbelt network expressiveness (darwin, runs now) — resolves SPEC §13 Q6

**Files:** `docs/spikes/seatbelt-net.md`, a scratch `_test.go` under a `spikes/`
dir (not shipped).

Write a temporary SBPL profile allowing outbound `:443` + loopback and denying a
CIDR (`169.254.0.0/16`) + the metadata IP; `sandbox-exec` a probe that connects
to a loopback listener, to `169.254.169.254`, and to `example.com:443`. Record
which of {port scope, loopback, RFC1918 CIDR, metadata deny} SBPL actually
expresses. **Outcome:** update SPEC §7.1/§5.4 — either macOS `trusted` gets real
`Private`/metadata rules, or they compile to `blocked` (soundness). No commit
until Task 1 exists; capture findings in the doc now.

### Task M2 — go-landlock through stage-2 re-exec (linux/CI)

Prove a re-exec'd child that calls `landlock.V4.RestrictSelf()` on a read-only
rule for a dir gets `EACCES` on write there, while the parent process is
unaffected (confinement is child-local). Confirms the Task 11+12 architecture.

### Task M3 — seccomp-BPF install through re-exec (linux/CI)

Prove a hand-built seccomp filter installed in the re-exec'd child (after
`no_new_privs`) denies a marker syscall (e.g. `socket(AF_INET, SOCK_DGRAM)` →
`EACCES`/`SIGSYS`) in the child only. Confirms the filter-build approach for
Task 12.

### Task M4 — google/nftables in a netns (linux/CI)

Prove: create a network namespace, apply an nftables ruleset via `google/nftables`
dropping egress except `:443`+loopback, and verify a probe can reach a loopback
listener + `:443` but not the metadata IP. Confirms rung-1 net (Task 13c).

### Task M5 — cgroup v2 delegation (linux/CI)

Prove: create a transient cgroup v2 scope, set `pids.max`, join a child, and
confirm a fork bomb is capped; detect + report cleanly when delegation is
unavailable. Confirms Task 14.

**Done when:** M1 documented with a SPEC update; M2–M5 committed as gated tests
(green in Linux CI, `t.Skip` with recorded reason elsewhere). M2–M5 land with
their backend tasks if no Linux host is available during Phase 1.

---

## Phase 1 — Module scaffold + pure-Go core

Platform-independent, unit-testable anywhere. Backends stubbed to `LevelNone`
passthrough so the whole surface compiles and runs before any OS enforcement.

### Task 1: Initialize the module

**Files:** Create `go.mod`, `README.md`, `.gitignore`, `doc.go`.

**Steps:**
1. `cd /Users/ipotter/code/looprig/sandbox && git init` (repo #11).
2. `go mod init github.com/looprig/sandbox`; set `go 1.26.4`; `go get
   golang.org/x/sys` (already in module cache — offline-safe). Do **not** add
   go-landlock/nftables yet — they arrive with the Linux phase.
3. `doc.go`: one-paragraph purpose from SPEC §1 + the `Init()`-must-be-called
   note.
4. `README.md`: positioning + a stub "honest per-rung capability table" (filled
   in Task 26).
5. `go build ./...` succeeds (empty).
6. Commit `chore: initialize sandbox module`.

### Task 2: Policy + guarantee types (SPEC §4, §5, §6)

**Files:** Create `policy.go`, `policy_test.go`.

**Step 1 — failing test:** zero values fail-closed — `Mode(0) == ZeroTrust`,
`FSAccess(0) == DenyAccess`, `EnvPolicy{}.Inherit == false`, `NetPolicy{}` denies
all, `Guarantees{}` all-false, `Level(0) == LevelNone`.

**Step 2:** FAIL (undefined). **Step 3 — implement:** `Mode` + const ladder;
`FSAccess` bitmask (`Read|Exec|Write`); `FSEntry`; `NetPolicy` (incl. `DNS`);
`EnvPolicy`; `Limits`; `Policy` (incl. `AckUnconfined`); `ExternalDecl` (incl.
`Env EnvPolicy`); `CompileReport` + `ReportEntry{Feature, Status, Detail}`;
`Level` consts; **`Guarantees` struct + `Guarantee*` bit constants** (SPEC §6).
**Step 4:** PASS. **Step 5:** commit `feat: policy and guarantee types`.

### Task 3: `PolicyFor` + presets (SPEC §4 table, §5.3, §5.4, §5.5)

**Files:** Create `presets.go`, `presets_test.go`; add `PolicyFor` +
`PolicyOption`s to `policy.go`.

**Step 1 — failing tests (table-driven, one row per mode):**
- `zerotrust` → restricted-read (workspace + minimal system paths), no writes,
  net hard-deny, baseline env.
- `write` → broad `Read|Exec`, `Read|Write|Exec` on workspace + `/tmp`,
  `.git`/`.looprig` carved read-only, net gated (zero), baseline env,
  `TMPDIR=/tmp` in `EnvPolicy.Set`.
- `trusted` → as write + `Net{Ports:{443}, DNS:true, Loopback:true, Private:true}`.
- `unconfined` without `AckUnconfined` → policy flagged (validated in Task 7).
- `DefaultSecretDenials` in every non-unconfined mode; `**/.env*` denied
  **including inside workspace**; metadata IPs denied whenever any net allowed.
- `EnvPolicy` baseline allowlist contents; `TMPDIR` = `/tmp`.

**Step 2:** FAIL. **Step 3:** implement `PolicyFor` + options (`WithWritable`,
`WithDenyRead`, `WithNet`, `WithEnv`, `WithLimits`, `WithCarveouts`,
`WithoutSecretDenials`, `WithAckUnconfined`). **Step 4:** PASS. **Step 5:**
commit `feat: PolicyFor and secure-default presets`.

### Task 4: FS precedence resolver (SPEC §5.1)

**Files:** Create `fsresolve.go`, `fsresolve_test.go`.

**Step 1 — failing test:** resolving a path over a set of `FSEntry` yields
**deny > write > read**, longest-path match wins within a class; a carveout
inside a writable root resolves read-only; a denied fixed path under a readable
root resolves deny. **Step 2:** FAIL. **Step 3:** implement (used by backends +
the ReadGuard adapter, Phase 4). **Step 4:** PASS. **Step 5:** commit
`feat: filesystem precedence resolver`.

### Task 5: Grant tokens — HMAC mint/verify (SPEC §9.2)

**Files:** Create `grant.go`, `grant_test.go`.

**Step 1 — failing tests (injected clock — no `time.Now()` in tests):**
- `mintGrant`/`verifyGrant` round-trip → returns bound description + delta.
- Tamper any of the three segments → verify fails.
- Wrong key (different executor) → fails.
- Expired (ttl elapsed via injected clock) → fails.
- Bumped policy generation → prior token fails.
- Description is MAC-covered: altering it invalidates the MAC.

**Step 2:** FAIL. **Step 3:** implement with `crypto/hmac`+`crypto/sha256`, a
per-executor `crypto/rand` key, an injectable `clock func() time.Time`, payload
struct (policy-gen, cmd-hash, delta, description, expiry) serialized
deterministically (sorted). Format `lrsx1.<b64url(payload)>.<b64url(mac)>`.
**Step 4:** PASS. **Step 5:** commit `feat: unforgeable grant tokens`.

### Task 6: Executor + null backend + External + env scrub + guarantees (SPEC §6, §11)

**Files:** Create `executor.go`, `executor_test.go`, `backend.go` (internal
`backend` interface: `compile(Policy) (spawnSpec, CompileReport, Level,
guaranteeBits uint64, error)`), `backend_null.go` (fallback build tag /
`LevelNone`).

**Step 1 — failing tests:**
- `NewExecutor(PolicyFor(Write, ws))` on null backend → `Level()==LevelNone`;
  `Guarantees()` reports **only** `EnvScrub==true` (scrub applies even with no OS
  backend), all else false; `GuaranteeBits()` matches.
- `RunCommand(ctx, dir, "echo hi")` runs directly; `RunArgv` runs argv with no
  shell.
- Env scrub on null backend: child sees baseline env only, `GITHUB_TOKEN`
  absent, `TMPDIR==/tmp` (probe with `env`).
- `NewExternalExecutor(ExternalDecl{Boundary:"docker"})` → `Level()==LevelExternal`,
  passthrough exec, `ExternalDecl.Env` scrub applies, `Guarantees()` = full
  (trust-by-declaration).
- `PlanGrants`/`DescribeGrant`/`RunCommandWithGrants` wired to Task 5.
- `NewExecutorDynamic(src, ws)` recompiles per `src.Current()`; a mode change
  bumps policy generation (a pre-change token now fails).
- `ReadOnlyView()` shares source/probes; strips writes + net + granting.
- **Fail-closed on unresolvable home (Task-3 review decision, §5.3 guard):** for a
  **non-unconfined** policy, if `os.UserHomeDir()` errors — so `DefaultSecretDenials`
  could not materialize the `~/.*` secret denials (`~/.ssh`, `~/.aws`, keychains,
  browser profiles) — `NewExecutor` **returns an error** instead of building a
  broad-read executor with the secret-read hole open. Test: force home-unresolvable
  (`t.Setenv("HOME","")`) → `NewExecutor(PolicyFor(Write, ws))` errors; `unconfined`
  is exempt (no secret denials expected).

**Step 2:** FAIL. **Step 3:** implement. `Init()` is a no-op stub here (real body
Task 11). Env assembly from `EnvPolicy` lives here (shared by all backends).
`Guarantees()` derives from the backend's `guaranteeBits`; `GuaranteeBits()`
returns them. **Step 4:** PASS. **Step 5:** commit `feat: executor, null
backend, external executor, env scrubbing, guarantees`.

### Task 7: `AckUnconfined` validation gate

**Files:** Modify `executor.go`; add to `executor_test.go`.

**Step 1 — failing test:** `NewExecutor` on an unconfined policy without
`AckUnconfined` → error; with it → passes, produces a passthrough executor.
**Step 2:** FAIL. **Step 3:** validate in `NewExecutor`. **Step 4:** PASS.
**Step 5:** commit `feat: require explicit ack for unconfined`.

---

## Phase 2 — macOS Seatbelt backend

Gated `//go:build darwin`. Tests run only on macOS. Uses Task M1's findings.

### Task 8: SBPL generation + enforcement (SPEC §7.1, §5.2)

**Files:** Create `backend_seatbelt.go`, `backend_seatbelt_test.go`,
`testdata/*.sbpl` (golden profiles).

**Step 1a — failing pure tests (no exec):** `compileSBPL(Policy)` per mode →
golden profile: default-deny base; `file-read*`/`file-write*`/`process-exec`
allows per resolved entry; deny rules for secret paths + `.git` carveout;
network section per `Ports`/`Loopback`/`DNS`. Per M1: `Private`/metadata either
emit real rules or are recorded `blocked` in `CompileReport`.
**Step 1b — failing integration tests (§12.1 macOS rows):** under `write` —
write outside ws+`/tmp` fails; `.git` write fails; `~/.ssh` read fails; `.env`
read fails; `connect` blocked; `Level() >= LevelDegraded`; `Guarantees()` has
`WriteBoundary && ReadDenies && EnvScrub && NetworkBoundary` true.

**Step 2:** FAIL. **Step 3:** implement SBPL generation + `-D<param>` path
passing; `spawnSpec` = `/usr/bin/sandbox-exec -p <profile> -D... -- /bin/sh -c
<cmd>` (+ argv form for `RunArgv`); wire `platformBackend()` to select Seatbelt
on darwin; set `guaranteeBits`. **Step 4:** PASS. **Step 5:** commit
`feat(darwin): seatbelt backend passes acceptance rows`.

---

## Phase 3 — Linux ladder

Gated `//go:build linux`. Stage-2 re-exec is the common spawn path for both
rungs (SPEC §7.2). Add `go-landlock` + `google/nftables` to `go.mod` here. Rung
2 built before rung 1 (works in containers where userns is blocked); a runtime
probe picks the strongest. **Integration tests need a Linux host/CI.**

### Task 10: Capability probe + rung selection (SPEC §7.2)

**Files:** Create `probe_linux.go`, `probe_linux_test.go`.

Detect Landlock ABI (via go-landlock), seccomp availability, userns/mountns/netns
creation, cgroup v2 writable delegation. `selectRung()` → rung 1 / rung 2 / none.
Capability-aware skips: when a mechanism is absent, assert the probe **reports**
absence (not that the mechanism works). Commit `feat(linux): capability probe
and rung selection`.

### Task 11: `Init()` stage-2 re-exec dispatch — common path (SPEC §6, §7.2)

**Blocks Tasks 12 & 13.** **Files:** Create `init_linux.go`, `init_other.go`
(no-op non-linux); modify `executor.go`.

**Step 1 — failing test:** a helper binary calling `sandbox.Init()` in `main`,
re-executed with the stage-2 sentinel, reports it entered stage 2 and applies a
sealed spec (passed via env/pipe). **Step 2:** FAIL. **Step 3:** implement
moby/reexec-style dispatch keyed on a sentinel arg/env; `Init()` returns
immediately on the normal path; stage-2 reads the sealed spawn spec, will apply
(namespaces if rung 1) + Landlock + seccomp + `no_new_privs` + env + cgroup, then
`exec`s the target (mechanisms filled by 12/13/14). **Step 4:** PASS.
**Step 5:** commit `feat(linux): stage-2 re-exec dispatch (common spawn path)`.

**Carry-forward from Task 6a review — revisit the `spawnSpec` seam here.** 6a's
`spawnSpec` is two independent, reused closures (`wrapArgv`, `configure`) with no
per-spawn context, threaded from a spec "compiled once and reused." Linux stage-2
needs **per-spawn** state: a fresh pipe/fd to pass the sealed spec, `ExtraFiles`
that must match an fd referenced in the argv, `SysProcAttr.Cloneflags`, and the
target `dir` — and concurrent spawns each need their own pipe, not a shared static
fd. Before wiring 12/13, evaluate reshaping the seam to a single per-spawn
`func(dir string, argv []string) (finalArgv []string, configure func(*exec.Cmd), cleanup func())`
returning a matched argv+configure pair, rather than two reused fields. Null/Seatbelt
are unaffected (they'd just ignore `dir` and return a nil cleanup).

### Task 12a: Rung 2 — Landlock FS via stage-2 (SPEC §7.2, §7.5)

**Files:** Create `backend_landlock_linux.go`, `_test.go`.

**Step 1 — failing tests (skip if ABI<4):** write outside writable roots →
EACCES; workspace write ok; `.git` carveout via **enumerated sibling allows**
(snapshot semantics: a file created mid-spawn under the carved parent is
inaccessible); fixed secret denies (`~/.ssh`) blocked; `Guarantees().WriteBoundary
&& ReadDenies` true. **Step 2:** FAIL. **Step 3:** compile Policy → go-landlock
ruleset (FS rules) applied in the stage-2 child; enumerated-allow expansion for
fixed denies. **Step 4:** PASS. **Step 5:** commit `feat(linux): rung-2 landlock
FS`.

### Task 12b: Rung 2 — seccomp-BPF via stage-2 (SPEC §7.2)

**Files:** `seccomp_linux.go`, `_test.go`; extend the landlock backend.

**Step 1 — failing tests:** `no_new_privs` set; `ptrace`/`io_uring` denied; UDP
`socket(AF_INET*, SOCK_DGRAM)` denied below ABI v10. **Step 2:** FAIL.
**Step 3:** hand-built seccomp-BPF program installed in the stage-2 child (per
M3). **Step 4:** PASS. **Step 5:** commit `feat(linux): rung-2 seccomp filter`.

### Task 12c: Rung 2 — TCP ports + DNS + glob-deny degradation (SPEC §5.2, §7.5)

**Step 1 — failing tests:** TCP to `Ports` allowed, other TCP blocked (Landlock
TCP rules); DNS via `RES_OPTIONS=use-vc` TCP path works on glibc (musl narrowing
recorded); `**/.env*` glob deny **unenforced for subprocesses** → `Level()==
LevelDegraded`, `Guarantees().ReadDenies` reflects fixed-path denies only, report
entry present. **Step 2:** FAIL. **Step 3:** implement; set `guaranteeBits`
(no `AddressNetwork` on rung 2). **Step 4:** PASS. **Step 5:** commit
`feat(linux): rung-2 network + degradation reporting`.

### Task 13a: Rung 1 — namespaces + mount bind-view (SPEC §7.2, §7.5)

**Files:** Create `backend_namespace_linux.go`, `_test.go`.

**Step 1 — failing tests (skip if userns blocked):** restricted-read
(`zerotrust`): tmpfs root + scoped ro-binds; host dotfiles/other repos
**invisible** (not just unreadable); FS carveouts via ro re-mask bind (not
enumeration); workspace rw. **Step 2:** FAIL. **Step 3:** Cloneflags
(user/mount/pid/net ns) → stage-2 (Task 11) sets up the bind view. **Step 4:**
PASS. **Step 5:** commit `feat(linux): rung-1 namespace + mount view`.

### Task 13b: Rung 1 — glob denies via bounded enumeration masking (SPEC §7.5)

**Step 1 — failing tests:** `**/.env*` under workspace masked by empty ro-bind
(spawn-time bounded enumeration to max depth); `Level()` stays `Full`; report
notes the command-created-file residual. **Step 2:** FAIL. **Step 3:** implement
enumeration + masking in stage-2. **Step 4:** PASS. **Step 5:** commit
`feat(linux): rung-1 glob-deny masking`.

### Task 13c: Rung 1 — nftables address network (SPEC §5.2, §5.4) — full v1 net

**Step 1 — failing tests:** metadata IP unreachable under `trusted`;
`Private`/`Loopback` honored; DNS over UDP works (nftables 53/udp+tcp);
non-allowed egress blocked. **Step 2:** FAIL. **Step 3:** in-netns nftables via
`google/nftables` (per M4). **Step 4:** PASS. **Step 5:** commit `feat(linux):
rung-1 nftables address filtering`.

### Task 13d: Rung 1 — Level/Guarantees wiring (SPEC §7.5, §10.3)

**Step 1 — failing tests:** rung-1 full policy → `Level()==LevelFull` and
`Guarantees()` all-true (ProcessBoundary, WriteBoundary, ReadDenies, EnvScrub,
NetworkBoundary, AddressNetwork; ResourceLimits once Task 14 lands).
**Step 2:** FAIL. **Step 3:** compose `guaranteeBits` from the applied
mechanisms. **Step 4:** PASS. **Step 5:** commit `feat(linux): rung-1
level/guarantees`.

### Task 14: cgroup v2 limits (SPEC §7.4)

**Files:** Create `cgroup_linux.go`, `_test.go`.

**Step 1 — failing tests:** spawned command joins a transient scope with
`pids.max`/`memory.max`/`cpu.max`; a fork bomb is capped; cgroup v2 unavailable →
limits unenforced + report entry, `Level()` unchanged, `Guarantees().ResourceLimits
== false` (per M5). **Step 2:** FAIL. **Step 3:** implement (join in stage-2).
**Step 4:** PASS. **Step 5:** commit `feat(linux): cgroup v2 resource limits`.

---

## Phase 4 — Harness seams

In `harness` (`/Users/ipotter/code/looprig/harness`). **No import of `sandbox`**
— every signature stdlib-only. Verified in Task 20. **Work on a feature branch**
(harness is an existing repo).

### Task 15: Runner interfaces + Bash/Grep injection (SPEC §10.1)

**Files:** Modify `pkg/tool/tool.go` (add `CommandRunner`, `ArgvRunner`,
`GrantedRunner`, `GrantsFromContext`); `pkg/tools/bash.go` (delegate
`runShellCommand` to an injected `CommandRunner`; nil → today's direct
`exec.CommandContext`; `WithRunner` option); `pkg/tools/grep.go:290` (inject
`ArgvRunner`; `WithArgvRunner`). Tests: `pkg/tools/bash_test.go`, `grep_test.go`.

**Step 1 — failing test:** a fake `CommandRunner` capturing (dir, command);
`NewBash(root, WithRunner(fake))` routes through it; `NewBash(root)` (nil) still
direct-execs (existing tests green). Same for Grep/argv. **Step 2:** FAIL.
**Step 3:** implement. **Step 4:** PASS + existing bash/grep suites green.
**Step 5:** commit `feat(harness): command/argv runner injection seam`.

### Task 16: PermissionChecker posture + guarantee interlock (SPEC §10.2, §10.3)

**Files:** Modify `pkg/tools/permission.go` (`WithPosture`, `WithCeilingPostures`,
posture struct incl. `RequiredGuarantees uint64`, final ceiling-clamp stage, the
**`GuaranteeBits() uint64` interlock**, optional secondary `Level()` floor);
Test `permission_test.go`.

**Step 1 — failing tests:** auto-approve-bash active only when
`runnerBits & posture.RequiredGuarantees == RequiredGuarantees` (fake runner
returns varying bitmasks); nil runner or zero bits → `trusted` degrades to ask;
ceiling clamp downgrades a would-be auto-approve; grant-carrying `argsJSON` →
Ask below top ceiling. **Step 2:** FAIL. **Step 3:** implement (runner probed via
`interface{ GuaranteeBits() uint64 }` and `interface{ Level() uint8 }`).
**Step 4:** PASS. **Step 5:** commit `feat(harness): posture options and
guarantee interlock`.

### Task 17a: Bash `grants` arg + `GrantsFromContext` (SPEC §9.3, §10.7)

**Files:** Modify `pkg/tools/bash.go` (optional `grants []string` in args schema
+ tool docs: "attach tokens from a prior denial, never invent"); `pkg/tool/tool.go`
(`GrantsFromContext(ctx) []string`). Test: merge of args-carried + ctx-carried
grants. **Step 1:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:**
commit `feat(harness): bash grants arg and context carrier`.

### Task 17b: `BashRequest.Grants` + describer + codec (SPEC §10.7 item 3)

**Files:** Modify `pkg/tool/permission_request.go` (`BashRequest.Grants
[]GrantDisplay{Token, Description string}`; **corrected path** — was wrongly
`pkg/session`); the tool's `BuildRequest` probes its runner for
`PlanGrants`/`DescribeGrant`; the durable codec + marshal fixtures. **Step 1 —
failing tests:** `BuildRequest` attaches verified grant displays; verification
failure fails the build (no prompt); **golden fixture**: a pre-existing journal
entry without the field decodes unchanged. **Step 2:** FAIL. **Step 3:**
implement (new field optional). **Step 4:** PASS + existing codec suites green.
**Step 5:** commit `feat(harness): bash-request grant display + codec`.

### Task 17c: `ApproveToolCall.AcceptedGrants` + persisted `GrantDeltas` (SPEC §10.7 item 4)

**Files:** Modify `pkg/command/*` (`ApproveToolCall.AcceptedGrants []string`;
approval record `GrantDeltas []string`); `pkg/loop/runner.go` (`runOne` places
accepted grants on per-call ctx; passes that ctx to `Permission.Grant` for
non-Once scopes). **Step 1 — failing tests:** pre-ask approval returns
`AcceptedGrants`; `GrantsFromContext` returns them; `Grant` receives the
grant-bearing ctx; record persists `GrantDeltas` (sorted, deduped, descriptions
not tokens); a deltaless record matches only grant-free calls. **Step 2:** FAIL.
**Step 3:** implement. **Step 4:** PASS. **Step 5:** commit `feat(harness): grant
acceptance + delta persistence`.

### Task 17d: Session-scoped repeats — `ApprovedGrants` re-mint (SPEC §10.7 item 6)

**Files:** Modify `pkg/tools/permission.go` (optional
`ApprovedGrants(toolName, argsJSON string) []string` using the held runner's
`PlanGrants`+`DescribeGrant`, filtered to the record's `GrantDeltas`);
`pkg/loop/runner.go` (probe + place on ctx). **Step 1 — failing test:** a repeat
identical call matches the persisted rule → `ApprovedGrants` re-mints filtered
tokens (single-mint, short-lived). **Step 2:** FAIL. **Step 3:** implement.
**Step 4:** PASS. **Step 5:** commit `feat(harness): session-scope grant
re-mint`.

### Task 18: Journaled ceiling command (SPEC §8, §10.2)

**Files:** Modify `pkg/command/*` (`SetSecurityCeiling{Level uint8}`), event
(`SecurityCeilingChanged`), the checker ceiling source; Tests. **Step 1 —
failing tests:** applying `SetSecurityCeiling` updates the ceiling ordinal, emits
the event, replays deterministically; clamp takes effect on next `Check`;
in-flight (already-spawned) commands unaffected. **Step 2:** FAIL. **Step 3:**
implement (ordinal only — harness never sees mode names). **Step 4:** PASS.
**Step 5:** commit `feat(harness): journaled security-ceiling command`.

### Task 19: ReadGuard adaptation hook (SPEC §10.5)

**Files:** Confirm `pkg/loop/deps.go` `ReadGuard` shape suffices; if the consumer
needs a helper to build a `ReadGuard` from FS rules, add a stdlib-only adapter
interface here (not the sandbox impl). Test that native read tools honor a fake
guard denying `.env`. Commit `feat(harness): readguard adaptation seam`.

**Carry-forward from Task 4 review (sandbox side, when the adapter is built):**
- `Resolve` (`fsresolve.go`) is **purely lexical** — the consumer MUST feed it
  absolute, `filepath.Clean`ed, **symlink-resolved** paths (and on case-insensitive
  macOS FS, canonical case), or a deny can be bypassed via a symlink/case variant.
- `Resolve` recompiles deny/allow globs on every call — fine for backend
  per-spawn use, but if the ReadGuard calls `Resolve` **per file read** on a hot
  path, add a `Compile(entries) *Resolver` that caches `*regexp.Regexp` per glob
  (travels with the "policy compiled per backend" model), rather than a
  package-level cache. Precompile only if profiling shows it matters.
- Optional defense-in-depth: `WithDenyRead`/`PolicyFor` currently accept unvalidated
  glob strings; the resolver already fails **closed** on an uncompilable deny glob
  (over-denies), but construction-time validation (surfaced at `NewExecutor`) would
  turn a silent over-deny into a clear error. Consider alongside the §5.3 home guard.

### Task 20: Dependency-direction guard

**Files:** Create `pkg/tool/deps_test.go` (or CI script). Assert (via `go list
-deps ./...`) that **no harness package imports `github.com/looprig/sandbox`** —
a failing test if violated. Commit `test(harness): forbid sandbox import`.

---

## Phase 5 — Consumer wiring (swe)

In `swe` (`/Users/ipotter/code/looprig/swe`) — the only module importing both.
**Feature branch.**

### Task 21: `postureFor` / ceiling table + RequiredGuarantees masks (SPEC §10.2, §10.3)

**Files:** Create `swarms/swe/security.go`, `_test.go`.

**Step 1 — failing test:** the ~20-line ordinal→posture table matches SPEC §4
(edits auto at `write`+, bash auto at `trusted`+, etc.); each posture's
`RequiredGuarantees` mask is built from `sandbox.Guarantee*` constants (write →
`GuaranteeWriteBoundary|GuaranteeEnvScrub|GuaranteeReadDenies`; trusted adds
`GuaranteeNetworkBoundary`). **Step 2:** FAIL. **Step 3:** implement.
**Step 4:** PASS. **Step 5:** commit `feat(swe): mode→posture table + guarantee
masks`.

### Task 22: `WithSecurityMode` knob + BuildTools wiring (SPEC §10.4)

**Files:** Modify `swarms/swe/swarm.go`, `operator.go`, `reviewer.go`,
`spawner.go` (per-leaf executor + posture from `min(role, ceiling)`),
`agents.go`/registry as needed; Tests.

**Step 1 — failing tests:** building primary/operator/reviewer toolsets with a
mode wires a sandbox executor into `NewBash`/`NewGrep` and the matching posture
into the checker; effective mode = `min(role static, session ceiling)`; a
spawned subagent is clamped `<=` parent (SPEC §8, §10.6). **Step 2:** FAIL.
**Step 3:** implement `WithSecurityMode(Mode)` (session ceiling) + per-role
static modes in `BuildTools`. **Step 4:** PASS. **Step 5:** commit `feat(swe):
security-mode knob and per-role wiring`.

**Carry-forward from Task 16 review (I-2) — add a CONFORMANCE test here.** harness
probes the sandbox executor by anonymous `interface{ GuaranteeBits() uint64 }` /
`interface{ Level() uint8 }` / `CommandRunner`/`ArgvRunner`/`PlanGrants`/`DescribeGrant`
(no import — structural coupling). A signature drift on `sandbox.Executor` would
NOT fail to compile; harness would silently probe→0 and Bash auto-approve would
quietly stop firing (fail-closed but invisible). swe imports BOTH modules, so add
a compile-time/assertion test here that a real `*sandbox.Executor` satisfies every
harness structural interface it must (`tool.CommandRunner`, `tool.ArgvRunner`,
`tool.GrantedRunner`, and the `GuaranteeBits()`/`Level()`/`PlanGrants()`/`DescribeGrant()`
anonymous interfaces the checker/tools assert). This is the only place the drift
can be caught.

### Task 23: Foreign-agent process wrapping (SPEC §10.6)

**Files:** Modify `harness/pkg/foreignloop/claude/claude.go:68` (accept an
injected `CommandRunner`/`Wrap` for the foreign process), swe wiring; create
`foreign.go` in sandbox (`ForeignAgentPolicy(base, decl)` preset,
`Net{Ports:{443}, DNS:true}` + creds env allowlist + external-isolation marker);
Tests.

**Step 1 — failing tests:** foreign process spawned wrapped; child commands
inherit confinement; its LLM API reachable (`:443`+DNS); harness tokens scrubbed
except the agent's allowlisted key; child told it is externally sandboxed.
**Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:** commit
`feat: sandbox foreign-agent process tree`.

---

## Phase 6 — Acceptance matrix + release

### Task 24: Acceptance matrix integration suite (SPEC §12.1)

**Files:** Create `acceptance_test.go` (+ `_linux`/`_darwin` split), a table
mirroring §12.1 row-for-row. Rows requiring an absent mechanism `t.Skip` with a
recorded reason (never silently pass). Include: dynamic downgrade mid-session,
grant retry (post-denial + pre-ask), fabricated-token rejection, env scrub,
metadata deny, cgroup-unavailable, foreign-agent launch, **per-row `Guarantees()`
assertions**. Commit `test: acceptance matrix`.

### Task 25: `sandboxtest` conformance helper (mirror `storetest`)

**Files:** Create `sandboxtest/` — a reusable suite a consumer runs against any
`Executor` to assert the write boundary / env scrub / guarantee reporting hold.
Commit `feat: sandboxtest conformance suite`.

### Task 26: README, security notes, CI matrix, tag

**Files:** `README.md` (positioning, the honest per-rung capability table, the
"reads are not confidential in write/trusted" caveat, `Init()` requirement); CI
running the suite on macOS + Linux (rung 1 and a userns-disabled container for
rung 2, so M2–M5 + Linux tasks actually execute). Version-tag repo #11 per the
looprig release convention. Commit `docs: sandbox README and security notes`;
tag `v0.1.0`.

### Task 27: Update harness/swe CLAUDE.md + memory

**Files:** Modify `harness/CLAUDE.md:74` (the "OS-level sandboxing out of scope /
prerequisite for auto-approving Bash" note now points here as the realized
unlock), `swe/CLAUDE.md`; update the `sandbox-module-design` memory to "built,
v0.1.0". Commit `docs: record sandbox unlock in harness/swe guides`.

---

## Cross-cutting notes

- **No `time.Now()`/`rand` in test assertions** — inject a clock into grant
  expiry (Task 5); seed any randomness; vary by index.
- **Soundness invariant is a test, not a comment** (SPEC §7.5): every backend
  task asserts that an un-enforceable feature compiles *narrower* (blocked/
  degraded) and is recorded — never wider. `Guarantees()` bits are the
  machine-checkable form of this.
- **`Guarantees()`/`GuaranteeBits()` gate auto-approval** (Task 16 interlock) —
  the load-bearing safety property. If a platform task can't reach a required
  guarantee, the dependent auto-approve posture must stay off — assert it.
- **Stage-2 re-exec is mandatory on Linux** for both rungs (Task 11 blocks
  12/13); never apply Landlock/seccomp in the parent.
- **Order across modules**: Phase 0.5 M1 now (darwin); Phase 1 blocks
  everything; Phase 4 (harness) can proceed in parallel with Phases 2–3 (no
  shared files); Phase 5 needs both. Linux integration (Phase 0.5 M2–M5,
  Phase 3) needs a Linux host/CI — authored now, proven there.
- **Deferred (SPEC §12):** SNI-peek egress proxy, MITM method filtering, seccomp
  user-notification telemetry, prompt-injection classifier, Windows backend,
  session-scoped executor daemon.
- **cli follow-up (outside this plan's scope):** the escalation prompt shows grant
  descriptions only if a renderer type-asserts `tool.BashRequest.Grants` and
  displays each `.Description` (§9.3). Task 17b attaches + durably journals them in
  harness, but the `cli` TUI (separate module) must render them for the operator to
  actually see the escalation — track as a cli change after this plan.
