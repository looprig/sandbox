# Windows Sandbox Dual-Tier Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the approved no-admin restricted-token tier and installed
elevated Windows tier without claiming any guarantee that the selected Windows
mechanism does not enforce.

**Architecture:** Keep the root package as the existing alias/forwarder facade.
Windows mechanisms live under `internal/windows`, Windows object-path primitives
live in the leaf `internal/winpath` package, the companion service/runner lives
under `cmd/sandbox-host`, and reusable conformance behavior remains in
`pkg/sandboxtest`. The executor continues to own environment assembly, command
execution, grants, and lifecycle; compiled Windows specs may additionally own
idempotently releasable ACL leases.

**Tech Stack:** Go 1.26.4, `golang.org/x/sys/windows`, Win32 restricted tokens,
`STARTUPINFOEX`, Job Objects, Windows ACLs and SIDs, named pipes, local service
and account APIs, DPAPI, Windows Firewall APIs, the existing authenticated Go
HTTP proxy, and Windows Server/Windows 11 CI.

**Normative design:** `docs/plans/2026-07-21-windows-sandbox-design.md`.

## Implementation status and Windows handoff (2026-07-22)

Work is on branch `feat/windows-sandbox`.

- Phase 1 (Tasks 1-4) is implemented, independently reviewed for specification
  compliance and code quality, and verified with the full host race suite plus
  Windows amd64/arm64 cross-builds.
- Phase 2 Tasks 5-8 are implemented at code level, independently approved for
  static specification compliance and code quality, and cross-build for Windows
  amd64/arm64. The focused Job quarantine tests and live Job cancellation/
  breakaway tests pass on the current Windows host. No complete live Windows
  phase result is claimed yet.
- Task 5 still requires the exact-token runtime matrix on every supported
  disposable Windows image. A failure requires bound trace evidence collected
  by a separate elevated collector while the baseline test itself runs as a
  standard user. No go/no-go result has been selected.
- Tasks 6-8 still require the complete disposable-worker live Windows path,
  handle-inheritance, and Job matrices. The current managed host cannot run the
  path suites because its sandbox denies parent-path identity walks, and its Go
  toolchain has no C compiler for `-race`.
- A failed completion-port zero proof now transfers the Job, command backing,
  spawn cleanup, lifecycle barriers, transient compiled spec, and proxy authority
  to an injected quarantine/reaper. Release occurs only after a later exact zero
  proof; delayed cleanup errors are returned by `ExecutorSet.Close`. Focused core
  and real `Executor.run` integration regressions cover retention, release order,
  early setup errors, proxy observation, and set-close blocking.
- `TestProcessTreeCancellationAndJobClosePreventDelayedGrandchild` is the
  shared Phase 2 parent-crash/host-close evidence: closing the host-owned Job
  prevents a delayed ordinary grandchild marker, alongside the cancellation
  case. Task 12 reuses that reviewed lifecycle proof rather than simulating a
  weaker non-production parent.
- Task 9 is implemented and independently approved for static specification
  compliance and code quality. Focused SID/ACL-plan tests, vet, and Windows
  amd64/arm64 cross-builds pass. The live restricted-token conformance tests
  remain outstanding: this managed host starts Codex from an already restricted
  source token, and the tests fail with that explicit prerequisite rather than
  skipping or claiming a pass.
- Task 10 is implemented at code level. Focused transactional ACL/journal tests,
  vet, and Windows amd64/arm64 cross-builds pass. The destructive disposable
  NTFS exact/tree/inheritance/carveout/reparse/hard-link matrix is executable
  behind `SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST=1` but has not been run on this
  developer workstation, as required by the repository execution rules.
- Task 11 is implemented at code level. Focused backend/platform tests and vet
  pass, and the affected packages cross-compile for Windows amd64/arm64. The
  disposable restricted executor lifecycle test is gated with the same worker
  prerequisite and has not been run here. Three local executor runtime tests
  fail before backend construction because the managed host denies the required
  parent-path identity walk; this is not recorded as a pass or skip.
- Task 12 is implemented at code level. Shell-aware conformance and non-live
  focused tests pass; the Windows adversarial, broker, descendant, and acceptance
  suites plus their helper cross-compile for amd64/arm64. Their disposable-worker
  gates have not been enabled on this developer workstation and remain unrun.
- Tasks 13-23 have not started. Tasks 13-19 remain hard-gated on the reviewed
  Task 5 runtime-baseline result.

Run these gates on the Windows handoff branch:

```powershell
# Standard-user exact-token gate. Required Python and every manifest-required
# runtime must be installed; required-row skips/absence are not a pass.
go test -count=1 -v ./spikes/windows -run TestRestrictedRuntimeBaseline

# Path identity and namespace behavior. Exercise NTFS and ReFS plus enabled
# 8.3, symlink, junction, hard-link, and root-swap controls without skips.
go test -race -count=1 ./internal/winpath ./pkg/profile ./internal/policy

# Explicit handle-list, least-authority stdio, and two-stage runner canaries.
go test -race -count=1 ./internal/windows ./internal/exec -run 'Handle|Spawn|Standard'

# Job configuration, breakaway, descendants, limits, UI, and cancellation.
go test -race -count=1 ./internal/windows ./internal/exec -run 'Job|ProcessTree|ResourceLimit'
```

If Task 5 records a runtime failure, follow
`docs/spikes/windows-restricted-runtime.md`: keep `go test` in the standard-user
session, run ProcMon/another approved collector in a separate elevated session,
bind the shared run nonce and captured PIDs, finalize the raw-trace hash, and
validate the evidence without rerunning the baseline. ProcMon-only evidence is
not sufficient for an NT Object Manager class it did not capture.

---

## Repository and execution rules

- Do not create new files at the repository root. Existing root files may be
  modified only where the current facade/documentation pattern requires it:
  `SPEC.md`, `sandbox.go`, `facade_test.go`, `README.md`, `doc.go`, and
  `Makefile`.
- Put implementation in its owning package. In particular, do not add Windows
  mechanisms to `sandbox.go` or `internal/exec` merely to avoid creating
  `internal/windows` files.
- Use `//go:build windows` for Win32 implementations and a narrow non-Windows
  stub only when the public API must compile everywhere.
- Follow @superpowers:test-driven-development for every implementation task:
  observe the named test fail, make the smallest implementation pass, then run
  the package and cross-build gates before committing.
- Follow @superpowers:systematic-debugging for every unexpected Windows result.
  A mechanism failure narrows a claim or blocks the milestone; it never causes
  an unreviewed fallback.
- Run Tasks 1-4 before Windows mechanism work. Task 5 is a hard go/no-go gate for
  Tasks 13-19. Restricted mode may ship after Task 12; elevated mode may not.
- Do not run account, service, firewall, or ACL integration tests on a developer
  workstation. Use a disposable Windows VM/CI worker and always invoke the
  cleanup test stage.

## Target package layout

```text
cmd/sandbox-host/               companion service and protected runner
internal/enforce/               backend contract and compiled-resource release
internal/exec/                  executor/grant lifecycle and shared process tree
internal/platform/              platform option routing and backend selection
internal/policy/                effective policy and identity-bound grant handles
internal/windows/               Windows backend, setup, broker, ACL, token, Job
internal/winpath/               leaf Win32 path/object identity primitives
pkg/profile/                    public authority and compile-report vocabulary
pkg/sandboxtest/                reusable shell-aware guarantee conformance suite
spikes/windows/                 live feasibility and adversarial test programs
docs/spikes/                    recorded mechanism inventories
docs/plans/                     this plan and the approved design
scripts/                        cross-build helpers
```

## Common verification commands

Run after every task whose files build on the current host:

```bash
gofmt -w <changed-go-files>
go test -race ./<changed-package>/...
git diff --check
```

Run after every task that adds or changes Windows code:

```bash
./scripts/test-windows-build.sh
```

Expected: every package and test package compiles for `windows/amd64` and
`windows/arm64`; no Windows binary is executed on the non-Windows host.

On a disposable standard-user Windows worker:

```powershell
go test -race -count=1 ./internal/windows ./internal/exec ./pkg/sandboxtest
```

On a disposable elevated Windows worker:

```powershell
go test -race -count=1 -tags=windows_elevated ./internal/windows ./internal/exec
```

Expected: PASS, followed by the cleanup verification that finds no installation
accounts, service, firewall rule, active lease, or meaningful ACE.

## Phase 1 — Canonical seams and portable surface

### Task 1: Amend the canonical lifecycle and shell contracts

**Files:**

- Modify: `SPEC.md`
- Modify: `internal/enforce/enforce.go`
- Modify: `internal/enforce/null.go`
- Create: `internal/enforce/shell_unix.go`
- Create: `internal/enforce/shell_windows.go`
- Modify: `internal/darwin/seatbelt.go`
- Modify: `internal/linux/backend.go`
- Modify: `internal/exec/executor.go`
- Modify: `internal/exec/executor_set.go`
- Modify: `internal/exec/executor_set_test.go`
- Modify: `internal/exec/grant_v1_test.go`
- Modify: `pkg/sandboxtest/sandboxtest.go`
- Modify: `pkg/sandboxtest/sandboxtest_test.go`

**Step 1: Pin the changed canonical contract**

Amend `SPEC.md` to say that a compiled `enforce.Spec` may own immutable,
idempotently releasable resources; per-spawn mutable state still belongs to
`Wrap`. Make `RunCommand` shell selection platform-specific and change
conformance from “unclaimed write boundary implies the write succeeds” to the
one-way security rule “a claimed boundary must deny every covered probe.” Add
the named `windows.runtime-baseline` intent/report entry.

**Step 2: Write failing lifecycle tests**

Add a capture backend whose `Release` increments an atomic counter. Test:

```go
func TestExecutorSetCloseReleasesCompiledSpecOnce(t *testing.T) {
    backend := &captureBackend{release: func() error { /* increment */; return nil }}
    // Construct one executor, call Close twice, assert release count == 1.
}

func TestGrantCompiledSpecReleasedAfterSpawn(t *testing.T) {
    // Recompile for one filesystem grant and assert its transient Release runs
    // only after the execution lease and process tree are empty.
}
```

**Step 3: Run the focused tests and observe failure**

Run:

```bash
go test ./internal/exec -run 'TestExecutorSetCloseReleasesCompiledSpecOnce|TestGrantCompiledSpecReleasedAfterSpawn' -count=1
```

Expected: FAIL because `enforce.Spec` has no `Release` and executor close does
not own compiled backend resources.

**Step 4: Add release ownership**

Change the seam to:

```go
type Spec struct {
    Wrap    func(string, []string) ([]string, func(*exec.Cmd) error, func())
    Release func() error
}
```

Guard release with executor lifecycle state so base release is called once on
close and a grant-compiled release is deferred until its execution finishes.
On construction failure, release every spec already compiled. Keep Darwin,
Linux, and null `Release` nil.

**Step 5: Split shell selection by platform**

Move `ShellArgv` out of `enforce.go`:

```go
// shell_unix.go
func ShellArgv(command string) []string { return []string{"/bin/sh", "-c", command} }

// shell_windows.go
func ShellArgv(command string) []string {
    return []string{system32CommandInterpreter(), "/D", "/S", "/C", command}
}
```

The Windows helper must resolve the canonical System32 `cmd.exe` path; it must
not read `%ComSpec%`.

**Step 6: Make conformance conservative**

In `checkWriteBoundary`, retain the writable-inside positive control and assert
outside denial only when `GuaranteeWriteBoundary` is set. Do not require an
honest `LevelNone` backend to permit the write. Add a fake backend test that
denies the direct probe while withholding the bit and must pass.

**Step 7: Verify and commit**

Run:

```bash
go test -race ./internal/enforce ./internal/exec ./pkg/sandboxtest
go test -race ./internal/darwin ./internal/linux
git diff --check
```

Expected: PASS.

Commit:

```bash
git add SPEC.md internal/enforce internal/exec internal/darwin/seatbelt.go internal/linux/backend.go pkg/sandboxtest
git commit -m "refactor: support releasable platform spawn specs"
```

### Task 2: Add typed Windows public configuration and non-Windows stubs

**Files:**

- Create: `internal/windows/types.go`
- Create: `internal/windows/errors.go`
- Create: `internal/windows/setup_other.go`
- Create: `internal/windows/types_test.go`
- Modify: `internal/exec/executor_set.go`
- Modify: `internal/exec/executor_set_test.go`
- Modify: `sandbox.go`
- Modify: `facade_test.go`

**Step 1: Write facade and option tests**

Pin these declarations through the external facade test:

```go
var _ sandbox.WindowsSandboxMode = sandbox.WindowsAuto
var _ sandbox.ExecutorSetOption = sandbox.WithWindowsSandboxMode(sandbox.WindowsRestrictedToken)
var _ sandbox.ExecutorSetOption = sandbox.WithWindowsSandboxStateRoot(`C:\ProgramData\Looprig`)
var _ []sandbox.WindowsSetupProblem = sandbox.WindowsSetupStatus{}.Problems
```

On non-Windows, test that inspection/setup return `ErrSandboxUnavailable` and
that non-default Windows executor options are rejected rather than ignored.

**Step 2: Run and observe failure**

Run:

```bash
go test . ./internal/exec ./internal/windows -run 'Windows|Facade' -count=1
```

Expected: FAIL with undefined Windows API.

**Step 3: Implement the typed surface in its owning package**

Define the exact types and problem codes from design §6 in
`internal/windows/types.go`, including:

```go
type Config struct {
    Mode      SandboxMode
    StateRoot string
}

type SetupProblem struct {
    Code WindowsSetupProblemCode
    Resource string
    Path string
    Port uint16
    PID uint32
    Detail string
}
```

Use the design names for the exported aliases (`WindowsSandboxMode`,
`WindowsSetupConfig`, `WindowsSetupStatus`, and `WindowsSetupProblem`). Keep
`Detail` diagnostic-only and validate it through `internal/safetext`; never
include a credential or nonce.

Add `WithWindowsSandboxMode` and `WithWindowsSandboxStateRoot` to the existing
`executorSetConfig`. Modify only the existing root `sandbox.go` to alias and
forward the surface; do not create a root `windows.go`.

**Step 4: Implement stubs and sentinel relationships**

Non-Windows `Inspect`, `Setup`, and `Remove` return
`enforce.ErrUnavailable`. Setup-required and stale typed errors unwrap to that
sentinel. Explicit non-default Windows options fail option validation on
non-Windows.

**Step 5: Verify and commit**

Run:

```bash
go test -race . ./internal/exec ./internal/windows
git diff --check
```

Expected: PASS.

Commit:

```bash
git add sandbox.go facade_test.go internal/windows internal/exec/executor_set.go internal/exec/executor_set_test.go
git commit -m "feat: add typed Windows sandbox configuration"
```

### Task 3: Route platform options and add the Windows cross-build gate

**Files:**

- Create: `internal/platform/options.go`
- Create: `internal/platform/platform_windows.go`
- Create: `internal/platform/platform_windows_test.go`
- Modify: `internal/platform/platform_darwin.go`
- Modify: `internal/platform/platform_linux.go`
- Modify: `internal/platform/platform_other.go`
- Modify: `internal/platform/platform_other_test.go`
- Modify: `internal/exec/executor.go`
- Create: `scripts/test-windows-build.sh`
- Modify: `Makefile`

**Step 1: Fix and pin platform selection**

First fix the existing typo in `platform_other_test.go` so it checks the local
`backend` value rather than the `enforce.Backend` type. Add tests proving:

- zero Windows options leave Darwin/Linux selection unchanged;
- non-zero Windows options fail on non-Windows;
- the Windows file forwards mode/state into `internal/windows.PlatformBackend`;
- unconfined profiles still choose `enforce.NewNull` explicitly.

**Step 2: Run and observe failure**

Run:

```bash
go test ./internal/platform ./internal/exec -run 'Platform|WindowsOption' -count=1
```

Expected: FAIL because `platform.Backend` has no options and Windows has no
selector.

**Step 3: Add the option seam**

Use:

```go
type Options struct {
    Windows windows.Config
}

func Backend(Options) (enforce.Backend, error)
```

Pass the immutable executor-set option snapshot into backend construction.
Darwin/Linux accept only the zero Windows config. Windows calls the Windows
selector. Keep all authority in `profile.Settings`; mode is operational choice,
not fingerprint input.

**Step 4: Add a safe cross-build script**

`scripts/test-windows-build.sh` must enumerate `go list ./...`, create a
`mktemp -d` output directory, and compile each package's tests independently for
both `windows/amd64` and `windows/arm64`. It must not write `.exe` files into the
repository. Add `test-windows-build` to `Makefile`.

**Step 5: Verify and commit**

Run:

```bash
go test -race ./internal/platform ./internal/exec
./scripts/test-windows-build.sh
git diff --check
```

Expected: host tests PASS; both Windows architectures compile.

Commit:

```bash
git add internal/platform internal/exec/executor.go scripts/test-windows-build.sh Makefile
git commit -m "build: add Windows backend routing and cross-build gate"
```

### Task 4: Make policy/runtime vocabulary Windows-aware

**Files:**

- Modify: `internal/policy/effective.go`
- Create: `internal/policy/runtime_unix.go`
- Create: `internal/policy/runtime_windows.go`
- Modify: `internal/policy/effective_test.go`
- Modify: `internal/policy/fsresolve.go`
- Modify: `internal/policy/fsresolve_test.go`

**Step 1: Write Windows policy tests**

Add build-tagged tests proving a sandboxed Windows policy uses drive roots,
`NUL`, and a named `windows.runtime-baseline` rather than `/bin`, `/usr/lib`, or
`/dev/null`. Add pure path-key tests proving Windows matching is case-insensitive
and separator-insensitive without changing Unix matching.

**Step 2: Cross-build and observe failure**

Run:

```bash
./scripts/test-windows-build.sh
```

Expected: the Windows tests fail to compile or assert Unix runtime entries.

**Step 3: Split platform vocabulary**

Move `MinimalRuntimeEntries` and null-device selection behind build-tagged
helpers. The Windows policy contains only policy intent roots and the explicit
runtime-baseline marker; it does not enumerate WRP files or project ACLs onto
them. Refactor literal matching through a platform path-key helper so Windows
uses ordinal case-insensitive keys and Unix behavior remains byte-sensitive.

**Step 4: Verify and commit**

Run:

```bash
go test -race ./internal/policy
./scripts/test-windows-build.sh
```

Expected: PASS on host and cross-build.

Commit:

```bash
git add internal/policy
git commit -m "refactor: add Windows policy vocabulary"
```

## Phase 2 — Feasibility and Windows primitives

### Task 5: Prove the `S-1-5-12` runtime baseline before elevated work

**Files:**

- Create: `spikes/windows/runtime_baseline_windows_test.go`
- Create: `spikes/windows/testdata/runtimeprobe/main.go`
- Create: `docs/spikes/windows-restricted-runtime.md`
- Modify: `docs/plans/2026-07-21-windows-sandbox-design.md` only if the result
  changes a reviewed assumption

**Step 1: Build the exact-token spike**

The spike creates the proposed fully restricted primary token with Restricted
Code (`S-1-5-12`) in the restricting list and no broader ambient SID. Its table
must include the installed-runner-shaped Go helper, canonical System32
`cmd.exe`, PowerShell, Go subprocesses, every product-supported runtime, CRT/DLL
loading, locale/console startup, a DLL initializer, and a TLS callback fixture.
For every failure record the requested access, object path/identity, owner, and
DACL. Never call `SetSecurityInfo` on an OS runtime object.

**Step 2: Run on every supported disposable Windows image**

Run:

```powershell
go test -count=1 -v ./spikes/windows -run TestRestrictedRuntimeBaseline
```

Expected: either every arbitrary target starts under the exact token, or the
report names a concrete gap. “Skipped” is not a passing gate.

**Step 3: Test the only sanctioned fallback when needed**

If and only if failures are limited to the cooperative protected runner, add a
runner-only case that installs a minimally broader initial-thread impersonation
token, drops/closes it before reading an untrusted request, and proves the target
cannot duplicate or query it. Do not apply this technique to arbitrary target
executables or their loader callbacks.

**Step 4: Record the go/no-go decision**

Complete `docs/spikes/windows-restricted-runtime.md` with:

- Windows build and filesystem image;
- exact token groups, privileges, restricting SIDs, and integrity;
- runtime inventory and DACL deltas;
- selected result: exact token, trusted-runner-only bootstrap, narrowed target
  set, or elevated milestone blocked pending LPAC/AppContainer review.

**Step 5: Commit the evidence**

Run:

```bash
git diff --check
./scripts/test-windows-build.sh
```

Expected: clean diff and successful cross-build. A reviewed go/no-go result is
required before Task 13.

Commit:

```bash
git add spikes/windows docs/spikes/windows-restricted-runtime.md
git commit -m "spike: validate Windows restricted runtime baseline"
```

### Task 6: Implement handle-based Windows path identity

**Files:**

- Create: `internal/winpath/path_windows.go`
- Create: `internal/winpath/path_windows_test.go`
- Create: `internal/winpath/README.md`
- Modify: `pkg/profile/profile.go`
- Create: `pkg/profile/canonical_unix.go`
- Create: `pkg/profile/canonical_windows.go`
- Modify: `pkg/profile/profile_test.go`
- Modify: `internal/policy/binding.go`
- Create: `internal/policy/binding_windows.go`
- Create: `internal/policy/identity_windows.go`
- Create: `internal/policy/pathhandle_windows.go`
- Modify: `internal/policy/identity_other.go`
- Modify: `internal/policy/pathhandle_other.go`
- Create: `internal/policy/binding_windows_test.go`
- Modify: `internal/enforce/shell_windows.go`

**Step 1: Write canonicalization and identity tests**

Cover `C:\x`, `c:\X`, `\\?\C:\x`, 8.3 aliases, ADS, drive-relative paths,
UNC, `\\.\`, `GLOBALROOT`, volume GUIDs, junctions, symlinks, root swaps,
object type, volume serial, 128-bit file ID, reparse tag, and link count. Positive
controls prove a normal NTFS/ReFS local path opens. Tests must reject unsupported
spelling rather than normalizing it into broader authority.

**Step 2: Run on Windows and observe failure**

Run:

```powershell
go test -count=1 ./internal/winpath ./pkg/profile ./internal/policy -run Windows
```

Expected: FAIL because current code uses lexical `filepath`/`EvalSymlinks` and
Unix identity stubs.

**Step 3: Implement the leaf object-path package**

Define a handle-owned result:

```go
type Object struct {
    Handle       windows.Handle
    DOSPath      string
    PathKey      string
    VolumeSerial uint64
    FileID       [16]byte
    Kind         Kind
    ReparseTag   uint32
    LinkCount    uint32
}
```

Open with `FILE_FLAG_BACKUP_SEMANTICS` and
`FILE_FLAG_OPEN_REPARSE_POINT`, obtain the final DOS volume path and identity
from the handle, compare with ordinal case-insensitive semantics, and make
ownership/close explicit. Reject remote/unsupported filesystems and namespace
spellings before use.

**Step 4: Wire profile and grant binding without a cycle**

`pkg/profile` may import the leaf `internal/winpath`; `internal/winpath` must not
import `pkg/profile`, `internal/policy`, or `internal/windows`. Split the Unix
`CanonicalRoot` body from `profile.go`. Make Windows `PathBinding` and
`PathHandle` retain the no-follow object handle and compare the complete object
identity on revalidation. Replace Task 1's bootstrap System32 resolver with this
handle-validated path service so `RunCommand` never trusts `%ComSpec%` or an
unverified executable path.

**Step 5: Verify and commit**

Run:

```bash
go test -race ./pkg/profile ./internal/policy
./scripts/test-windows-build.sh
```

Run on Windows:

```powershell
go test -race -count=1 ./internal/winpath ./pkg/profile ./internal/policy
```

Expected: PASS.

Commit:

```bash
git add internal/winpath pkg/profile internal/policy
git commit -m "feat: add identity-bound Windows path handling"
```

### Task 7: Enforce explicit child handle inheritance

**Files:**

- Create: `internal/windows/handlelist_windows.go`
- Create: `internal/windows/handlelist_windows_test.go`
- Create: `internal/windows/testdata/handleprobe/main.go`
- Modify: `internal/exec/executor.go`

**Step 1: Write allowlist and live canary tests**

Create inheritable canaries for a writable file, directory, Job, token, pipe,
and event. Launch the helper with only stdin/stdout/stderr allowed. The helper
enumerates its own handle table and reports type/access for each handle. Assert
that standard I/O works and no canary is present. Add a runner-shaped case where
the sealed request read handle is present in the runner but absent in its target.

**Step 2: Run and observe failure**

Run on Windows:

```powershell
go test -count=1 ./internal/windows -run 'HandleList|InheritedHandleCanary'
```

Expected: FAIL because process creation has no explicit handle-list invariant.

**Step 3: Implement the shared launch attribute**

Build `STARTUPINFOEX` with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Create handles
non-inheritable by default; duplicate only declared handles with minimum access
and the inheritance bit required by the API. Pass `bInheritHandles=TRUE` only
with a non-empty explicit list. Reject pseudo handles, duplicates with wider
access, and any failure to initialize/update the attribute list.

Expose a narrow Windows-only configure helper to `internal/exec`; do not move
generic command execution into `internal/windows`. Ensure token, Job,
canonicalization, ACL/journal/state, broker, and proxy handles are never added.

**Step 4: Verify and commit**

Run:

```bash
./scripts/test-windows-build.sh
```

Run on Windows:

```powershell
go test -race -count=1 ./internal/windows ./internal/exec -run 'Handle|Spawn'
```

Expected: PASS.

Commit:

```bash
git add internal/windows internal/exec/executor.go
git commit -m "feat: restrict Windows handle inheritance"
```

### Task 8: Harden the shared Windows Job Object

**Files:**

- Create: `internal/windows/job_windows.go`
- Create: `internal/windows/job_windows_test.go`
- Modify: `internal/exec/process_tree_windows.go`
- Modify: `internal/exec/process_tree_other.go`
- Modify: `internal/exec/executor.go`
- Create: `internal/exec/process_tree_windows_test.go`

**Step 1: Write failing Job configuration tests**

Test read-back of:

- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`;
- no `BREAKAWAY_OK` or `SILENT_BREAKAWAY_OK`;
- active-process, memory, and CPU hard-cap limits when requested;
- every UI restriction named in design §8 for sandboxed Windows processes;
- no sandbox UI restrictions for explicitly unconfined execution.

Add a nested helper that attempts `CREATE_BREAKAWAY_FROM_JOB`, writes a delayed
marker from a grandchild, and verifies cancellation/host death prevents it.

**Step 2: Run and observe failure**

Run on Windows:

```powershell
go test -count=1 ./internal/windows ./internal/exec -run 'Job|ProcessTree'
```

Expected: FAIL because the existing Job has only kill-on-close and lacks UI and
resource configuration.

**Step 3: Implement Job options and ordering**

Pass immutable process-tree options from the execution snapshot:

```go
type processTreeOptions struct {
    Sandboxed bool
    Limits    policy.Limits
}
```

Create/configure the Job before starting the suspended process, assign before
resume, terminate on every setup failure, and retain the Job handle until active
process count reads zero. Report `GuaranteeResourceLimits` only when all
requested limits are installed/read back and an end-to-end process guarantee is
otherwise present.

**Step 4: Verify and commit**

Run:

```bash
./scripts/test-windows-build.sh
```

Run on Windows:

```powershell
go test -race -count=1 ./internal/windows ./internal/exec -run 'Job|ProcessTree|ResourceLimit'
```

Expected: PASS.

Commit:

```bash
git add internal/windows/job_windows.go internal/windows/job_windows_test.go internal/exec
git commit -m "feat: harden Windows Job containment"
```

## Phase 3 — No-admin restricted-token tier

### Task 9: Build restricting SIDs, restricted tokens, and ACL plans

**Files:**

- Create: `internal/windows/sid.go`
- Create: `internal/windows/sid_test.go`
- Create: `internal/windows/token_windows.go`
- Create: `internal/windows/token_windows_test.go`
- Create: `internal/windows/acl_plan.go`
- Create: `internal/windows/acl_plan_test.go`

**Step 1: Write pure SID/ACL-plan tests**

Pin deterministic installation/executor SID namespaces, cryptographically
random one-shot SIDs, never-reuse behavior, ACE ordering, read/write axis
separation, carveout denies before inherited allows, no reparse traversal, and
multi-link denial. An exact grant to a multi-link file must return
`ErrGrantUnsupported`; a tree plan must record
`windows.filesystem.hardlink` narrowing.

**Step 2: Write live token-shape tests**

On Windows, create the restricted-tier token and assert:

- `DISABLE_MAX_PRIVILEGE`, `LUA_TOKEN`, and `WRITE_RESTRICTED`;
- dangerous privileges/groups removed;
- executor/grant SIDs appear only in the restricting list;
- integrity is unchanged;
- the target token cannot enable a removed privilege.

**Step 3: Run and observe failure**

Run:

```bash
go test ./internal/windows -run 'SID|ACLPlan' -count=1
./scripts/test-windows-build.sh
```

Run the live token test on Windows. Expected: FAIL before implementation.

**Step 4: Implement least-authority token and plans**

Use `CreateRestrictedToken` and explicit token-information read-back. ACL plans
contain object identity, expected link count/type, exact ACE bytes, and rollback
metadata; they do not carry trusted path strings alone. Do not modify any DACL
in this task.

**Step 5: Verify and commit**

Run host pure tests, the Windows cross-build, and the live Windows token tests.
Expected: PASS.

Commit:

```bash
git add internal/windows/sid.go internal/windows/sid_test.go internal/windows/token_windows.go internal/windows/token_windows_test.go internal/windows/acl_plan.go internal/windows/acl_plan_test.go
git commit -m "feat: plan restricted Windows tokens and ACLs"
```

### Task 10: Apply and roll back restricted ACL projections

**Files:**

- Create: `internal/windows/acl_windows.go`
- Create: `internal/windows/acl_windows_test.go`
- Create: `internal/windows/restricted_journal.go`
- Create: `internal/windows/restricted_journal_test.go`

**Step 1: Write transactional ACL tests**

On a disposable NTFS tree, test exact/tree projection, inheritance, carveout
denies, reparse skipping, hard-link denial, DACL read-back, injected failure at
every mutation index, concurrent unrelated user DACL changes, and cleanup that
removes only matching lease ACEs. Use a positive control showing the current
user can modify the test tree without restriction.

**Step 2: Write crash-journal tests**

The restricted journal lives below the caller's stable scratch root, outside
the executor-set child that normal close removes. Test write+flush-before-ACL,
normal removal, next-construction sweep, corrupt/deleted journal tolerance,
file-ID mismatch refusal, retired SID persistence, and opportunistic pruning of
recognized inert ACEs. Journal content may authorize cleanup only, never access.

**Step 3: Run and observe failure**

Run on Windows:

```powershell
go test -count=1 ./internal/windows -run 'ACLProjection|RestrictedJournal'
```

Expected: FAIL because projection and journal types are not implemented.

**Step 4: Implement handle-bound mutation and rollback**

Use `GetSecurityInfo`/`SetSecurityInfo` on retained handles. Insert exact ACEs,
read them back, and rollback in reverse order. Never replace a saved whole DACL.
Reject ownership/identity/link-count changes between planning and mutation.
Flush journal state before each mutation and remove the record only after its ACE
is confirmed absent.

**Step 5: Verify and commit**

Run:

```bash
./scripts/test-windows-build.sh
```

Run the focused live Windows tests with `-race -count=1`. Expected: PASS.

Commit:

```bash
git add internal/windows/acl_windows.go internal/windows/acl_windows_test.go internal/windows/restricted_journal.go internal/windows/restricted_journal_test.go
git commit -m "feat: add transactional restricted ACL leases"
```

### Task 11: Compile and select the restricted-token backend

**Files:**

- Create: `internal/windows/backend_windows.go`
- Create: `internal/windows/backend_windows_test.go`
- Modify: `internal/windows/setup_other.go`
- Modify: `internal/platform/platform_windows.go`
- Modify: `internal/exec/executor_set.go`
- Modify: `internal/exec/executor.go`
- Create: `internal/exec/windows_selection_test.go`

**Step 1: Write compile/selection matrices**

For `WindowsRestrictedToken`, assert the compiler always reports `LevelNone`
and only executor-owned `GuaranteeEnvScrub`; direct Job/token/UI/ACL mechanisms
appear as narrowed defense-in-depth report entries. It never claims read,
network, process, write, or resource bits.

For `WindowsAuto` with elevated setup absent, assert selection succeeds only
when `profile.Settings().RequiredGuarantees` is covered by the restricted bits.
Profiles requiring write/read/network fail with typed
`ErrWindowsSetupRequired` naming the missing guarantees. Explicit restricted
mode never contacts the broker.

**Step 2: Run and observe failure**

Run:

```bash
./scripts/test-windows-build.sh
```

Run on Windows:

```powershell
go test -count=1 ./internal/windows ./internal/exec -run 'RestrictedCompile|WindowsAuto'
```

Expected: FAIL because the backend selector is still a stub.

**Step 3: Implement compile ownership**

At compile time, canonicalize supported roots, sweep the restricted cleanup
journal, generate the never-reused executor SID, project the base ACL lease,
and return a spec whose `Release` is idempotent. `Wrap` creates a fresh
restricted token per spawn and applies only explicit handles/process attributes.
Any partial compile releases its lease before returning.

**Step 4: Keep unsupported classes closed**

Return `ErrGrantUnsupported` for host-wide filesystem grants, nonexistent exact
targets, exact directories, multi-link exact files, remote/unsupported roots,
and every network grant. Do not turn any exact target into a parent tree.

**Step 5: Verify and commit**

Run the host suite, cross-build, and standard-user Windows focused tests.
Expected: PASS.

Commit:

```bash
git add internal/windows internal/platform/platform_windows.go internal/exec
git commit -m "feat: add no-admin Windows restricted backend"
```

### Task 12: Establish the restricted adversarial suite

**Files:**

- Create: `internal/windows/restricted_integration_windows_test.go`
- Create: `internal/windows/broker_escape_windows_test.go`
- Create: `internal/windows/testdata/escapeprobe/main.go`
- Create: `internal/exec/acceptance_windows_test.go`
- Modify: `pkg/sandboxtest/sandboxtest.go`
- Create: `pkg/sandboxtest/shell_unix.go`
- Create: `pkg/sandboxtest/shell_windows.go`

**Step 1: Make conformance shell-aware**

Replace `/bin/sh` quoting and `env` assumptions with build-tagged helpers.
Windows helpers use direct argv where possible and canonical System32
`cmd.exe /D /S /C` only for shell-specific probes. Add reusable read, process,
network, and resource implication checks gated on claimed bits.

**Step 2: Add direct restricted cases**

Test inside writes; denied direct writes to profile/sibling/`.git`/state/other
drive; ordinary descendants in the Job; cancellation; UI and breakaway
read-back; junction/symlink/root-swap; hard links; case/extended/8.3/ADS/device;
handle canaries; journal recovery; and never-reused stale SID ACEs. Every denial
test has an unconfined positive control.

**Step 3: Add broker-escape cases**

Run Explorer `IShellDispatch.ShellExecute`, PowerShell `Start-Process`, WMI
`Win32_Process.Create`, `schtasks`, COM activation/elevation, GUI launch, and
named-pipe broker attempts as isolated subprocess cases with an external
watchdog. A successful broker escape is recorded and cleaned up; it must not
make the suite fail merely because restricted mode intentionally withholds the
affected bits. The suite fails if the backend claims a bit those probes bypass.

**Step 4: Run the standard-user gate**

Run on a disposable standard-user Windows worker with no elevated installation:

```powershell
go test -race -count=1 ./pkg/sandboxtest ./internal/windows ./internal/exec -run 'Restricted|Sandboxtest|BrokerEscape'
```

Expected: PASS, with explicit broker outcomes and no process/marker left behind.

**Step 5: Commit the restricted tier checkpoint**

```bash
git add pkg/sandboxtest internal/windows internal/exec/acceptance_windows_test.go
git commit -m "test: establish restricted Windows adversarial coverage"
```

At this checkpoint the restricted tier is independently shippable, but auto
mode must still require elevated setup for write/read/network-restricted
profiles.

## Phase 4 — Installed elevated tier

### Task 13: Define and fuzz the broker protocol before service code

**Gate:** Start only after Task 5 records an approved runtime baseline.

**Files:**

- Create: `internal/windows/protocol.go`
- Create: `internal/windows/protocol_test.go`
- Create: `internal/windows/protocol_fuzz_test.go`
- Create: `internal/windows/pipe_windows.go`
- Create: `internal/windows/pipe_windows_test.go`

**Step 1: Write codec tests and fuzz seeds**

Pin a length-prefixed protocol version, message kinds, maximum frame/path/count
sizes, strict enum decoding, duplicate-field rejection, UTF-16 validation, and
unknown-version failure. Requests may carry duplicated object handles or
canonical path metadata, never a password or unrestricted token.

**Step 2: Write pipe authentication tests**

Test a DACL limited to SYSTEM, Administrators, and the configured owner SID;
real client PID/token lookup; process creation-time binding; owner mismatch;
AppContainer rejection; installation restricting-SID rejection; disconnect
cleanup; and PID-reuse simulation.

**Step 3: Run and observe failure**

Run pure tests/fuzz smoke on the host and pipe tests on Windows. Expected: FAIL
before implementation.

**Step 4: Implement the smallest protocol and authenticated transport**

Initial operations are exactly status, acquire/release lease, issue restricted
token handle for an existing lease, and reconcile. Do not add arbitrary process
launch, arbitrary ACL, arbitrary firewall, or raw-token operations. Bind every
lease to connection nonce + real PID + creation time + process handle.

**Step 5: Verify and commit**

Run:

```bash
go test -race ./internal/windows -run 'Protocol'
go test ./internal/windows -run '^$' -fuzz=FuzzBrokerFrame -fuzztime=30s
./scripts/test-windows-build.sh
```

Run live pipe tests on Windows. Expected: PASS.

Commit:

```bash
git add internal/windows/protocol.go internal/windows/protocol_test.go internal/windows/protocol_fuzz_test.go internal/windows/pipe_windows.go internal/windows/pipe_windows_test.go
git commit -m "feat: add authenticated Windows broker protocol"
```

### Task 14: Implement setup manifest, status, and protected host installation

**Files:**

- Create: `internal/windows/manifest.go`
- Create: `internal/windows/manifest_test.go`
- Create: `internal/windows/setup_windows.go`
- Create: `internal/windows/setup_windows_test.go`
- Create: `internal/windows/host_install_windows.go`
- Create: `cmd/sandbox-host/main_windows.go`
- Create: `cmd/sandbox-host/main_other.go`

**Step 1: Write setup/status state-machine tests**

Cover absent, staging, ready, stale, and recovery-pending states. Pin typed
problems for missing manifest, owner mismatch, stale binary, service down,
missing account/credential, firewall override/change, port owner PID, runtime
gap, lease recovery, and protocol mismatch. Assert `Detail` contains no test
secret and consumers can branch only on `Code`.

**Step 2: Write protected-host tests**

Use a disposable ProgramData-like test root. Test copy-to-staging, SHA-256
manifest, owner/SYSTEM/Admin DACL, sandbox read/execute only, atomic ready
replacement, source mutation after setup, stale hash detection, and rollback on
every injected step. Never execute the caller-supplied source path at runtime.

**Step 3: Run and observe failure**

Run pure manifest tests and elevated Windows setup tests. Expected: FAIL before
implementation.

**Step 4: Implement transaction boundaries**

Validate elevation, installation ID, owner SID, local ProgramData state root,
host binary, and proxy ports. Stage protected files and manifest, perform
self-tests through injectable mechanism interfaces, then atomically mark ready.
Inspection is read-only and works unelevated. Partial setup never reports ready.

**Step 5: Verify and commit**

Run host pure tests, cross-build, and elevated disposable-root tests. Expected:
PASS.

Commit:

```bash
git add internal/windows/manifest.go internal/windows/manifest_test.go internal/windows/setup_windows.go internal/windows/setup_windows_test.go internal/windows/host_install_windows.go cmd/sandbox-host
git commit -m "feat: add transactional Windows host installation"
```

### Task 15: Provision accounts, credentials, service, and removal

**Files:**

- Create: `internal/windows/account_windows.go`
- Create: `internal/windows/account_windows_test.go`
- Create: `internal/windows/dpapi_windows.go`
- Create: `internal/windows/dpapi_windows_test.go`
- Create: `internal/windows/service_windows.go`
- Create: `internal/windows/service_windows_test.go`
- Modify: `internal/windows/setup_windows.go`
- Modify: `cmd/sandbox-host/main_windows.go`

**Step 1: Write elevated lifecycle tests**

On a disposable VM, test deterministic hash-derived account/service names,
random non-expiring passwords, non-admin membership, hidden UI state, denied
interactive/remote/network logon, minimum service logon right, restricted
service SID, failure actions, LocalSystem user-scope DPAPI, and ciphertext ACLs.
Assert the interactive user and sandbox account cannot read/decrypt credential
state.

**Step 2: Write idempotence/removal tests**

Setup twice preserves identity when valid; refresh rotates passwords and
advances version transactionally. Removal verifies manifest-owned targets,
stops/deletes service, removes only owned rights/accounts/state, and reports
residual objects. Inject failure at every step and prove retry convergence.

**Step 3: Run and observe failure**

Run on an elevated disposable Windows worker with a final cleanup block.
Expected: FAIL before implementation.

**Step 4: Implement narrow Win32 wrappers**

Wrap NetAPI/local security authority, DPAPI, and service-control operations in
small interfaces with real Windows and fake test implementations. Zero password
buffers immediately after logon/DPAPI use. Never return an unrestricted account
token or credential to the host process.

**Step 5: Verify and commit**

Run focused elevated tests, then inspect that no test account/service/state is
left. Expected: PASS and empty residue report.

Commit:

```bash
git add internal/windows/account_windows.go internal/windows/account_windows_test.go internal/windows/dpapi_windows.go internal/windows/dpapi_windows_test.go internal/windows/service_windows.go internal/windows/service_windows_test.go internal/windows/setup_windows.go cmd/sandbox-host/main_windows.go
git commit -m "feat: provision Windows sandbox identities and service"
```

### Task 16: Install and verify account-scoped firewall rules

**Files:**

- Create: `internal/windows/firewall_windows.go`
- Create: `internal/windows/firewall_windows_test.go`
- Create: `internal/windows/ports_windows.go`
- Create: `internal/windows/ports_windows_test.go`
- Modify: `internal/windows/setup_windows.go`

**Step 1: Write rule-model tests**

Pin installation-owned rule names and the exact offline-account rules: block
non-loopback outbound protocols, block loopback UDP, block loopback TCP except
the configured proxy ports, all profiles, correct account SID. Read-back must
compare identity, enabled state, profile, direction, action, protocol,
address/port sets, and account SID. Group Policy override is a typed unhealthy
status, never a warning-only state.

**Step 2: Write port-lock tests**

Bind all configured ports before construction, keep deny-only guards on unused
ports, fail if any port is owned, report PID when safely available, and serialize
one host process per installation. Test partial-bind rollback and concurrent
constructors.

**Step 3: Run and observe failure**

Run rule-model tests on host/cross-build and live enforcement tests on an
elevated disposable Windows worker. Expected: FAIL before implementation.

**Step 4: Implement install/read-back/remove**

Use the documented Windows Firewall API through narrow wrappers. Setup first
installs the broad fail-closed blocks, then narrows loopback TCP to the verified
port complement. Construction re-verifies every field. Removal deletes only
manifest-owned rule identities.

**Step 5: Verify and commit**

Use parent-side loopback and non-loopback listeners as positive controls; no
external Internet is required. After tests, assert no rules/listeners remain.

Commit:

```bash
git add internal/windows/firewall_windows.go internal/windows/firewall_windows_test.go internal/windows/ports_windows.go internal/windows/ports_windows_test.go internal/windows/setup_windows.go
git commit -m "feat: enforce offline Windows account egress"
```

### Task 17: Implement broker leases and restricted token issuance

**Files:**

- Create: `internal/windows/broker_windows.go`
- Create: `internal/windows/broker_windows_test.go`
- Create: `internal/windows/lease_journal_windows.go`
- Create: `internal/windows/lease_journal_windows_test.go`
- Create: `internal/windows/broker_client_windows.go`
- Create: `internal/windows/broker_client_windows_test.go`
- Modify: `cmd/sandbox-host/main_windows.go`

**Step 1: Write authorization tests**

The broker may add only the installation account SID and broker-generated
restricting SIDs, and only while impersonating an authenticated pipe client that
could change the DACL itself. Test forged paths/PIDs/handles, other-installation
SIDs, arbitrary ACEs, unrestricted token requests, missing lease, replayed
nonce, dead client, and protocol downgrade.

**Step 2: Write durable lease tests**

Pin journal write/flush order, exact inserted ACE bytes, object identities,
rollback, client pipe death, parent process death, service restart, startup
reconciliation before token service, and never-reused SIDs. Cleanup must preserve
concurrent unrelated DACL edits.

**Step 3: Run and observe failure**

Run pure state-machine tests and live elevated broker tests. Expected: FAIL
before implementation.

**Step 4: Implement minimal service operations**

The service handles only the protocol operations defined in Task 13. It logs on
the offline/online account internally, creates the full restricted primary token,
duplicates only that restricted token handle into the authenticated client, and
closes/zeros all unrestricted account material before responding.

**Step 5: Verify and commit**

Kill clients and restart the service during tests, then assert journal/ACE
reconciliation. Expected: PASS.

Commit:

```bash
git add internal/windows/broker_windows.go internal/windows/broker_windows_test.go internal/windows/lease_journal_windows.go internal/windows/lease_journal_windows_test.go internal/windows/broker_client_windows.go internal/windows/broker_client_windows_test.go cmd/sandbox-host/main_windows.go
git commit -m "feat: add Windows sandbox broker leases"
```

### Task 18: Add the protected runner and private desktop

**Files:**

- Create: `internal/windows/desktop_windows.go`
- Create: `internal/windows/desktop_windows_test.go`
- Create: `internal/windows/runner_windows.go`
- Create: `internal/windows/runner_windows_test.go`
- Modify: `cmd/sandbox-host/main_windows.go`

**Step 1: Write runner protocol/handle tests**

Pass normalized argv, cwd, desktop name, and nonce over a sealed inherited
read-only pipe. Test malformed/oversized requests, missing nonce, shell-free argv,
exit-code forwarding, standard I/O, request-handle removal before target launch,
and absence of token/Job/desktop/broker/state handles in the target.

**Step 2: Write private desktop tests**

The broker creates and ACLs the window station/desktop before the UI-limited Job
starts. Test that the runner/target use it, cannot switch to the interactive
desktop, and fail closed on creation/open/ACL errors. Include GUI positive and
negative controls.

**Step 3: Add the approved bootstrap only if Task 5 selected it**

If the spike approved trusted-runner initialization, install the temporary
thread impersonation token only around trusted startup. Assert and read back
that no thread token remains before request parsing, then close the handle. If
Task 5 selected the exact token, do not add dormant bootstrap code.

**Step 4: Run and observe failure, then implement**

Run the focused elevated Windows runner tests. Expected initial FAIL; implement
the minimum runner/desktop behavior and rerun until PASS.

**Step 5: Commit**

```bash
git add internal/windows/desktop_windows.go internal/windows/desktop_windows_test.go internal/windows/runner_windows.go internal/windows/runner_windows_test.go cmd/sandbox-host/main_windows.go
git commit -m "feat: add protected Windows sandbox runner"
```

### Task 19: Compile the elevated filesystem and process guarantees

**Files:**

- Create: `internal/windows/elevated_backend_windows.go`
- Create: `internal/windows/elevated_backend_windows_test.go`
- Modify: `internal/windows/backend_windows.go`
- Modify: `internal/platform/platform_windows.go`
- Modify: `internal/exec/executor.go`
- Create: `internal/exec/elevated_windows_test.go`

**Step 1: Write elevated compile matrices**

Test offline/online account selection, full restricting SIDs, explicit runtime
baseline report, executor/grant lease ownership, setup status validation, runner
hash, private desktop, Job/process bits, read/write bits, resource limits, and
auto preference. `LevelFull` requires every requested axis; safe narrowing with
all required guarantees yields `LevelDegraded`.

**Step 2: Write filesystem live matrices**

Cover exact/tree read/write allows and denies, protected carveouts, case,
extended paths, ADS, junction/symlink/root swap, races, multi-link tree denial,
unsupported exact hard links, other drive, unsupported filesystems, UNC/device,
and WRP baseline audit. Every case includes an unrestricted or installation-
account positive control.

**Step 3: Run and observe failure**

Run cross-build and elevated focused tests. Expected: FAIL before compiler
implementation.

**Step 4: Implement fail-closed construction**

Validate status and runtime baseline, acquire broker ACL lease, request only the
restricted account token handle, create the sealed runner request, and return a
compiled spec whose release closes the lease after the Job empties. Any hash,
firewall, DACL, token, desktop, handle-list, Job, or broker mismatch fails before
resume. Never fall back to the interactive user.

**Step 5: Verify and commit**

Run the full elevated filesystem/process suite and removal verification.
Expected: PASS and no residual lease.

Commit:

```bash
git add internal/windows/elevated_backend_windows.go internal/windows/elevated_backend_windows_test.go internal/windows/backend_windows.go internal/platform/platform_windows.go internal/exec
git commit -m "feat: add elevated Windows filesystem sandbox"
```

### Task 20: Integrate target-scoped proxy networking and grant leases

**Files:**

- Modify: `internal/windows/elevated_backend_windows.go`
- Create: `internal/windows/network_windows_test.go`
- Modify: `internal/exec/executor_set.go`
- Modify: `internal/exec/executor.go`
- Modify: `internal/exec/grant.go`
- Modify: `internal/exec/grant_v1_test.go`
- Modify: `pkg/network/proxy.go`
- Modify: `pkg/network/proxy_test.go`

**Step 1: Write network posture tests**

Offline mode must deny direct non-loopback TCP/UDP, DNS, metadata, loopback
non-proxy ports, PowerShell web requests, curl, Python sockets, and operation
after proxy variables are removed. Approved HTTP/CONNECT targets succeed through
the authenticated listener; unapproved host/port and direct-address attempts
fail. Online mode allows network and claims no network boundary.

**Step 2: Write grant/release tests**

`network.proxy-target.v1` compiles only for the verified offline posture.
Concurrent executions have independent credentials and grant SIDs. Grant spec
release occurs after Job-empty and closes active forward/CONNECT traffic.
`network.broad.v1` and host-wide filesystem grants return
`ErrGrantUnsupported` without consuming the token or widening base policy.

**Step 3: Run and observe failure**

Run existing proxy tests, cross-build, and live elevated network tests. Expected:
initial FAIL because the Windows backend does not compose the port lock/firewall
with the proxy.

**Step 4: Implement composition**

Bind every configured port before offline executor construction. Attach the
existing authenticated proxy to one port and deny-only guard listeners to the
rest. Authorize exactly one normalized target per execution, inject only
execution credentials, and report `NetworkBoundary` + `TargetNetwork`;
`AddressNetwork` remains conditional on the selected route contract.

**Step 5: Verify and commit**

Run host proxy tests and the disposable-worker elevated network suite with local
listeners only. Expected: PASS and all credentials/tunnels/listeners released.

Commit:

```bash
git add internal/windows/elevated_backend_windows.go internal/windows/network_windows_test.go internal/exec pkg/network
git commit -m "feat: add target-scoped Windows sandbox egress"
```

## Phase 5 — Acceptance, CI, and package documentation

### Task 21: Complete elevated adversarial and recovery coverage

**Files:**

- Create: `internal/windows/elevated_integration_windows_test.go`
- Create: `internal/windows/setup_integration_windows_test.go`
- Create: `internal/windows/recovery_integration_windows_test.go`
- Modify: `internal/exec/acceptance_windows_test.go`
- Modify: `pkg/sandboxtest/sandboxtest.go`

**Step 1: Add the end-to-end matrix**

Cover every design §14.4 case: setup corruption/staleness; credential/state
protection; read/write matrices and races; unsupported roots/classes; offline,
target, and online network; private desktop; Explorer/shell/WMI/COM/scheduled
task launch; detached flags; Job limits; handle enumeration; concurrency; client
death; service restart; refresh; and removal.

**Step 2: Assert guarantee implications, not mechanism anecdotes**

For every claimed bit, run all direct and brokered probes that could bypass it.
A single successful outside operation is a suite failure. For restricted mode,
the same broker probes justify absent bits and are watchdog-cleaned. Every
negative probe has a positive control outside the relevant boundary.

**Step 3: Stress races**

Repeat identity swap, reparse insertion, DACL edits, grant expiry, executor
close, proxy release, broker disconnect, context cancellation, and host death
hundreds of times. Use `-race` where compatible and a separate non-race
process-stress invocation when the race runtime changes timing.

**Step 4: Run the full disposable-worker gate**

Run:

```powershell
go test -race -count=1 ./...
go test -count=100 ./internal/windows -run 'Race|Recovery|BrokerEscape'
```

Expected: PASS. Final cleanup inspection must report no accounts, service,
firewall rules, journal entries, active processes, or meaningful lease ACEs.

**Step 5: Commit**

```bash
git add internal/windows internal/exec/acceptance_windows_test.go pkg/sandboxtest/sandboxtest.go
git commit -m "test: complete Windows sandbox acceptance coverage"
```

### Task 22: Add CI gates and package READMEs

**Files:**

- Create: `internal/windows/README.md`
- Create: `cmd/sandbox-host/README.md`
- Create: `pkg/sandboxtest/README.md`
- Modify: `internal/winpath/README.md`
- Modify: `README.md`
- Modify: `doc.go`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

**Step 1: Write package documentation**

`internal/windows/README.md` documents ownership, tier guarantees, file map,
setup/broker trust boundary, cleanup invariants, supported Windows/filesystems,
and how to run standard/elevated suites. `internal/winpath/README.md` documents
handle ownership and rejected namespaces. `cmd/sandbox-host/README.md` explains
service versus runner mode and protocol limits. `pkg/sandboxtest/README.md`
documents the structural `SUT`, one-way guarantee assertions, platform shell
helpers, and how external consumers reuse it.

**Step 2: Update existing root documentation only**

Update the existing root `README.md` module tree to list `internal/windows`,
`internal/winpath`, and `cmd/sandbox-host`; add the public Windows mode/setup
example, guarantee table, one-host-process v1 limitation, supported filesystems,
and cleanup command. Update `doc.go` to mention Windows alongside Darwin/Linux.
Do not create any additional root document or Go file.

**Step 3: Add three CI gates**

- `windows-cross-compile`: both architectures, every package/test binary.
- `windows-restricted`: standard user, no installed broker, conformance and
  broker-escape suite.
- `windows-elevated`: disposable elevated worker, setup + full adversarial suite
  + unconditional cleanup/status verification.

An unavailable requested mechanism fails the job. A skip is allowed only for a
named, detected Windows edition/API limitation recorded in the test and compile
report.

**Step 4: Run documentation and repository verification**

Run:

```bash
go test -race ./...
./scripts/test-windows-build.sh
make lint
git diff --check
```

Expected: PASS. Then run both live Windows jobs and require their cleanup
reports to be empty.

**Step 5: Commit**

```bash
git add internal/windows/README.md internal/winpath/README.md cmd/sandbox-host/README.md pkg/sandboxtest/README.md README.md doc.go Makefile scripts/test-windows-build.sh .github/workflows/ci.yml
git commit -m "docs: publish Windows sandbox operations and CI gates"
```

### Task 23: Final security review and release gate

**Files:**

- Modify only files identified by review findings
- Update: `docs/plans/2026-07-21-windows-sandbox-design.md` when an accepted
  finding changes the guarantee contract
- Update: `SPEC.md` when the canonical implemented contract changes

**Step 1: Perform two independent reviews**

Use @superpowers:requesting-code-review for spec/guarantee compliance and a
second review focused on Win32 handle/token/ACL/service/firewall cleanup. Review
the final diff from the commit before Task 1, not only the last task.

**Step 2: Re-run threat-model probes for every finding**

Use @superpowers:receiving-code-review and
@superpowers:systematic-debugging. Reproduce each claimed gap with a positive
control before changing code. Add the failing regression test first.

**Step 3: Run the complete verification matrix fresh**

Run host race/lint/vulnerability gates, both Windows cross-build architectures,
the standard-user Windows suite, and the elevated setup/adversarial/removal
suite. Record exact job URLs or logs in the release handoff.

**Step 4: Check the acceptance checklist line by line**

Confirm design §17, including typed setup problems, the runtime feasibility
record, explicit handle lists, restricted absent bits, elevated claimed bits,
unsupported-class failures, credential secrecy, lease recovery, process cleanup,
and unchanged Darwin/Linux behavior.

**Step 5: Commit review fixes and hand off**

Use @superpowers:verification-before-completion before claiming completion and
@superpowers:finishing-a-development-branch to choose merge/PR/cleanup. Do not
promote a guarantee bit or mark elevated mode ready while any corresponding live
probe is missing or skipped.

## Explicitly deferred work

Do not implement these items as part of this plan:

- LPAC/AppContainer strong unelevated tier;
- per-execution WFP filters or multi-host-process elevated installations;
- `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED` exact-command grants;
- `network.broad.v1` on Windows;
- UNC/SMB, FAT/exFAT, raw-device, or arbitrary object-manager roots;
- AppContainer loopback exemption or alternate target-proxy transport.

They remain reviewed v2 directions in design §16.1-§16.2. Discovering that an
elevated v1 guarantee depends on one of them blocks the affected milestone and
requires a design/SPEC revision; it does not expand this plan automatically.
