# SPIKE: go-landlock through a stage-2 re-exec (Task M2)

Throwaway investigation proving the Linux confinement primitive the Task 11/12
sandbox backend is built on: a **re-exec'd stage-2 child** that applies a
go-landlock read-only rule to a directory gets **`EACCES` on write** there,
while the **parent process is unaffected**. This validates the architecture
where the sandbox re-execs `/proc/self/exe` as a stage-2 helper and applies
Landlock in the child *before* exec'ing the target: confinement is child-local
and survives the re-exec.

Code: `spikes/landlock/landlock_reexec_linux_test.go` (build tag `//go:build
linux`, package `landlockspike`, isolated from the shipped root
`package sandbox`).

## Environment

| | |
|---|---|
| Kernel | 6.8.0-63-generic |
| Landlock | ABI **v4** enabled — `landlock` present in `/sys/kernel/security/lsm` (`lockdown,capability,landlock,yama,apparmor`) |
| Probe | `syscall.LandlockGetABIVersion()` → `4` (no error) |
| Unprivileged userns | blocked on this host — **irrelevant**; Landlock needs no userns, so the spike RUNS here (does not skip) |
| Go | 1.26.4 |
| Dep | `github.com/landlock-lsm/go-landlock v0.9.0` (pure-Go, no cgo required) |

## What was proven

A single test, `TestLandlockReexecReadOnly`, drives the **full two-hop flow the
real backend uses**, via a `TestMain` multiplexer keyed on env sentinels:

1. The parent re-execs the test binary (`exec.Command(os.Args[0])`) with the
   `LRSANDBOX_SPIKE_STAGE2` sentinel + two `t.TempDir()` paths.
2. The **stage-2 child** applies Landlock and then `syscall.Exec`'s the
   **target** (a second, fresh image of the same binary in `…_TARGET` mode). It
   runs no probes itself — it only applies the restriction and execve's.
3. The **target** runs under the ruleset **inherited across that execve**, runs
   three filesystem probes, prints `KEY=VALUE` markers, and exits.

This mirrors the backend exactly — *re-exec stage-2 → apply Landlock → `execve`
the command → command runs confined* — so a passing RO-write denial in the
target proves the ruleset **survives the second execve**, not merely that it
applied in the stage-2 process. The parent parses the markers and makes a
**4-way anti-fail-open assertion**:

| # | Assertion | How verified |
|---|---|---|
| 1 | **Target write under RO** dir is denied with `EACCES` | Target `os.OpenFile(O_CREATE\|O_WRONLY)` under `roDir`; `errors.Is(err, syscall.EACCES)` → marker `RO_WRITE=EACCES`. Passing this proves the ruleset survived execve into the target |
| 2 | **Target write under RW** dir still succeeds | Same open under `rwDir` succeeds → `RW_WRITE=OK`. Proves the deny is **path-scoped, not blanket** |
| 3 | **Target read of an existing RO** file still succeeds | Parent seeds `roDir/existing.txt`; target `os.ReadFile` → `RO_READ=OK` |
| 4 | **Parent** can still write under the same RO dir | After the child tree exits, parent `os.WriteFile(roDir/parent_write.txt)` returns nil → confinement did **not** leak into the parent (child-local) |

The `APPLY=OK` marker is emitted by the target: reaching the target at all proves
Landlock applied AND execve of a fresh image succeeded under the restriction (the
"/" read+exec grant keeps the binary + loader executable). Assertions 2–4 are the
discipline: a naive test that only checked "target write failed" (assertion 1)
would pass even if Landlock denied **everything**, or if the parent were also
confined. The positive-capability checks make a fail-open impossible to mistake
for a pass.

To keep the target executable across the execve, the stage-2 child grants
`RODirs("/")` (read+exec on the whole tree — the same broad-host-read shape the
real `write` mode uses) plus `RWDirs(rwDir)`; `roDir` is covered only by the `/`
read grant, so writes there are denied while reads succeed.

## go-landlock v0.9.0 API used

```go
import "github.com/landlock-lsm/go-landlock/landlock"

// Applies to the whole calling process (and its future children/execs).
err := landlock.V4.BestEffort().RestrictPaths(
    landlock.RODirs("/"),     // read + exec on the whole tree (target stays executable across execve)
    landlock.RWDirs(rwDir),   // full read-write, so the target CAN write somewhere
)
```

Capability gate uses the syscall subpackage:

```go
import lsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
v, err := lsyscall.LandlockGetABIVersion()   // skip if err != nil || v < 4
```

`RestrictPaths` restricts the whole process, sets `no_new_privs`, and — since
Landlock is inherited across `execve` — the confinement is exactly what a
stage-2 helper needs: apply, then `exec` the target already-confined.

## TDD red → green

- **RED**: `restrictReadOnly` stubbed as a no-op → child `RO_WRITE=OK` →
  assertion 1 fails (`child RO_WRITE = "OK", want "EACCES"`) while 2/3/4 pass.
  Confirms the Landlock call is load-bearing, not decorative.
- **GREEN**: wire the real `landlock.V4.BestEffort().RestrictPaths(...)` → all 5
  subtests pass under `go test -race`.

## Gotchas discovered

1. **Transitive dep `kernel.org/pub/linux/libs/security/libcap/psx` (v1.2.77).**
   The default (non-`landlocktsync`) build path of go-landlock's `syscall`
   subpackage imports `libcap/psx` for all-threads restriction. Building the
   spike surfaced a *missing go.sum entry* — the module had never compiled
   anything importing go-landlock before. Resolved with `go mod tidy`, which:
   promoted `go-landlock` from `// indirect` to a direct require, added
   `libcap/psx v1.2.77 // indirect`, and cleaned a stale `x/sys v0.37.0` go.sum
   pair. `psx` has a pure-Go fallback, so `CGO_ENABLED=0 go build` works; **no
   new top-level dependency was introduced** — psx is purely transitive to the
   already-approved go-landlock.

2. **`-race` requires cgo.** `CGO_ENABLED=0 go test -race` fails with
   *"-race requires cgo"*. The module's `CGO_ENABLED=0 -trimpath` rule is a
   **build/ship** rule; tests must run with the default (cgo-enabled) toolchain
   to satisfy the mandatory `-race`. Both are compatible: `go build ./...`
   ships cgo-free, `go test -race` runs with cgo.

3. **`BestEffort()` silently no-ops on a kernel without Landlock** (documented
   in the API). That is a fail-open trap. Defended twice here: the parent gates
   on `LandlockGetABIVersion() >= 4` before it will even re-exec, **and** the
   4-way assertion turns any no-op into a RED (the RO write would succeed).
   Either alone would suffice; together they make a silent no-op unfalsifiable.

## Carry-forward for Task 11/12 (from adversarial review)

1. **Thread-scope is a guarantee, not scheduling luck.** For ABI v4 (`< 8`)
   go-landlock takes the non-tsync path: `AllThreadsPrctl` +
   `AllThreadsLandlockRestrictSelf` via `libcap/psx`, which broadcasts the
   syscall to **every** OS thread. With `CGO_ENABLED=0`, psx redirects to the
   stdlib `syscall.AllThreadsSyscall` (Go 1.16+), which also covers all threads.
   So the restriction applies process-wide regardless of which thread a goroutine
   lands on — the shipped rung-2 backend does **not** need any special handling
   for this, and the target's in-process file ops are genuinely confined.

2. **Do NOT build the shipped backend with `-tags landlocktsync` unless ABI ≥ 8.**
   go-landlock's `restrict.go` sets `useTsync = abi.version >= 8`. On the common
   v1–v7 kernels it calls `AllThreadsLandlockRestrictSelf`/`AllThreadsPrctl` —
   which under the `landlocktsync` build tag are **panic stubs**
   (`allthreads_tsync_linux.go`). Building rung-2 with that tag would hard-panic
   at restrict time on any pre-v8 kernel (including this v4 host). Keep the
   default (non-tsync) build.

3. **`/proc/self/exe`, not `os.Args[0]`, in shipped code.** This spike re-execs
   `os.Args[0]` (fine for a test binary); Task 11's real dispatch must re-exec
   `/proc/self/exe` to avoid PATH-lookup / relative-path fragility.

## Verdict for Task 11/12

The re-exec + Landlock-in-child model is **sound on this host**: RO/RW path
scoping is enforced (`EACCES`), the deny is path-specific, reads survive, the
parent is untouched, and — proven by the target running post-execve — the
ruleset **survives the `execve` into the target**, which is the exact leg the
backend depends on. Landlock needs no userns. The capability gate (`t.Skip` with
a recorded reason when ABI < 4) is the portable guard for hosts that lack it.
Adversarial review verdict: **SOUND**.
