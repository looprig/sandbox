# Spike M3 — hand-built seccomp-BPF install through a stage-2 re-exec (Linux)

**Status:** GREEN on this host (kernel 6.8, x86_64, seccomp available).
**Validates:** Task 12b (rung-2 seccomp filter).
**File:** `spikes/seccomp/seccomp_reexec_linux_test.go` (`//go:build linux`, package `seccompspike`).

## What it proves

A hand-built, pure-Go seccomp-BPF filter — **no cgo, no libseccomp** — installed in a
re-exec'd stage-2 child after `PR_SET_NO_NEW_PRIVS`:

1. denies the marker syscall `socket(AF_INET, SOCK_DGRAM)` (UDP/IPv4) with `EACCES`,
2. **survives execve into the target** (the probes run in a *second* fresh image, post-execve),
3. is **arg-scoped**, not a blanket ban — `socket(AF_INET, SOCK_STREAM)` (TCP) still succeeds,
4. is **child-local** — the parent (never seccomp'd) can still open a UDP socket.

seccomp filters and `no_new_privs` are inherited across execve; that inheritance is exactly
what the real rung-2 backend relies on (stage-2 installs the filter, then execve's the command).

## Two-hop re-exec shape (mirrors the Landlock M2 spike)

```
parent test  --envStage2-->  stage-2 child            --envTarget-->  target
(never                       LockOSThread()                            runs the 3 probes
 confined)                   PR_SET_NO_NEW_PRIVS                       under the INHERITED
                             PR_SET_SECCOMP(filter)                    filter, prints markers
                             syscall.Exec(self)  ────execve────►
```

`TestMain` multiplexes on env sentinels (envTarget first, then envStage2, else the suite).
The parent captures `CombinedOutput` and parses `KEY=VALUE` markers.

## The BPF program (annotated)

Classic BPF, built as `[]unix.SockFilter`. seccomp_data offsets:
`nr@0, arch@4, instruction_pointer@8, args[0]@16, args[1]@24`.

```
[0]  LD  A = arch                       (offset 4)
[1]  JEQ A == AUDIT_ARCH_X86_64 ? ->[3] : ->[2]
[2]  RET SECCOMP_RET_KILL_PROCESS       # arch mismatch (e.g. i386) -> kill (fail-closed)
[3]  LD  A = nr                         (offset 0)
[4]  JSET A & 0x40000000 ? ->[5] : ->[6]  # __X32_SYSCALL_BIT set?
[5]  RET SECCOMP_RET_KILL_PROCESS       # x32 syscall -> kill (shares the x86_64 arch value)
[6]  JEQ A == SYS_socket ? ->[8] : ->[7]
[7]  RET SECCOMP_RET_ALLOW              # not socket(): allow (Go runtime needs its syscalls)
[8]  LD  A = args[0] low word           (offset 16) = domain
[9]  JEQ A == AF_INET ? ->[11] : ->[10]
[10] RET SECCOMP_RET_ALLOW              # non-AF_INET socket: allow
[11] LD  A = args[1] low word           (offset 24) = type (may carry SOCK_CLOEXEC/NONBLOCK)
[12] AND A = A & 0xff                   # strip the flag bits, keep the base type
[13] JEQ A == SOCK_DGRAM ? ->[15] : ->[14]
[14] RET SECCOMP_RET_ALLOW              # AF_INET but not UDP (e.g. TCP): allow  <-- positive control
[15] RET SECCOMP_RET_ERRNO | EACCES     # AF_INET UDP: deny cleanly with EACCES
```

**Security-critical points**

- **Arch guard first (`[0]`–`[2]`) stops i386, but NOT x32.** i386 runs under a *different*
  arch value (`AUDIT_ARCH_I386`) → killed. **x32 shares `AUDIT_ARCH_X86_64`** with native
  x86_64, so it passes the arch guard; its syscall numbers carry `__X32_SYSCALL_BIT`
  (`0x40000000`), so an x32 `socket()` has `nr = 41|0x40000000`, which fails the
  `nr == SYS_socket` compare and would **fall through to ALLOW** — a silent bypass. The
  **x32 guard (`[4]`–`[5]`)** rejects any syscall carrying that bit (fail-closed). This was
  caught by adversarial review; the earlier "blocks i386/x32" claim was wrong. **Load-bearing
  for Task 12b: the shipped filter MUST keep this x32 guard.**
- **Arg offset + endianness (`[6]`, `[9]`).** seccomp_data 64-bit args are two 32-bit words;
  on little-endian x86_64 the low word sits at the arg's base offset, so a single
  `BPF_W|BPF_ABS` load at 16 / 24 reads `domain` / `type`.
- **SOCK type flag masking (`[10]`).** Go's net stack always ORs `SOCK_CLOEXEC|SOCK_NONBLOCK`
  into `type`; comparing raw against `SOCK_DGRAM (2)` would never match. `& 0xff` isolates the
  base type. (The probes call `unix.Socket(..., proto=0)` with a bare type, but the mask makes
  the filter correct for real callers too.)
- **`RET_ERRNO`, not a SIGSYS kill.** The denied `socket()` returns a clean `syscall.EACCES`
  the target can assert on, rather than dying — easier to observe and closer to the real
  policy's soft-deny.

## The seccomp install call

`golang.org/x/sys` **v0.40.0 exposes no `unix.Seccomp` wrapper** (`go doc … Seccomp` → no symbol),
so the install uses the classic **`PR_SET_SECCOMP` / `SECCOMP_MODE_FILTER`** path via
`unix.Syscall(unix.SYS_PRCTL, …)`:

```go
unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)          // mandatory precondition
prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
unix.Syscall(unix.SYS_PRCTL, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)))
```

- `PR_SET_NO_NEW_PRIVS` **must** come first: without `CAP_SYS_ADMIN`, `SET_MODE_FILTER`
  returns `EACCES` unless `no_new_privs == 1`.
- `uintptr(unsafe.Pointer(&prog))` is passed **directly** as a `unix.Syscall` argument — the
  vet-recognized idiom that keeps `prog` (and the backing `filter` slice) alive across the call
  (belt-and-braces `runtime.KeepAlive(&prog)` too).

**Per-thread gotcha.** `PR_SET_SECCOMP` and `PR_SET_NO_NEW_PRIVS` are **per-thread**. The Go
scheduler could otherwise migrate the goroutine between install and execve, leaving the exec'ing
thread unfiltered. The stage-2 child calls `runtime.LockOSThread()` and does install → execve on
that one pinned thread; execve then collapses the process to that single filtered thread. (The
real backend can instead use the `seccomp(2)` syscall with `SECCOMP_FILTER_FLAG_TSYNC` to sync
all threads — not needed here.)

## The 4 assertions (all pass)

| # | assertion | how verified |
|---|-----------|--------------|
| 1 | UDP denied, filter survived execve | target: `unix.Socket(AF_INET, SOCK_DGRAM, 0)` → `EACCES`; marker `UDP=EACCES` |
| 2 | TCP allowed (arg-scoped, anti-fail-open) | target: `unix.Socket(AF_INET, SOCK_STREAM, 0)` succeeds, fd closed; marker `TCP=OK` |
| 3 | no_new_privs held across execve | target: `PrctlRetInt(PR_GET_NO_NEW_PRIVS)` == 1; marker `NNP=1` |
| 4 | confinement child-local (no leak) | parent: `unix.Socket(AF_INET, SOCK_DGRAM, 0)` succeeds |

`APPLY=OK` (printed on reaching the target) additionally proves the filter applied *and* execve
of a fresh image succeeded under it.

## TDD: RED → GREEN

- **RED** — the UDP-deny return instruction temporarily stubbed to `SECCOMP_RET_ALLOW`
  (allow-all for the UDP case): `UDP=OK, want EACCES` fails, while `APPLY=OK / TCP=OK / NNP=1`
  all pass — isolating the failure to the missing deny and proving the filter is load-bearing
  (not the harness).
- **GREEN** — real `SECCOMP_RET_ERRNO | EACCES` at the final instruction: all 5 subtests pass
  under `-race`.

```
ok  github.com/looprig/sandbox/spikes/seccomp   (5/5 PASS, -race)
```

`gofmt -l` clean, `go vet` clean; root module `go build ./...` + `go test -race .` unaffected.

## Carry-forward for Task 12b (from adversarial review — verdict SOUND)

1. **Keep the x32 guard (load-bearing).** The shipped rung-2 filter must reject
   `nr & __X32_SYSCALL_BIT` (`0x40000000`) after the arch guard, or an x32 caller bypasses
   every `nr`-based rule. Added to this spike's reference filter (`[4]`–`[5]`).
2. **Multi-threaded install needs TSYNC.** `PR_SET_SECCOMP` (used here) is per-thread. The
   spike is safe because it installs and execve's on one `runtime.LockOSThread()`-pinned thread.
   If the real backend installs from a multi-threaded process (or uses `os/exec` fork+exec),
   it must either keep install→exec on one locked thread in the child (this spike's shape) OR
   use the `seccomp(2)` syscall with `SECCOMP_FILTER_FLAG_TSYNC` to filter all threads. Landlock
   (M2) is already all-threads via psx; seccomp needs the equivalent.
3. **MPTCP interaction (see the nftables spike doc).** On rung 2 the network boundary leans on
   Landlock TCP port rules, which do NOT cover Multipath TCP. For a sound `NetworkBoundary`
   guarantee the seccomp filter should also block `socket(..., IPPROTO_MPTCP)` (protocol 262),
   or the port allowlist is bypassable. Cross-reference `docs/spikes/nftables-netns.md`.
4. **Probe, don't Fatalf, for the capability gate.** This spike relies on host facts and lets an
   install failure surface as a non-zero child exit (host-gated throwaway). Shipped code should
   probe `SECCOMP_MODE_FILTER` availability and `t.Skip`/degrade deliberately for portability.

## Deps

Only `golang.org/x/sys/unix` (already in go.mod). No libseccomp, no cgo in the filter path.
(`-race` enables cgo for the test binary — that's the race detector, not the filter.)
