# sandbox

`github.com/looprig/sandbox` confines the commands an agent spawns with real
OS-level enforcement — Seatbelt on macOS; namespaces + Landlock + seccomp +
nftables + cgroups on Linux.

Harness's permission gates answer *"may this tool call run?"*. This module
answers *"what can it touch once it runs?"*. The two compose: OS-level
enforcement is what makes broad auto-approval safe. The module provides security
modes, a two-axis (filesystem + network) policy model with env scrubbing and
resource limits, unforgeable HMAC grant tokens for escalation, and — the
load-bearing signal for a consumer's auto-approval interlock — a per-property
`Guarantees()` report of what was *actually* enforced.

## Positioning

- Module path `github.com/looprig/sandbox`, a sibling of `harness`/`storage`,
  wired with `replace => ../sandbox` during development.
- **Leaf module.** Depends only on the standard library, `golang.org/x/sys`, and
  a tiny allowlist of vetted **pure-Go** OS-primitive libraries
  (`github.com/landlock-lsm/go-landlock`, `github.com/google/nftables`). No cgo,
  no external binaries, and **no looprig imports**.
- Independently useful: it can sandbox any `*exec.Cmd` in any Go program (via
  `Executor.Wrap`), and harness couples to it only structurally (stdlib-typed
  interfaces) — harness must never import it.

## Initialization (required on Linux)

Consumers **MUST** call `sandbox.Init()` as the very first line of `main()`:

```go
func main() {
	sandbox.Init()
	// ... rest of program
}
```

On Linux every sandboxed spawn re-executes `/proc/self/exe` as a confinement
helper (the moby/reexec pattern); `Init()` is the dispatch entry point that
catches that re-exec before `main()` runs. On other platforms it is a no-op, but
call it unconditionally so the code is portable. If it is not called, an
`Executor` built with a Linux enforcement backend fails construction with
`ErrInitNotCalled` (fail-closed) rather than silently running commands
unconfined.

## Capability matrix (honest, per rung)

`Level()` and `Guarantees()` report what was *achieved on the host*, never what
was requested. A capability the mechanism cannot express compiles **narrower**
(recorded in `CompileReport`), never wider (SPEC §7.5).

| Capability             | macOS Seatbelt        | Linux rung 1 | Linux rung 2                     | no sandbox |
| ---------------------- | --------------------- | ------------ | -------------------------------- | ---------- |
| process boundary       | ✅ (sandbox-exec)     | ✅ (namespaces) | ❌ (no namespaces)            | ❌ |
| write boundary         | ✅                    | ✅ (mount + Landlock) | ✅ (Landlock)             | ❌ |
| read denies (fixed)    | ✅                    | ✅ (mount masks) | ✅ (enumerated allows)        | ❌ |
| read denies (glob `**/.env*`) | ✅ (SBPL regex) | ✅ (bounded-scan masks) | ⚠️ unenforced for subprocesses | ❌ |
| restricted-read (invisibility) | ❌            | ✅ (pivot_root view) | ❌                         | ❌ |
| env scrub              | ✅                    | ✅            | ✅                               | ✅ |
| network (TCP ports)    | ✅                    | ✅ (nftables) | ✅ (Landlock ConnectTCP)         | ❌ |
| address-scoped net (loopback/private/metadata) | ⚠️ blocked (SBPL can't scope) | ✅ (nftables) | ⚠️ blocked (port-only) | ❌ |
| resource limits (cgroup) | ⚠️ ulimit approx   | ✅           | ✅                               | ❌ |
| **`Level()`**          | `Full` / `Degraded`†  | **`Full`**   | **`Degraded`**                   | `None` |

† Seatbelt / rung 2 report `Degraded` when a policy needs address-scoping
(`Private`/metadata) that the mechanism can't express; a port+loopback+DNS
policy on Seatbelt is `Full`.

### Reads are not confidential in `write`/`trusted`

At rung 2 and under Seatbelt, the `write`/`trusted` modes grant **broad host
read** so tools work — only the fixed secret paths (`~/.ssh`, `~/.aws`, …) are
denied, and rung-2 glob denies (`**/.env*`) are **not enforced for
subprocesses** (the in-process `ReadGuard` still covers native tools). Treat a
rung-2 sandbox as a **write/execute/network** boundary, not a read-confidentiality
boundary. True restricted-read (host paths *invisible*) exists only at **rung 1**
(`zerotrust`), via the pivot_root mount view.

## Security modes

`ZeroTrust` < `ReadOnly` < `Write` < `Trusted` < `Unconfined` (the zero value is
`ZeroTrust`, fail-closed). Build a policy with `PolicyFor(mode, workspace,
opts...)` and an executor with `NewExecutor(policy)` (or `NewExecutorDynamic` for
a live, journal-clampable ceiling). `Unconfined` requires an explicit
`AckUnconfined`.

## Backend selection

`platformBackend()` picks the strongest achievable enforcement per host: Seatbelt
on darwin; on Linux a runtime probe (`selectRung`) chooses **rung 1** (userns +
mountns + netns available) or **rung 2** (Landlock ABI ≥ 4 + seccomp, no
namespaces — the common in-container case) or **none** (honest `LevelNone`). The
probe keeps the report honest: a host that cannot enforce a rung never claims it.

## Status

v0.1.0. Seatbelt (macOS) and the full Linux rung-1/rung-2 ladder + cgroup limits
are implemented. Rung 2 is validated on Linux hosts with Landlock ABI ≥ 4; rung 1
is validated in CI on hosts permitting unprivileged user namespaces. Deferred to
a later version: domain/method-level egress (SNI-peek proxy), seccomp
user-notification telemetry, and a native Windows backend (`ErrUnsupportedPlatform`
today — use WSL2 or a container).
