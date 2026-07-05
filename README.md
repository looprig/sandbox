# sandbox

`github.com/looprig/sandbox` provides OS-level sandboxing for agent command
execution.

**Status:** early scaffold — no enforcement implemented yet.

Harness's permission gates answer "may this tool call run?". This module
answers "what can it touch once it runs?". The two compose: OS-level
enforcement is what makes broad auto-approval safe. Concretely, it provides
security modes, a two-axis policy model, and per-platform enforcement (Seatbelt
on macOS; namespaces + Landlock + seccomp + nftables on Linux).

## Positioning

- Module path `github.com/looprig/sandbox`, a sibling of `storage` / `harness`,
  wired with `replace => ../sandbox` during development.
- **Leaf module.** It depends only on the standard library, `golang.org/x/sys`,
  and a tiny allowlist of vetted pure-Go OS-primitive libraries
  (`github.com/landlock-lsm/go-landlock`, `github.com/google/nftables`, added in
  a later phase). No cgo, no external binaries, and **no looprig imports** — not
  even `core`.
- It must be independently useful: it can sandbox any `exec.Cmd` in any Go
  program, and harness must never import it.

## Initialization

Consumers MUST call `sandbox.Init()` as the very first line of `main()`:

```go
func main() {
	sandbox.Init()
	// ... rest of program
}
```

`Init()` is a no-op stub today, but it becomes load-bearing on Linux later.
Wiring the call from day one means consumers do not have to retrofit it when the
Linux enforcement lands.

## Capability matrix

> **STUB — placeholder cells, to be filled in a later task.** The rows and
> columns below fix the shape of the honest per-rung capability table; the
> contents are TBD and MUST NOT be relied upon.

| Capability          | macOS Seatbelt | Linux rung 1 | Linux rung 2 | no sandbox |
| ------------------- | -------------- | ------------ | ------------ | ---------- |
| process boundary    | TBD            | TBD          | TBD          | TBD        |
| write boundary      | TBD            | TBD          | TBD          | TBD        |
| read denies         | TBD            | TBD          | TBD          | TBD        |
| env scrub           | TBD            | TBD          | TBD          | TBD        |
| network             | TBD            | TBD          | TBD          | TBD        |
| address-scoped net  | TBD            | TBD          | TBD          | TBD        |
| resource limits     | TBD            | TBD          | TBD          | TBD        |
