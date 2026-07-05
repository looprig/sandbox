# sandbox — module spec

Status: canonical spec, 2026-07-05. Phase 0 policy decisions recorded (§13).
Implementation in progress per `docs/plans/2026-07-05-sandbox-module-plan.md`.
Design agreed in discussion; revised after review (env policy, grant
unforgeability, honest v1 denial detection, Landlock feasibility limits, backend
compilation rules, subagent/foreign-agent section, acceptance matrix).

OS-level sandboxing for agent command execution: security modes, a two-axis policy
model, and per-platform enforcement (Seatbelt on macOS; namespaces + Landlock +
seccomp on Linux). The prior art is OpenAI Codex's sandbox (`codex-rs`:
`sandboxing`, `linux-sandbox`, `bwrap` crates); this design keeps its architecture
(policy → per-command argv/spawn transform, external-sandbox escape hatch,
escalation into the approval layer) and departs from it where we can do better in
Go: pure-Go enforcement with no bubblewrap dependency, isolation level as a typed
input to permission gates, secure-by-default deny-reads and env scrubbing, cgroup
resource limits, and unforgeable grant-token escalation instead of
stderr-heuristic retry.

## 1. Purpose

Harness's permission gates answer *"may this tool call run?"*. This module answers
*"what can it touch once it runs?"*. The two compose: OS enforcement is what makes
broad auto-approval safe. harness/CLAUDE.md already names this module as the
prerequisite for ever auto-approving Bash broadly; this spec is that unlock.

## 2. Positioning and dependency rules

- Module path `github.com/looprig/sandbox`, sibling of `storage`/`harness`, wired
  with the usual `replace => ../sandbox` during development.
- **Leaf module: stdlib + `golang.org/x/sys` + a tiny allowlist of vetted
  pure-Go OS-primitive libraries** (`github.com/landlock-lsm/go-landlock` for
  Landlock rulesets, `github.com/google/nftables` for netlink/nftables). No cgo,
  no external binaries, no looprig imports — not even `core`. It must be
  independently useful (sandbox any `exec.Cmd` in any Go program), and harness
  must never import it. The allowlist is deliberately minimal; each entry is a
  focused, auditable pure-Go wrapper over a kernel primitive, and in a
  security-critical path a vetted library is preferred over hand-rolled syscalls
  (Phase-0 decision, §13).
- Harness↔sandbox coupling is **structural only**: every seam interface harness
  defines uses stdlib types exclusively, so this module satisfies them without an
  import (§10). The `storage` ← `fsstore` pattern, done with interfaces instead of
  a shared contracts import.
- The consumer (swe, or any customer composition root) is the only place that
  imports both and glues them (§10.4).

## 3. Threat model

Defended against (a prompt-injected or malicious command spawned by the agent):

- **Host tampering** — writes outside the workspace: filesystem policy.
- **Exfiltration** — reading secrets and sending them out: network policy, plus
  default deny-reads (§5.3) closing the read → write-into-workspace → user-pushes
  path that exists even with network off.
- **Credential leakage via environment** — children inherit the harness process
  environment (LLM API keys, `GITHUB_TOKEN`, cloud creds) unless scrubbed; the
  existing Bash tool never sets `Cmd.Env` (harness/pkg/tools/bash.go:192), so
  today every spawned command sees everything. EnvPolicy (§5.5) closes this.
- **Resource abuse** — fork bombs, memory bombs: cgroup v2 limits (§7.4).
- **Approval social-engineering** — a command or the model fabricating escalation
  requests: grants are MAC-verified tokens only this module can mint (§9).

Out of scope: kernel exploits (that is container/microVM territory — §11) and
Windows-native enforcement in v1 (§7.3). The harness process itself runs
unconfined; everything it *spawns* is confined — including foreign agent
processes, which are in scope for v1 (§10.6).

## 4. Security modes

One user-facing knob bundling OS enforcement and gate posture coherently. The
mode vocabulary lives here; harness stays mode-agnostic — it sees only an ordered
ceiling and registered postures (§8, §10.2).

```go
type Mode uint8

const (
    ZeroTrust  Mode = iota // zero value = most restrictive (fail-closed)
    ReadOnly
    Write
    Trusted
    Unconfined
)
```

Semantics ("gated" = OS-blocked by default, unlockable through a permission ask;
"hard-deny" = blocked, no prompt offered):

| | zerotrust | readonly | write | trusted | unconfined |
|---|---|---|---|---|---|
| Reads | workspace + minimal system paths only (restricted-read; host dotfiles/other repos invisible) | broad host reads | broad | broad | everything |
| Writes (OS-enforced) | none | none (gated) | workspace + tmp | workspace + tmp | everything |
| Network | hard-deny | gated | gated | HTTPS (:443) + DNS + loopback + RFC1918 allowed; rest gated | open |
| Environment (§5.5) | baseline allowlist | baseline allowlist | baseline allowlist | baseline allowlist | inherit all |
| File-edit tool calls | ask | ask | auto-approve | auto-approve | auto-approve |
| Bash tool calls | ask | ask | trivial auto (classifier), rest ask | all auto | all auto |
| Secret deny-reads (§5.3) | hard-deny | hard-deny | hard-deny | hard-deny | not applied |
| Metadata endpoints (§5.4) | hard-deny | hard-deny | hard-deny | hard-deny | not applied |

Notes:

- `trusted` is the maximum *sandboxed* tier: still workspace+tmp write-confined.
  Its default egress (HTTPS + local) is an explicit autonomy/exfil trade-off; v1
  cannot restrict HTTP methods (that needs the MITM proxy, deferred §12), so
  `trusted` + broad reads is a real exfil channel, mitigated by deny-reads and
  env scrubbing. Full `trusted` network semantics require Linux rung 1 (§7.5).
- `unconfined` is not the next rung — it is stepping off the ladder: no wrapper
  applied, full user-level authority (Codex's `danger-full-access`,
  AppArmor's "unconfined"). Constructing it requires `Policy.AckUnconfined =
  true`; the scare-surface lives at config/CLI, not in the type name.
- Approving a gated action never implies unconfined execution: approval answers
  "may this run", the sandbox still answers "what can it touch". Running outside
  the sandbox is only ever a separate explicit grant (§9).
- `External` (already-isolated environment) is **not a sixth mode** — it is an
  executor flavor, orthogonal to the ladder (§11).

## 5. Policy model

Modes are presets; the real model is orthogonal axes. `PolicyFor(mode, ws)`
expands a mode; consumers can construct or adjust a `Policy` directly (§6).

### 5.1 Filesystem axis

```go
type FSAccess uint8 // bitmask; zero value = no access (fail-closed)

const (
    DenyAccess  FSAccess = 0
    ReadAccess  FSAccess = 1 << iota // read files + list/traverse directories
    ExecAccess                       // execute binaries (Linux needs this explicitly)
    WriteAccess                      // create/modify/delete
)

type FSEntry struct {
    Path   string // absolute; supports glob patterns
    Access FSAccess
}
```

- Execute/traverse are explicit: running `/bin/sh`, loaders, and toolchains needs
  `ExecAccess`; mode presets grant `Read|Exec` on broad-host reads and
  `Read|Write|Exec` on the workspace (build outputs must be runnable). Backends
  map these to `LANDLOCK_ACCESS_FS_{READ_FILE,READ_DIR,EXECUTE,WRITE_FILE,...}`
  and SBPL `file-read*` / `process-exec` / `file-write*`.
- Precedence (policy semantics): **deny > write > read**, longest-path match wins
  within a class. How each backend *realizes* deny-inside-allow differs and may
  degrade `Level()` — see §7.5; the policy layer states intent, the compiler
  states what was actually enforced.
- Writable roots carry protected carveouts: `.git`, `.looprig` (and configurable
  additions) inside a writable root are re-masked **read-only** — the agent must
  not rewrite history or its own configuration. Git ops needing `.git` writes go
  through the gate.
- Tmp: **`/tmp` only** is the writable tmp root in `write`+ (excludable per
  policy); the sandbox forces `TMPDIR=/tmp` via EnvPolicy (§5.5) so tools do not
  reach for `$TMPDIR` outside it (macOS `/var/folders/...`). Caveat: a few macOS
  libraries read `_CS_DARWIN_USER_TEMP_DIR` via `confstr` regardless of
  `$TMPDIR`; revisit only if a real tool breaks (§13).

### 5.2 Network axis

```go
type NetPolicy struct {
    Loopback bool
    Private  bool       // RFC1918 + ULA
    Ports    []uint16   // e.g. {443}: outbound TCP to these ports, any host
    DNS      bool       // name resolution: 53/udp+tcp and platform resolver paths
    Open     bool       // unconfined only
}
```

Zero value = fully blocked. Domain-level allowlists are v2 (§12).

`DNS` exists because `Ports{443}` alone does not make
`curl https://example.com` work — resolution needs its own channel. It compiles
per backend: macOS — SBPL allowance for the system resolver via the
**mDNSResponder unix socket** (`allow network-outbound (remote unix-socket
(path-literal "/private/var/run/mDNSResponder"))`); outbound `:53` alone does
**not** work (macOS `getaddrinfo` delegates name resolution to the unsandboxed
mDNSResponder daemon over that socket — verified in the Task M1 spike,
`docs/spikes/seatbelt-net.md`); rung 1 — nftables 53/udp+tcp in-namespace; rung 2 —
Landlock TCP:53 plus `RES_OPTIONS=use-vc` injected via EnvPolicy to force glibc
onto TCP DNS (UDP:53 cannot be port-scoped below ABI v10; musl ignores
`use-vc`, recorded as a narrowing). `trusted` and foreign-agent presets set
`DNS: true`.

**Feasibility (drives §7.5):** address-scoped rules (`Loopback`, `Private`,
metadata deny) require a network namespace with in-namespace filtering — Linux
rung 1. Landlock network rules are **port-scoped TCP only** (`bind`/`connect`
from ABI v4; UDP scoping only from ABI v10 — see
<https://docs.kernel.org/userspace-api/landlock.html>), and seccomp cannot
inspect `sockaddr` pointers. So on rung 2: `Ports` compiles to Landlock TCP
rules; UDP is blocked wholesale via seccomp `socket(AF_INET*, SOCK_DGRAM)`
denial below ABI v10; `Loopback`/`Private` are **not expressible and compile to
blocked** (sound: narrower than policy, never wider). Practical consequence:
UDP DNS is unavailable on rung 2 below ABI v10; the `DNS` channel there
compiles to Landlock TCP:53 + `RES_OPTIONS=use-vc` (below), which restores
name-based egress for glibc programs — musl and other UDP-only resolvers remain
broken on that rung and are recorded in the compilation report, not silently
ignored. macOS SBPL expresses ports and loopback reliably (loopback via the
`localhost` token, which matches *all of this host's own addresses*, not
strictly `127.0.0.0/8` — a widening recorded in the CompileReport, but it never
admits a genuine remote). CIDR/address-scoped rules (`Private`, metadata) are
**verified unsupported** (Task M1: SBPL's network host token is `*` or
`localhost` only — literal IP/CIDR/subnet is rejected at profile-compile time,
not bypassable via `require-not` or precedence), so they compile to **blocked**
(same soundness rule); the macOS `AddressNetwork` guarantee is therefore always
false.

### 5.3 Default deny-reads

Applied in every mode except `unconfined`, must be explicitly loosened:
`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`, `~/.netrc`,
`~/.docker/config.json`, OS keychains, browser profile dirs, and `**/.env*`
**everywhere — including inside the workspace** (repo-local `.env` files are
exactly the secrets the existing harness read-guard denies; the sandbox must
match it, not weaken it). Shipped as a named preset (`DefaultSecretDenials`) so
the list is versioned and auditable.

### 5.4 Metadata endpoint hard-deny

`169.254.0.0/16` and `fd00:ec2::254` are denied whenever any network is allowed,
including under `trusted`'s "local network". Cloud metadata services hand out
live credentials to a plain GET; "local" never includes them by default.
(Enforceable only where address scoping is — rung 1 / Seatbelt-if-verified; on
rung 2 it holds vacuously because `Private` compiles to blocked and `:80` is not
in the default port set. §7.5.)

### 5.5 Environment policy

Spawned commands must not inherit the harness process environment. Default is a
**baseline allowlist**, not a scrub-list: `PATH`, `HOME`, `TERM`, `LANG`,
`LC_*`, `USER`, `LOGNAME`, `SHELL`, `TZ`, plus `TMPDIR` **set by the sandbox**
to the policy's writable tmp (`/tmp`; §5.1). Everything else — `SSH_AUTH_SOCK`, `AWS_*`,
`GOOGLE_*`, `AZURE_*`, `GITHUB_TOKEN`/`GH_TOKEN`, LLM API keys
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …), `DOCKER_*`, `GPG_*`, `KUBECONFIG`,
`NPM_TOKEN` — is absent unless explicitly allowed.

```go
type EnvPolicy struct {
    Inherit bool              // pass everything through (unconfined / explicit opt-in only)
    Allow   []string          // names or globs added to the baseline, e.g. "GOFLAGS", "CARGO_*"
    Set     map[string]string // forced values; sandbox always sets TMPDIR here
}
```

Zero value = baseline allowlist (fail-closed). `HOME` keeps its real value — it
is just a path; access to it is governed by the filesystem axis. `unconfined`
implies `Inherit`.

## 6. Public API (core)

```go
// Called first in the consumer's main(); no-op except when this process is
// re-executed as the Linux sandbox stage-2 helper (moby/reexec pattern, §7.2).
func Init()

type Policy struct {
    Workspace     string
    FS            []FSEntry // fully expanded: mode preset + carveouts + deny presets + consumer opts
    Net           NetPolicy
    Env           EnvPolicy
    Limits        Limits    // zero value = per-mode defaults; see §7.4
    AckUnconfined bool      // required iff the policy grants unconfined access
}

type Limits struct {
    MaxPIDs     int
    MaxMemBytes int64
    MaxCPUPct   int
    Disabled    bool // explicit opt-out; zero value means "mode defaults apply"
}

func PolicyFor(mode Mode, workspace string, opts ...PolicyOption) Policy
// PolicyOption: WithWritable(path), WithDenyRead(glob), WithNet(NetPolicy),
// WithEnv(EnvPolicy), WithLimits(Limits), WithCarveouts(names...),
// WithoutSecretDenials() (explicit, logged).

type Executor struct{ ... }
func NewExecutor(p Policy, opts ...ExecOption) (*Executor, error)
// ExecOption: WithGrantTTL(d), WithCgroupParent(path).

// Dynamic mode (§8): recompiles PolicyFor(src.Current(), workspace, popts...)
// per spawn (cached per mode; each mode change bumps the policy generation used
// in grant-token binding, §9.2). A ModeSource cannot be an ExecOption on
// NewExecutor — a single pre-expanded Policy cannot be re-derived per mode.
type ModeSource interface{ Current() Mode }
func NewExecutorDynamic(src ModeSource, workspace string, popts ...PolicyOption) (*Executor, error)

type ExternalDecl struct {
    Boundary   string    // "docker" | "gvisor" | "firecracker" | "kata" | free-form
    NetworkVia string    // what handles egress, e.g. "infra-proxy"; audit field
    Note       string
    Env        EnvPolicy // scrubbing still applies inside external boundaries (§11)
}
func NewExternalExecutor(decl ExternalDecl) *Executor // §11; only source of LevelExternal

// Structurally satisfies harness's CommandRunner (§10.1): shell-string form.
func (e *Executor) RunCommand(ctx context.Context, dir, command string) ([]byte, int, error)
// Structurally satisfies harness's ArgvRunner (§10.1): direct argv exec, no
// shell — for tools like Grep that already build argv safely.
func (e *Executor) RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error)
// Structurally satisfies harness's GrantedRunner (§10.1). Grants are MAC-verified
// tokens previously minted by this executor (§9). Invalid/expired → typed error.
func (e *Executor) RunCommandWithGrants(ctx context.Context, dir, command string, grants []string) ([]byte, int, error)

// Grant minting and verification (§9). Stdlib-only signatures — harness probes
// these structurally, and a named sandbox type in a signature would force the
// import this design forbids.
func (e *Executor) PlanGrants(dir, command string) []string   // pre-ask minting: tokens only
func (e *Executor) DescribeGrant(token string) (string, bool) // MAC-verify → bound description

// Achieved (probed + compiled, not requested) isolation. Zero value fail-closed.
func (e *Executor) Level() uint8 // LevelNone=0, LevelDegraded, LevelFull, LevelExternal
func (e *Executor) Report() CompileReport // what was enforced, narrowed, unenforced (§7.5)

// Machine-readable per-property guarantees — the load-bearing signal for the
// auto-approval interlock (§10.3), finer-grained than Level(). Each field is
// fail-closed: false unless the backend actually enforced it (soundness, §7.5).
type Guarantees struct {
    ProcessBoundary bool // spawned inside an isolating boundary (ns / seatbelt / external)
    WriteBoundary   bool // writes confined to policy-writable roots
    ReadDenies      bool // §5.3 secret deny-reads enforced for subprocesses
    EnvScrub        bool // child sees the EnvPolicy baseline; harness secrets absent
    NetworkBoundary bool // egress restricted to policy (at least port-level)
    AddressNetwork  bool // address-scoped rules (Loopback/Private/metadata) enforced
    ResourceLimits  bool // cgroup/ulimit limits applied
}
func (e *Executor) Guarantees() Guarantees // rich form for direct library users

// Seam-facing stdlib form: the same guarantees as a bitmask, so harness can
// probe `interface{ GuaranteeBits() uint64 }` without importing this package
// (structural coupling, §2). Bit positions are exported constants; the consumer
// (swe) — which imports both — builds each posture's required mask from them and
// the checker gates on `bits & required == required` (§10.3).
const (
    GuaranteeProcessBoundary uint64 = 1 << iota
    GuaranteeWriteBoundary
    GuaranteeReadDenies
    GuaranteeEnvScrub
    GuaranteeNetworkBoundary
    GuaranteeAddressNetwork
    GuaranteeResourceLimits
)
func (e *Executor) GuaranteeBits() uint64

// Wrap an arbitrary command for non-harness users.
func (e *Executor) Wrap(cmd *exec.Cmd) (*exec.Cmd, error)

// Derived executor for read-path tools (Grep, §10.1): same policy and
// ModeSource as the parent — so zerotrust restricted-read applies to rg too —
// with writes removed, network forced blocked, and granting disabled (the read
// path never escalates). Shares the parent's probe results; no re-probe.
func (e *Executor) ReadOnlyView() *Executor
```

`LevelExternal` can only be constructed by `NewExternalExecutor` — trust by
explicit deployment declaration, never minted by probing.

## 7. Enforcement backends

Selection is per-platform via build tags; enforcement is a **stateless per-spawn
transform** (argv wrapper / spawn attributes). Nothing long-lived; this is what
makes runtime mode changes and per-agent policies cheap (§8).

### 7.1 darwin — Seatbelt

Generate an SBPL profile from the policy (default-deny base; `file-read*` /
`file-write*` / `process-exec` allows per entry; deny rules for §5.3 — SBPL
expresses deny-inside-allow natively; network section per §5.2) and spawn
`/usr/bin/sandbox-exec -p <profile> -D<param>=<path>… -- /bin/sh -c <command>`.
**Emitted FS paths are canonicalized (`filepath.EvalSymlinks`, with a
`filepath.Clean` fallback for not-yet-existing paths)** because Seatbelt matches
rules against the kernel's *symlink-resolved* access path: on macOS `/tmp` →
`/private/tmp`, `/etc` → `/private/etc`, `/var` → `/private/var`, and temp
workspaces under `/var/folders/…` resolve into `/private/…`. Without this the
`/tmp` (i.e. `$TMPDIR`, §5.5) and symlinked-workspace write grants silently
**deny** everything — verified by the Task 8b real-`sandbox-exec` enforcement
tests, which is why the golden profiles emit `/private/tmp` etc. (Residual: a
`WithDenyRead` glob whose literal prefix sits under a symlinked root and does not
yet exist under-matches; `DefaultSecretDenials`' `**/.env*` is prefix-free, so
the secure defaults are unaffected.)
Deprecated-but-universal (Chrome, Bazel, Codex, Claude Code). Network section
(verified in Task M1, `docs/spikes/seatbelt-net.md`): `Ports` → `(remote tcp
"*:P")` per port; `Loopback` → `(remote ip "localhost:*")`; `DNS` → the
mDNSResponder unix-socket allow (§5.2); `Private` and the metadata deny →
**blocked** (SBPL cannot address-scope) with a `CompileReport{address-network,
unenforced}` entry. Level: `LevelFull` for policies whose net needs only
default-deny + ports + loopback + DNS; a policy requesting `Private`/metadata
tops out at `LevelDegraded` (its `AddressNetwork` guarantee is false), per §7.5.

### 7.2 linux — pure-Go ladder, no bwrap

Probe at `NewExecutor` and take the strongest available rung; achieved level =
rung capability **and** compilation completeness (§7.5):

| Rung | Mechanism | Covers |
|---|---|---|
| 1 | userns+mountns+netns via `SysProcAttr.Cloneflags` + re-exec stage-2 (`/proc/self/exe`, entered through `Init()`): bind-mount view (ro root or tmpfs root for restricted-read, rw binds for writable roots, ro re-masks for carveouts and fixed deny-paths), in-ns nftables for §5.2 address rules, then Landlock + seccomp + `PR_SET_NO_NEW_PRIVS`, then exec target | FS incl. carveouts/globs-by-mount, full net semantics, restricted-read |
| 2 | Landlock v4+ (FS + TCP port rules) + pure-Go seccomp-BPF (UDP socket denial, ptrace/io_uring denial) + `PR_SET_NO_NEW_PRIVS`, applied in the stage-2 child (not the parent); no namespaces | FS by enumerated allowlist (§7.5), TCP port allowlist; no address scoping, no restricted-read |
| 3 | nothing available | — → `LevelNone` |

**Common spawn path (both rungs).** Go's `exec.Cmd` gives no safe
post-fork/pre-exec hook to run arbitrary syscalls in the child, and applying
Landlock/seccomp in the parent would confine the harness itself. So **every**
Linux spawn — rung 1 and rung 2 — goes through the stage-2 re-exec entered by
`Init()`: the parent seals a spawn spec, launches `/proc/self/exe
lrsandbox-stage2`, and stage-2 applies namespaces (rung 1 only) + Landlock
(`go-landlock`) + seccomp + `no_new_privs` + env + cgroup, then execs the
target. Rung-1 address filtering runs `google/nftables` over netlink inside the
netns (§5.2). Rung 2 differs only by skipping namespace/mount/nftables setup —
it still re-execs to apply Landlock+seccomp in the child.

Rung 2 matters because userns creation is commonly blocked inside containers —
exactly where Landlock still works. Rung 3 + the gate interlock (§10.3) means a
degraded host silently falls back to ask-a-human, never to raw auto-approved
execution. No external binaries: no bwrap detection, bundling, or digest
verification (Codex's approach) — the host binary re-execs itself.

### 7.3 windows — unsupported in v1

`NewExecutor` returns `ErrUnsupportedPlatform`. Documented guidance: WSL2 (Linux
ladder applies) or containers (§11). Codex's restricted-token + ACL + WFP stack
is a large system; revisit post-v1.

### 7.4 Resource limits (linux)

Each spawned command joins a transient cgroup v2 scope from `Policy.Limits`
(defaults on in `zerotrust`–`trusted`). Gates cannot stop `:(){ :|:& };:`; this
does. cgroup v2 unavailable (no writable delegation): limits are unenforced,
recorded in `CompileReport`; `Level()` is unaffected (resource limits are
containment-of-cost, not containment-of-authority) but the report is visible to
consumers. darwin approximation: `ulimit` in the wrapper.

### 7.5 Policy compilation per backend

The policy states intent; each backend compiles it to what its mechanism can
express, under one invariant:

> **Soundness: compiled enforcement is never wider than the policy. It may be
> narrower; every narrowing or unenforced feature is recorded in
> `CompileReport` and reflected in `Level()`.**

- **Deny-inside-allow** (carveouts, fixed-path secret denies): Seatbelt — native
  deny rules. Rung 1 — mount re-masking. Rung 2 — Landlock is additive
  (allowlist-only, no deny rules), so fixed-path denies compile by
  **enumerated allows**: at spawn, grant the siblings of the denied path instead
  of the parent (inode-pinned, snapshot semantics — entries created after spawn
  are inaccessible for that command's lifetime, which errs narrow). Applies to
  `.git` carveouts and `~/.ssh`-style fixed denies.
- **Glob denies** (`**/.env*`): Seatbelt — native regex deny rules. Rung 1 —
  mounts cannot express patterns, so globs compile by **spawn-time bounded
  enumeration**: scan the configured roots (workspace + `$HOME`) to a max depth
  (Codex's `glob_scan_max_depth` precedent), and mask each match with an empty
  read-only bind. Enumeration is re-run at every spawn, so any secret that
  exists when a command starts is masked; the only escape is a file the command
  *itself creates* mid-run — which by construction contains no pre-existing
  secret. That residual is sound (never wider than policy) and does not demote
  `Level()`; it is noted in `CompileReport`. Rung 2 — **not expressible**
  (Landlock is additive; masking by enumeration would require re-granting every
  sibling recursively for mid-tree patterns): unenforced, recorded,
  `Level() = LevelDegraded`. The in-process `ReadGuard` (§10.5) still enforces
  globs for native tools; the gap is subprocess reads.
- **Address-scoped network** (`Loopback`, `Private`, §5.4): rung 1 nftables /
  Seatbelt-if-verified; rung 2 compiles to blocked (§5.2).
- `LevelFull` requires: every policy feature enforced by the mechanism, no
  narrowings that change semantics the gate relies on. Anything less that still
  enforces the write boundary = `LevelDegraded`. The gate's auto-approve
  threshold defaults to `LevelFull` and may be consciously lowered to
  `LevelDegraded` by the consumer (§10.3).

## 8. Runtime mode changes

- Enforcement is consulted **at spawn time** (and gate posture at check time), so
  switching is one atomic value: wire a `ModeSource` (§6). This is the
  Claude-style cycle: `readonly` ≈ plan, `write` ≈ auto-accept-edits, `trusted` ≈
  full auto.
- **Journaled**: harness-side, a ceiling change is a session command
  (`command.SetSecurityCeiling{Level uint8}` → journal →
  `event.SecurityCeilingChanged`), never a bare setter — it must be replayable
  and auditable. Harness interprets the ceiling **only as an ordinal** (0 = most
  restrictive); the mapping ordinal → `sandbox.Mode` and ordinal → posture is
  registered by the consumer at construction (§10.2), keeping harness
  mode-agnostic.
- **Ceiling semantics**: the gate computes its effect as usual, then **clamps by
  the current ceiling's registered posture**. Downgrading `trusted → readonly`
  instantly neutralizes stale session grants without garbage-collecting them;
  upgrading re-exposes earned grants.
- **In-flight commands keep the policy they were spawned with.** Tightening does
  not retro-confine a live process; optional cancel-on-downgrade uses the
  existing per-call ctx.

Multi-agent composition:

- Static per-role modes at the composition root (reviewer `readonly`, operator
  `write`, test-runner `trusted`) — separate `PolicyFor` per toolset, which swe's
  per-role `BuildTools` structure already supports.
- **effective mode = min(role's static mode, session's dynamic ceiling)** — the
  user's toggle clamps the whole swarm.
- **Non-escalation down the agent tree**: a spawned subagent's mode is clamped to
  ≤ its parent's effective mode. Elevation only via static composition-root
  config, never via a runtime spawn request. Enforcement point: §10.6.

## 9. Denials, grants, escalation

### 9.1 What v1 can honestly detect

A parent running `sh -c` sees only exit status and output — it does **not**
learn "child got EACCES on path X"; macOS `sandbox-exec` is equally opaque.
Precise per-path/per-destination denial telemetry requires seccomp
user-notification and is deferred (§12). v1's detection tiers:

1. **Pre-ask (primary)**: `PlanGrants(dir, command)` — policy-aware
   classification predicts needed capabilities (`git push` → network) so the
   *first* call routes to Ask with minted grants, avoiding run-fail-rerun on
   non-idempotent commands.
2. **Mechanism signals (exact, coarse)**: wrapper/spawn-time errors; exec
   failures (126/127); `128+SIGSYS` where a filter kills rather than
   errno-returns.
3. **Generic denial (fallback)**: command failed *and* the policy blocks
   capabilities the classifier associates with it → the tool result carries
   policy-derived **candidate** grants ("this policy blocks network; if the
   failure was network-related, retry with the attached grant"). Child output
   may *order* candidates for UX, but never mints authority — a command printing
   "permission denied" changes nothing about what can be granted.

### 9.2 Unforgeable grant tokens

Grant strings must not be fabricable or inflatable by the model. Note the gate
already prevents *bypass* (grant-carrying calls are never auto-approved below
`unconfined` — §9.3); tokens defend against the remaining threats: **prompt
inflation** (fabricating `write:/` to social-engineer a broad approval),
**replay** across sessions/policy changes, and **reuse** against a different
command.

- Format: `lrsx1.<base64url(payload)>.<base64url(HMAC-SHA256)>`, keyed by a
  per-executor random key (executor lifetime, never serialized). The key itself
  is the session/instance binding: tokens cannot cross executors, processes, or
  restarts, so no session-id API is needed — deliberate, since executors are
  built before the session exists (swe late-bind pattern).
- Payload binds: policy generation (bumped on any policy/mode change, including
  `ModeSource` transitions), hash of (dir, command), the machine-readable
  delta, the **human-readable description** (so the prompt text itself is
  MAC-covered and cannot be inflated), and an expiry (`WithGrantTTL`, default
  15 min).
- Only `PlanGrants` and denial handling mint tokens. `DescribeGrant` verifies
  and returns the bound description for prompt display; verification failure →
  the tool errors without ever reaching a prompt, so a fabricated token cannot
  even generate an ask.
- `RunCommandWithGrants` re-verifies (MAC — which is itself the
  executor-instance binding — plus expiry, policy generation, command hash)
  before applying the delta for that single spawn.

### 9.3 Escalation is an ordinary gated call

No new loop control flow, but grants need a carrier on **two** paths:

- **Retry path** (post-denial): the tool result for a denied/failed command
  carries minted tokens; the model retries the *same* tool with
  `grants: [...]` in its args. Args are the carrier — `PermissionGate.Check`
  already receives `argsJSON` (harness/pkg/loop/deps.go:119), so no gate
  interface change. Gate rule: any grant-carrying call maps to **Ask** below
  the top ceiling.
- **Pre-ask path** (first call, no grants in args): today's runner cannot get
  approved deltas into `InvokableRun` — `applyDecision` (runner.go:366) never
  mutates args. So the approval itself carries them: the tool's `BuildRequest`
  attaches proposed grants (from `PlanGrants`) to the `PermissionRequest`; the
  human approves; `ApproveToolCall` returns the accepted tokens; the runner
  places them on the per-call ctx; the tool reads `tool.GrantsFromContext(ctx)`
  and merges with args-carried grants. Exact harness changes in §10.7.

Prompts show only `DescribeGrant`'s MAC-verified description. Existing approval
scopes apply; for `ScopeSession` the persisted match key is (tool, normalized
command, delta description) — not the token, which is single-mint — so a
repeated approved escalation re-asks nothing but always re-mints and
re-verifies. The persistence and re-mint mechanics this requires are §10.7
items 4 and 6.

## 10. Harness integration

Three small seams in harness (none import sandbox), plus consumer glue.

### 10.1 CommandRunner seam (`harness/pkg/tool`)

```go
// Stdlib types ONLY in these signatures — that is what lets sandbox satisfy
// them without importing harness.
type CommandRunner interface {
    RunCommand(ctx context.Context, dir, command string) (output []byte, exitCode int, err error)
}
type ArgvRunner interface { // direct argv exec, no shell interpretation
    RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error)
}
type GrantedRunner interface { // optional capability, probed by type assertion
    RunCommandWithGrants(ctx context.Context, dir, command string, grants []string) ([]byte, int, error)
}
```

`tools.NewBash(root, tools.WithRunner(r))`: nil runner = today's direct exec,
preserving bare-harness behavior. Injection at construction follows the
`ReadGuard` idiom; tool middleware is explicitly the wrong layer (wraps
JSON-in/blocks-out, never sees the spawn). **Grep is included in v1 via
`ArgvRunner`, not `CommandRunner`**: it builds an `rg` argv directly
(harness/pkg/tools/grep.go:290) with no shell involved, and forcing it through
a shell-string interface would reintroduce quoting/injection surface it never
had. `tools.NewGrep(root, tools.WithArgvRunner(r))` runs `rg` under a
read+exec, no-write, no-net policy view. (Resolves former open question 1.)

### 10.2 Gate posture (`tools.PermissionChecker`)

New options expressing what modes imply — harness sees **postures registered
per ceiling ordinal**, never mode names: auto-approve-edits, auto-approve-bash,
triviality-classifier slot, grant-carrying-calls-always-Ask, and the ceiling
clamp as a final checker stage (§8). Two constructors:
`WithPosture(posture, runner)` for a fixed mode, and
`WithCeilingPostures(src, table, runner)` for dynamic mode — the checker reads
`src.Current()` per Check and selects `table[ordinal]`, the same source the
`Executor` was built with so posture and enforcement never disagree. In both,
the last argument is the **one runner reference the checker holds**, probed
structurally for all its optional capabilities: `Level` (§10.3) and
`PlanGrants`/`DescribeGrant` (§10.7 item 6). No other checker↔executor edge
exists. The ordinal→posture table (~20 lines) is
built by the consumer from this module's documented mode semantics. This is the
resolution of "harness stays mode-agnostic" vs harness journaling ceiling
changes: harness knows *an ordered scale exists*; it never knows what
`trusted` means.

### 10.3 Guarantee interlock

The checker probes its configured runner for `interface{ GuaranteeBits() uint64 }`
(stdlib-only — no import) and gates each auto-approve posture on the **specific**
guarantees it requires, not a coarse level: the posture (consumer-built, §10.2)
carries a `RequiredGuarantees uint64` mask and the interlock passes only when
`bits & required == required`. `write`-mode bash-auto requires
`WriteBoundary | EnvScrub | ReadDenies`; `trusted` adds `NetworkBoundary` (and
`AddressNetwork` where the posture promises metadata/local-net semantics).
`Level()` remains a coarse UX rollup and an optional secondary floor
(default `LevelFull`; `LevelExternal` qualifies only because the deployment
explicitly constructed it). Consumers may consciously lower the
threshold to `LevelDegraded` (e.g. rung-2 fleets where the only gap is
subprocess glob-denies) — a logged, deliberate decision. No runner, or
`LevelNone`, means `trusted` behaves as `write`-with-asks. Fail-closed, same
invariant family as `EffectAsk = 0`.

### 10.4 Composition-root wiring (consumer)

```go
sandbox.Init() // first line of main (linux re-exec hook; no-op elsewhere)

// Static mode — the mode is known here, so posture is chosen directly:
ex, err := sandbox.NewExecutor(sandbox.PolicyFor(sandbox.Write, root))
pc      := tools.NewPermissionChecker(policy, tools.WithPosture(postureFor(sandbox.Write), ex))

// Dynamic — no local mode; posture is registered per ceiling ordinal (§10.2)
// and the checker reads the live ceiling through the same source:
ex, err := sandbox.NewExecutorDynamic(ceilingSource, root)
pc      := tools.NewPermissionChecker(policy, tools.WithCeilingPostures(ceilingSource, postureTable, ex))

// err == ErrUnsupportedPlatform etc. → ex == nil → tools run gated, never raw
bash := tools.NewBash(root, tools.WithRunner(ex))
grep := tools.NewGrep(root, tools.WithArgvRunner(ex.ReadOnlyView()))
// → loop.ToolSet → loop.Config → session.New(...)
```

Surfaced to end users as one knob (`swe.WithSecurityMode(...)` or the customer's
own builder option). A `session.Option` is deliberately not offered: Session
never constructs tools; the knob belongs where tools are built.

### 10.5 One policy, two enforcement points

The consumer adapts `Policy`'s read rules into the `ReadGuard` used by native
file tools, so `zerotrust` restricted-read and §5.3 denials bind the ReadFile
tool and `sh -c cat` identically. One source of truth; no drift between
in-process guards and OS enforcement. On rung 2 the `ReadGuard` is also the
only enforcement of glob denies (§7.5) — a documented gap that keeps
`Level() = LevelDegraded`.

### 10.6 Subagents and foreign agents

**In-process subagents are not OS processes and are untouched by enforcement.**
The Subagent tool's spawner calls `session.RunSubagent`
(swe/swarms/swe/spawner.go:130) — the child is another loop in the same
process; there is no spawn to wrap. The sandbox's effect is at **toolset
construction**: each sub-loop already gets its own session-scope
`PermissionChecker` (spawner.go:100), and that per-leaf build seam is where §8's
clamp applies — the child's executor and posture are built from
`min(role static mode, parent effective mode, session ceiling)`. Because
enforcement is per-spawn, mixed modes coexist in one process (operator's Bash
wraps at `write` while the reviewer's wraps at `readonly`). The clamp is also
what makes the Subagent tool safe to *auto-approve*: a spawn can never mint
authority its parent lacks.

**Foreign agents are OS processes and are sandboxed in v1.** The foreignloop
launcher (harness/pkg/foreignloop/claude, claude.go:68) execs an external agent
(e.g. Claude Code); Seatbelt profiles and namespaces are inherited by all
descendants, so wrapping the foreign agent process confines *everything it and
its own spawned commands do* — the honest trust boundary, since a foreign
agent's internal gates cannot be audited. Requirements:

- `ForeignAgentPolicy(base Mode, decl ForeignDecl)` preset: the base mode's FS
  policy plus egress to the agent's LLM API (`Net{Ports:{443}, DNS:true}` —
  hostname APIs need resolution, §5.2, so both are required) plus an env
  allowlist admitting the foreign agent's own credentials (its API key is *its*
  secret, not scrubbed — but harness's other tokens stay scrubbed).
- **Declare external isolation to the child** (env marker / the agent's own
  external-sandbox flag where it has one): nested sandboxes fail —
  `sandbox-exec` will not initialize inside an existing Seatbelt profile, and
  userns-in-userns is frequently blocked — so the foreign agent must be told
  not to erect its own.
- The entire foreign process tree shares one cgroup scope (§7.4).

### 10.7 Grant plumbing — exact harness changes

The grant flow (§9.3) is the one place needing more than the three seams. All
changes stay sandbox-vocabulary-free (tokens and descriptions are opaque
strings):

1. **Bash args schema** gains optional `grants []string` (and the tool docs
   tell the model: attach tokens received in a prior denial result, never
   invent them).
2. **`tool.GrantsFromContext(ctx) []string`** in `harness/pkg/tool`: the
   runner-populated per-call carrier for pre-ask-approved tokens; tools merge
   it with args-carried grants.
3. **`PermissionRequest` types** (permission_request.go): `BashRequest` gains
   `Grants []GrantDisplay{Token, Description string}` so prompts can render
   escalations. Descriptions are produced inside the tool's `BuildRequest` by
   probing its runner for `PlanGrants`/`DescribeGrant` (the tool holds the
   runner — the checker needs no describer seam); verification failure fails
   the build, so a fabricated token never reaches a prompt. These types are
   durable: the permission-request codec and command marshal fixtures must be
   updated together, with the new field optional so pre-existing journal
   entries decode unchanged.
4. **`command.ApproveToolCall`** gains `AcceptedGrants []string`; `runOne`
   places them on the per-call ctx (feeding seam 2), **and the runner passes
   that same ctx to `Permission.Grant`** for non-Once scopes —
   `Grant(ctx, toolName, argsJSON, scope)` otherwise sees only the original
   args, which in the pre-ask path contain no grants, and the promised
   (command, delta description) match key could never be persisted. Storage
   shape: the persisted approval record gains a new **optional** field
   `GrantDeltas []string` — the MAC-verified delta *descriptions* (never
   tokens), deduped and sorted; a rule matches only when tool, normalized
   command, and the delta-description set all match, and records without the
   field match only grant-free calls. Deny path unchanged.
5. **Checker convention**: a non-empty top-level `"grants"` field in `argsJSON`
   marks the call as an escalation → posture maps it to Ask below the top
   ceiling (part of the §10.2 posture options).
6. **Session-scoped repeats**: a later identical call matches the persisted
   grant-bearing rule and `Check` returns AutoApprove — but `Check` returns
   only an `Effect`, and the spawn still needs live tokens. The runner probes
   the checker for an optional stdlib-only capability,
   `ApprovedGrants(toolName, argsJSON string) []string` — implemented by the
   checker using the same runner reference it already holds from
   `WithPosture` (§10.2), so no new checker↔executor ownership edge is
   introduced: it calls that runner's `PlanGrants`, filters the candidates to
   the record's `GrantDeltas` via `DescribeGrant`, and the runner places the
   result on the per-call ctx exactly as in the pre-ask path. Tokens therefore stay single-mint and
   short-lived even under session-scope approvals.

## 11. External execution (cloud / containers / microVMs)

Mirrors Codex's `ExternalSandbox`: inside a container or microVM, the
environment is the isolation boundary and per-command wrapping is redundant.

- `NewExternalExecutor(ExternalDecl{...})` is an explicit, auditable declaration
  — "Docker/gVisor/Firecracker is the boundary; network egress handled by
  <NetworkVia>" — not merely the absence of a sandbox. It reports
  `LevelExternal`.
- Responsibility split when external: filesystem isolation → image + mounts;
  network → infra egress proxy; this module → pass-through (still applying
  `ExternalDecl.Env` scrubbing, which costs nothing and remains valuable).
- Boundary strength is the deployer's choice; plain Docker shares the host
  kernel — gVisor or a microVM (Firecracker/Kata) for hostile multi-tenant work.
- Because the seam is the executor interface, "cloud" is a different executor,
  not a disabled sandbox — a future `Container`/`Remote` executor implements the
  same `CommandRunner` against `docker exec` or a remote microVM without touching
  any tool or loop code.

## 12. v1 scope

**In v1**: modes + policy axes incl. EnvPolicy; deny-read defaults (incl.
in-workspace `.env`); metadata hard-deny (where expressible); Seatbelt backend;
Linux ladder (pure Go) with compilation reports and Level demotion; cgroup
limits; grant tokens (HMAC-minted, pre-ask + generic-denial tiers);
Level + gate interlock with configurable threshold; ModeSource + journaled
ceiling command + clamp; ReadGuard adaptation; Bash **and Grep** runner
injection; foreign-agent process wrapping; External executor.

**Deferred**:

- Per-path/per-destination denial telemetry and policy-delta precision (seccomp
  user-notification; ptrace/helper instrumentation explicitly rejected for v1
  complexity).
- Domain-level egress (netns + SNI-peek proxy — no MITM CA; cert-pinning safe).
- Method-level egress (GET-only "reading HTTPS") — requires opt-in MITM proxy.
- Prompt-injection classifier at the pre-ask hook.
- Windows native backend.
- Session-scoped executor daemon (one persistent sandbox per session; also the
  seam for sandboxing non-Bash tools and remote execution).

### 12.1 v1 acceptance matrix

| Scenario | Expected |
|---|---|
| macOS Seatbelt, `write` mode | writes outside ws+tmp fail; `.git` write fails; `~/.ssh` read fails; `.env` read fails; network `connect` fails; `Level = Full` (loopback+ports+DNS enforced; `Private`/metadata unsupported by SBPL → compile-to-blocked, so a policy needing address-scoping is `Degraded` — Task M1) |
| Linux rung 1, `write` mode | same as macOS, plus restricted-read verified in `zerotrust`; metadata IP unreachable under `trusted`; `Level = Full` |
| Linux rung 2, `write` mode | write boundary + `.git` carveout (enumerated allows) + fixed secret denies hold; `**/.env*` unenforced for subprocesses (ReadGuard still covers native tools); TCP limited to `Ports`; UDP blocked; `Level = Degraded`; auto-approve-bash OFF at default threshold |
| No sandbox available (rung 3 / nil runner) | Bash runs direct exec but `trusted` posture degrades to ask-everything (interlock); nothing auto-approved |
| Dynamic downgrade `trusted → readonly` mid-session | next Check clamped immediately; in-flight command finishes under old policy; journal has `SetSecurityCeiling`; stale session grants inert |
| Grant retry (post-denial) | denial → tool result carries minted token → model retries with `grants` → gate Asks with MAC-verified description → approved → single spawn with delta; fabricated token → tool error, no prompt |
| Pre-ask grant | classifier predicts `git push` needs net → BuildRequest attaches `PlanGrants` tokens → approval returns accepted tokens → runner puts them on per-call ctx → first spawn already carries delta; no run-fail-rerun |
| DNS under `trusted` (rung 2) | `curl https://example.com` resolves via TCP DNS (`RES_OPTIONS=use-vc`) on glibc; musl narrowing recorded in `CompileReport` |
| Env scrub | child of Bash sees baseline env only; `GITHUB_TOKEN`/`ANTHROPIC_API_KEY` absent; `TMPDIR` points into writable tmp |
| Metadata fetch under `trusted` (rung 1) | `curl 169.254.169.254` fails; `curl https://example.com` succeeds |
| cgroup v2 unavailable | command still runs sandboxed; limits recorded unenforced in `CompileReport`; `Level` unchanged |
| Foreign agent launch | child process tree confined; its LLM API reachable; harness env scrubbed except agent's allowlisted keys; agent told it is externally sandboxed |

## 13. Resolved policy decisions

Decided 2026-07-05 (Phase 0). Recorded here because each fixes a type shape or
test fixture. Adopted from the plan's recommendations; revisit if the pre-code
assumptions prove wrong during implementation.

1. **Writable tmp is `/tmp` only.** `$TMPDIR` locations outside `/tmp` (macOS
   `/var/folders/...`) are **not** made writable; instead the sandbox forces
   `TMPDIR=/tmp` via `EnvPolicy.Set`, so `/tmp` is enough for all use cases.
   `PolicyFor` expands `/tmp` (excludable per policy) as the single writable tmp
   root. Caveat: a few macOS libs read `_CS_DARWIN_USER_TEMP_DIR` via `confstr`
   regardless of `$TMPDIR`; revisit only if a real tool breaks.
2. **Triviality classifier** (`write` mode): **extend the existing
   `HardApproveRules` prefix rules** in v1. The posture's classifier slot (§10.2)
   is a prefix-rule matcher, not an execpolicy-style argv language (deferred).
3. **`trusted` default `Ports {443}` — not `80`.** `http://` stays gated;
   only `:443` is in the default trusted port set (relevant to the §5.4 metadata
   deny holding vacuously on rung 2).
4. **swe-level knob**: **`WithSecurityMode(Mode)`** sets the session's dynamic
   ceiling; per-role **static** modes are set in `BuildTools` at the composition
   root. Effective mode = `min(role static, session ceiling)` (§8, §10.4).
5. **Grant tokens**: TTL default **15 min** (`WithGrantTTL`); `ScopeSession`
   match keys use **capability-granularity** delta descriptions (e.g. "network
   egress"), not path granularity. Sets the `GrantDeltas` encoding (§9.3, §10.7).

Resolved during implementation:

6. **Seatbelt CIDR/network-filter expressiveness — RESOLVED (Task M1 spike,
   `docs/spikes/seatbelt-net.md`): SBPL cannot address-scope.** Its network host
   token is `*` or `localhost` only; literal IP/CIDR/subnet is rejected at
   profile-compile time (not bypassable via `require-not` or precedence). So
   macOS `trusted` does **not** get real `Private`/metadata semantics — both
   compile to **blocked** with a `CompileReport` entry, and `AddressNetwork` is
   always false on macOS (§7.1). Default-deny, port-scoping, loopback, and DNS
   (via the mDNSResponder unix socket, not outbound :53 — §5.2) all work and are
   enforced. The metadata hard-deny holds only vacuously (`:80` not in the
   default port set), identical to Linux rung 2.
