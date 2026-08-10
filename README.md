# sandbox

`github.com/looprig/sandbox` is a standalone Go module for constructing explicit
access profiles and enforcing them around spawned commands. It does not import
Harness, open approval prompts, parse tool arguments, or persist permissions.

## Module layout

Consumers import one path — `github.com/looprig/sandbox` — and never anything
below it. The root package is a facade of type aliases and thin forwarders, so
`sandbox.Profile` and `profile.Profile` are the *same* type and `errors.Is`
works against the re-exported sentinels.

```
sandbox.go              the public facade: aliases + forwarders
init_{linux,other}.go   Init(), at the path every main() calls it from

pkg/                    importable by consumers
  profile/              Profile, the authority enums, CompileReport, Guarantees
  network/              Target, Route, RouteResolver, route dialing, the egress Proxy
  sandboxtest/          the reusable executor conformance suite

internal/               implementation; not importable outside this module
  policy/               effective policy, FS vocabulary, compiled rules, path handles
  enforce/              the Backend contract and per-spawn Spec every backend implements
  darwin/               Seatbelt: SBPL generation and the darwin backend
  linux/                the enforcement ladder: namespaces, Landlock, seccomp,
                        nftables, cgroups, capability probing, stage-2 re-exec
  windows/              restricted-token and installed-broker Windows tiers
  winpath/              handle-owned Windows path identity and namespace rejection
  platform/             backend selection; the only importer of OS backends
  exec/                 Executor, ExecutorSet, process tree, and the grant tokens
  safetext/             the shared untrusted-identifier predicate
  testsupport/          fixtures shared across the suites

cmd/
  sandbox-host/          protected Windows broker service and restricted runner
```

Dependencies point one way: `pkg/*` ← `policy` ← `enforce` ← OS backends ←
`platform` ← `exec` ← the facade. `winpath` is a Windows leaf used by policy
and enforcement code. Nothing under `internal/` imports the root package, which
is why the executor's own tests live beside it in `internal/exec` rather than
at the root.

## Profile contract

Consumers choose every access value directly:

```go
type Access uint8

const (
	Deny  Access = 0
	Gated Access = 1
	Allow Access = 2
)

type ProfileConfig struct {
	WorkspaceRoot   string
	WorkspaceRead   Access
	WorkspaceWrite  Access
	HostRead        Access
	HostWrite       Access
	Network         Access
	Command         Access
	Home            Home
	Isolation       Isolation
	AdditionalRoots []RootAccess
	AckUnconfined   bool
}

profile, err := sandbox.NewProfile(config)
```

The zero access value is `Deny`; the zero HOME choice is `IsolatedHome`; and
the zero isolation choice is `Sandboxed`. A canonical workspace root is always
required. Invalid enum values, relative or contradictory roots, and an
unacknowledged or inconsistent unconfined configuration fail validation.

The module deliberately provides no named profile combinations. Applications
Product composition roots construct their own product profiles. `Restrict(base, ceiling)`
returns the component-wise, immutable intersection of two profiles and never
widens `base`.

`Profile.AccessVersion` and `Profile.AccessFor` form a dependency-free,
built-in-only seam for approval systems. Version 1 supports
`command.execute`, `filesystem.read`, `filesystem.write`, and `network`.
Unknown kinds, malformed scopes, and unsupported versions fail closed.

## Enforcement

`Sandboxed` execution compiles the normalized profile into the strongest
available OS boundary. `Gated` capabilities remain blocked unless that spawn
carries a valid grant for the exact approved delta. `Deny` cannot be opened by
a grant. `Allow` is included in the base spawn policy.

`Unconfined` runs with the invoking user's process authority and requires
`AckUnconfined`. Filesystem and network fields must all be `Allow`, because a
direct process cannot enforce narrower values. Command execution may still be
denied or gated before the process starts; a gated start requires the executor
to verify a `command.start.v1` grant.

`IsolatedHome` gives each executor an owner-only scratch HOME. Every executor
also receives a distinct owner-only TMPDIR under the `ExecutorSet` scratch
root; shared `/tmp` is not implicitly writable. `RealHome`
exposes the caller's HOME value, but filesystem access remains controlled by the
profile. Fixed runtime paths such as dynamic loaders and `/dev/null` are backend
implementation necessities, not implicit host-data access.

The macOS compiler has no broad file-read or process-exec preamble. Its tested
startup closure permits root-directory data, literal ancestor metadata for
configured roots, the system shell selector, and read/execute only below fixed
runtime or consumer-configured roots. Symlink-equivalent `/private` and public
path spellings are emitted together for allows and carveout denies. A denied
host-read profile therefore reports `ReadBoundary` honestly.

Consumers create an `ExecutorSet` with an explicit scratch root and maximum
executor count. Each opaque key receives an independent executor, grant
identity, HOME, and TMPDIR. `Close` revokes grants and proxy activity, then
removes only the child directory it owns. Direct executor construction is not a
public lifecycle path. `WithGrantTTL` optionally sets a positive maximum grant
lifetime for every executor in the set; omission uses the 15-minute default.

## Post-decision grants

An approval system calls `Executor.IssueGrant` only after a `Gated` requirement
has been approved by a user or compatible durable rule. It issues one
short-lived, single-spawn token for one typed enforcement class:

- `filesystem.path.read.v1`
- `filesystem.tree.read.v1`
- `filesystem.host.read.v1`
- `filesystem.path.write.v1`
- `filesystem.tree.write.v1`
- `filesystem.host.write.v1`
- `network.proxy-target.v1`
- `network.broad.v1`
- `command.start.v1`

Every token binds its executor, execution ID, exact normalized command,
canonical working directory, profile fingerprint, non-secret route fingerprint,
achieved guarantees, enforcement class, normalized target, and expiry.
Filesystem grants additionally bind the canonical target and the identity of
its deepest existing ancestor; target replacement or a symlink swap before
spawn fails closed. `filesystem.path.*` is exact while `filesystem.tree.*` is
recursive. The
executor verifies the token before spawning: `command.start.v1` authorizes that
exact start, while filesystem and network classes modify the compiled policy.
Tokens are never durable permission records.

A prepared `command.execute` requirement carries `command.start.v1` with the
exact normalized command as its target. A saved exact, wildcard, or family
permission may satisfy the external gate, but the resulting token always binds
only that exact command and one spawn. `Allow` starts require no token, `Deny`
never mints one, and command plus filesystem/network requirements share one
combined approval rather than opening a second prompt.

## The gate seam: using `Gated` standalone

There is **no gate interface to implement**. This module deliberately defines no
`Gate`, `Approver`, or `Prompter` type, because doing so would drag an approval
model — prompts, rule files, TTLs, persistence — into a package whose only job
is OS confinement. Instead `Gated` is wired through two plain method calls, and
everything between them is yours.

**1. Ask the profile.** `AccessFor` is the read side. It is dependency-free and
answers with the fixed numeric `Access` for a normalized capability:

```go
if p.AccessVersion() != 1 {
	return errors.New("unsupported profile ABI") // fail closed on an unknown version
}
access, err := p.AccessFor("filesystem.write", "/srv/app/build")
// access is 0 Deny, 1 Gated, 2 Allow
```

| `kind` | valid `scope` | meaning |
| --- | --- | --- |
| `command.execute` | `""` | may a command start at all |
| `network` | `""` | may the process reach the network |
| `filesystem.read` | `/abs/path` | read at one exact path |
| `filesystem.read` | `tree:/abs/path` | read anywhere under a configured root |
| `filesystem.read` | `host:*` | read anywhere outside the configured roots |
| `filesystem.write` | same three scopes | the write equivalents |

Unknown kinds, malformed scopes, a `tree:` scope naming a path that is not a
configured root, and an unconstructed profile all return an error rather than a
permissive value.

**2. Run your own approval.** `Deny` is final and `Allow` needs nothing, so only
`Gated` reaches your gate. What happens there is entirely your product's
business: an interactive prompt, a saved rule, a policy server, a CI allowlist.
This module never sees it.

You cannot get this step wrong by accident. `IssueGrant` does not trust the
caller to have asked: it re-reads `AccessFor(kind, scope)` itself and refuses
anything that is not `Gated` — `ErrGrantDenied` for `Deny`, `ErrGrantUnsupported`
for `Allow`. A bug in your gate therefore fails closed rather than minting
authority the profile never offered.

**3. Tell the executor.** Once *you* have decided yes, mint a token and spend it:

```go
token, err := executor.IssueGrant(ctx,
	executionID,      // your identifier for this one execution
	"go build ./...", // the exact normalized command
	"/srv/app",       // canonical working directory
	"filesystem.write", "/srv/app/build",     // the kind/scope you approved
	sandbox.GrantClassFilesystemPathWrite,    // the enforcement class
	"/srv/app/build",                         // the normalized target
	time.Now().Add(30*time.Second).UnixMilli(),
)
out, code, err := executor.RunCommandWithGrants(ctx, executionID, "/srv/app", "go build ./...", []string{token})
```

`class` selects the enforcement, and `scope`/`target` must agree with it exactly
or the mint fails closed:

| class | `kind` | `scope` | `target` |
| --- | --- | --- | --- |
| `command.start.v1` | `command.execute` | `""` | the exact normalized command |
| `filesystem.path.read.v1` | `filesystem.read` | `/abs/path` | the same `/abs/path` |
| `filesystem.path.write.v1` | `filesystem.write` | `/abs/path` | the same `/abs/path` |
| `filesystem.tree.read.v1` | `filesystem.read` | `tree:/abs/path` | `/abs/path` |
| `filesystem.tree.write.v1` | `filesystem.write` | `tree:/abs/path` | `/abs/path` |
| `filesystem.host.read.v1` | `filesystem.read` | `host:*` | `host:*` |
| `filesystem.host.write.v1` | `filesystem.write` | `host:*` | `host:*` |
| `network.proxy-target.v1` | `network` | `""` | `tcp:host:port` |
| `network.broad.v1` | `network` | `""` | `tcp:*:port` |

Use the exported `sandbox.GrantClass*` constants rather than the literals: the
strings are the shipped enforcement contract, and the constants are what a
rename is checked against.

### Errors your gate keys on

`RunCommand` is the shortest path — it needs no execution ID and no tokens — and
it tells you when a gate is required:

- `ErrGrantRequired` — a capability is `Gated` and no token covered it. **This is
  the signal to open your gate**, then retry via `RunCommandWithGrants`.
- `ErrGrantDenied` — the capability is `Deny`. Do not prompt; there is nothing a
  user could approve.
- `ErrGrantExpired`, `ErrGrantReplay`, `ErrGrantWrongCommand`,
  `ErrGrantWrongExecution`, `ErrGrantWrongWorkingDirectory` — the token did not
  bind to this spawn. Treat these as bugs in the calling code, not as prompts.
- `ErrGrantTargetChanged` — the granted path was replaced or symlink-swapped
  between approval and spawn. Never retry automatically.

Match them with `errors.Is`.

### What a token is, and is not

A token is a single-spawn capability, not a saved permission. It is bound to the
executor, execution ID, exact command, canonical working directory, profile
fingerprint, route fingerprint, achieved guarantees, class, normalized target,
and expiry — and for filesystem classes, to the identity of the target's deepest
existing ancestor. It is consumed by one spawn and then refused as a replay.

So a durable rule in *your* system ("always allow `go build` in this workspace")
is perfectly reasonable; it just means your gate answers without asking a human.
It never means a longer-lived token. Persistence belongs to you; enforcement
belongs here.

## Target-scoped network enforcement

On macOS, target-scoped HTTP and HTTPS traffic uses an authenticated loopback
forward/`CONNECT` proxy outside the child boundary. Seatbelt permits the child
to reach only that listener and denies direct remote egress. The proxy enforces
the normalized hostname and port, leaves TLS end-to-end, and may chain through
an explicitly configured organization HTTP/HTTPS proxy. Organization proxy
credentials stay in the supervisor. Upstream failure never falls back to a
direct connection. Releasing an execution credential cancels its active forward
requests and CONNECT tunnels without disturbing other executions.

Hostname and address-class enforcement are separate guarantees. HTTPS method
and path are not visible through opaque TLS and are not claimed. Proxy-unaware
clients fail closed. Git over SSH therefore needs either a future raw-TCP
adapter or an honestly broad, exact-command grant supported by the backend.
`network.broad.v1` includes the platform resolver authority needed for hostname
clients; it does not require a second DNS approval.

Neither Linux enforcement rung reports target-network enforcement in v1. A
target grant fails closed there. A consumer may instead request a visibly broad,
exact-command-bound grant only when the selected Linux backend can enforce that
broader boundary.

Linux keeps its existing explicit-root Landlock/mount enforcement and never
turns a parent loopback proxy port into a target-network guarantee. Hosts with
no usable Linux rung fail executor construction instead of selecting a direct
fallback. Other operating systems likewise reject `Sandboxed`; only an
explicitly acknowledged `Unconfined` profile may run directly.

Deferred v2 work includes a Linux rung-1 bridge from the private network
namespace to the parent proxy, address-aware rung-2 enforcement, SOCKS5,
complete SSH proxy integration, transparent TCP interception, opt-in TLS
termination with a managed CA, and stronger TLS destination binding.

## Windows modes and setup

Windows exposes three selection modes:

- `WindowsRestrictedToken` applies a restricted interactive-user token, a Job,
  UI restrictions, an explicit handle list, and temporary ACL restrictions.
  Because same-session Windows brokers can retain the user's full authority, v1
  honestly reports only `GuaranteeEnvScrub` and `LevelNone`.
- `WindowsElevated` requires a verified installation-owned LocalSystem broker
  and restricted local accounts. It never falls back to the interactive tier.
- `WindowsAuto` uses elevated setup when the profile requires its guarantees
  and falls back to restricted mode only when setup is absent, not stale.

Setup is an explicit elevated lifecycle operation. A product normally builds
`cmd/sandbox-host` and passes its immutable output to a small privileged setup
helper:

```go
cfg := sandbox.WindowsSetupConfig{
	InstallationID: "my-product",
	StateRoot:      `C:\ProgramData\MyProduct\Sandbox`,
	HostBinary:     `C:\build\sandbox-host.exe`,
	RuntimeEvidencePath: `C:\build\runtime-evidence.json`,
	ProxyPorts:     []uint16{43191, 43192},
}
if err := sandbox.SetupWindowsSandbox(ctx, cfg); err != nil {
	return err
}
status, err := sandbox.InspectWindowsSandbox(ctx, cfg)
if err != nil || !status.Ready {
	return fmt.Errorf("Windows sandbox is not ready: status=%+v err=%w", status, err)
}

set, err := sandbox.NewExecutorSet(profile,
	sandbox.WithScratchRoot(scratch),
	sandbox.WithMaxExecutors(4),
	sandbox.WithWindowsSandboxMode(sandbox.WindowsElevated),
	sandbox.WithWindowsSandboxStateRoot(cfg.StateRoot),
)
```

Cleanup is also explicit and must run elevated:

```go
if err := sandbox.RemoveWindowsSandbox(ctx, cfg); err != nil {
	return err
}
status, err := sandbox.InspectWindowsSandbox(ctx, cfg)
if err != nil || status.Ready {
	return fmt.Errorf("Windows sandbox residue: status=%+v err=%w", status, err)
}
```

`RuntimeEvidencePath` must name the approved Task 5 exact-token evidence from
the matching Windows build, architecture, filesystem, Go toolchain, and source
revision. Setup copies it into protected installation state and fails closed
when any required runtime row is missing, skipped, stale, or modified.

Windows v1 supports canonical local DOS-drive roots on NTFS or ReFS. UNC/SMB,
FAT/exFAT, drive-relative paths, alternate streams, object-manager/device
namespaces, `GLOBALROOT`, named pipes, and raw devices fail closed. Broad
host-wide filesystem grants are not supported.

| Guarantee | Restricted token v1 | Elevated v1 |
| --- | --- | --- |
| process boundary | no | yes |
| write boundary | no | yes when ACL projection succeeds |
| read boundary | no | yes for supported roots and runtime baseline |
| environment scrub | yes | yes |
| network boundary | no | yes for the offline account |
| address network | no | when the configured route earns it |
| resource limits | no | when every requested Job limit reads back |
| target network | no | yes through the authenticated proxy |

V1 uses one installed host process per installation. It does not support
service sharding or multiple independent proxy owners for one installation.

Important current status: the Windows implementation and cross-build coverage
exist, but production elevated readiness remains deliberately unavailable until
the exact restricted-token/runtime matrix passes and is reviewed on supported
disposable Windows 11 and Windows Server workers. Setup inspection therefore
must not be treated as ready based on compile-only or Windows 10 evidence.

## Honest guarantees

Construction and spawning report what the selected backend actually enforces.
A required filesystem or network guarantee that is unavailable causes a
fail-closed error; production never silently runs a sandboxed profile directly.
The profile and route fingerprints cover all durable authority inputs while
excluding permission rules, secret proxy credentials, and ephemeral grants.
`AddressNetwork` is reported for a target route only when both the backend
enforces `TargetNetwork` and the selected route supplies an address guarantee.

## Linux initialization

Linux consumers call `sandbox.Init()` as the first statement in `main` so a
re-executed confinement helper can dispatch before application startup. Other
platforms treat it as a no-op. A Linux executor that requires helper dispatch
fails construction when initialization was omitted.
