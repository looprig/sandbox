# sandbox

`github.com/looprig/sandbox` is a standalone Go module for constructing explicit
access profiles and enforcing them around spawned commands. It does not import
Harness, open approval prompts, parse tool arguments, or persist permissions.

> Implementation status: this document specifies the greenfield target contract
> being implemented on `feat/sandbox-access-profiles`. Until that branch is
> complete, exported code may temporarily lag this contract.

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
such as CodeRig construct their own product profiles. `Restrict(base, ceiling)`
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

`IsolatedHome` gives each executor an owner-only scratch HOME. `RealHome`
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
identity, and isolated HOME. `Close` revokes the set and removes only the child
directory it owns.

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
achieved guarantees, enforcement class, normalized target, and expiry. The
executor verifies the token before spawning: `command.start.v1` authorizes that
exact start, while filesystem and network classes modify the compiled policy.
Tokens are never durable permission records.

A prepared `command.execute` requirement carries `command.start.v1` with the
exact normalized command as its target. A saved exact, wildcard, or family
permission may satisfy the external gate, but the resulting token always binds
only that exact command and one spawn. `Allow` starts require no token, `Deny`
never mints one, and command plus filesystem/network requirements share one
combined approval rather than opening a second prompt.

## Target-scoped network enforcement

On macOS, target-scoped HTTP and HTTPS traffic uses an authenticated loopback
forward/`CONNECT` proxy outside the child boundary. Seatbelt permits the child
to reach only that listener and denies direct remote egress. The proxy enforces
the normalized hostname and port, leaves TLS end-to-end, and may chain through
an explicitly configured organization HTTP/HTTPS proxy. Organization proxy
credentials stay in the supervisor. Upstream failure never falls back to a
direct connection.

Hostname and address-class enforcement are separate guarantees. HTTPS method
and path are not visible through opaque TLS and are not claimed. Proxy-unaware
clients fail closed. Git over SSH therefore needs either a future raw-TCP
adapter or an honestly broad, exact-command grant supported by the backend.

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

## Honest guarantees

Construction and spawning report what the selected backend actually enforces.
A required filesystem or network guarantee that is unavailable causes a
fail-closed error; production never silently runs a sandboxed profile directly.
The profile and route fingerprints cover all durable authority inputs while
excluding permission rules, secret proxy credentials, and ephemeral grants.

## Linux initialization

Linux consumers call `sandbox.Init()` as the first statement in `main` so a
re-executed confinement helper can dispatch before application startup. Other
platforms treat it as a no-op. A Linux executor that requires helper dispatch
fails construction when initialization was omitted.
