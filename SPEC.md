# sandbox module specification

Status: canonical implemented contract, 2026-07-19.

## 1. Scope and dependency boundary

`github.com/looprig/sandbox` validates immutable access profiles, constructs
per-consumer executors, enforces filesystem/network/process boundaries, reports
achieved guarantees, and issues authenticated post-decision spawn grants.

The module is independently usable. It has no LoopRig module dependency and no
knowledge of tools, permission files, interactive approvals, sessions, roles,
or product profile names. A consumer may connect its primitive structural seams
to any approval system without introducing a reverse dependency.

The sandbox threat actor is the spawned target and its descendants. The
executor, harness, and unrelated processes outside the target's enforcement
domain are trusted not to adversarially mutate the target filesystem
concurrently. In particular, an unsandboxed process running as the same host
UID is outside scope: it already has ambient same-user file and process
authority, and this module does not provide mutual isolation between such
processes.

## 2. Profile vocabulary

```go
type Access uint8

const (
	Deny  Access = 0
	Gated Access = 1
	Allow Access = 2
)

type Home uint8

const (
	IsolatedHome Home = iota
	RealHome
)

type Isolation uint8

const (
	Sandboxed Isolation = iota
	Unconfined
)

type RootAccess struct {
	Path  string
	Read  Access
	Write Access
}

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

type Profile struct { /* immutable normalized state */ }

func NewProfile(ProfileConfig) (*Profile, error)
func (p *Profile) AccessVersion() uint16
func (p *Profile) AccessFor(kind, scope string) (uint8, error)
func (p *Profile) Fingerprint() string
func Restrict(base, ceiling *Profile) (*Profile, error)
```

Access numeric values are part of ABI version 1 and may not be reordered. Zero
means deny, isolated HOME, and sandboxed execution. `NewProfile` requires a
canonical workspace root and rejects unknown enum values, relative additional
roots, contradictory roots, and any unusable zero `Profile`.

`AccessFor` recognizes exactly `command.execute`, `filesystem.read`,
`filesystem.write`, and `network`. Filesystem scopes are canonical paths,
`tree:<canonical-root>`, or `host:*`; command and network use an empty profile
scope. Unknown kinds or malformed scopes return errors.

`Restrict` takes the lower value under `Deny < Gated < Allow` for every access
field, intersects root access, prefers sandboxed execution and isolated HOME,
requires equal canonical workspace roots, and validates the result. Neither
input is mutated.

The profile fingerprint covers the ABI version, normalized access fields,
workspace and additional roots, HOME and isolation choices, unconfined
acknowledgement, and required guarantee contract. It excludes permission rules
and ephemeral grants.

## 3. Validation and isolation

An unconfined profile requires explicit acknowledgement and `Allow` for all
process filesystem and network fields. A direct child cannot enforce narrower
filesystem or network access. Command access may remain any value because an
executor can still require a valid command-start grant before the child starts.

Sandboxed profiles compile from deny-by-default. Workspace, additional-root,
host, and network access are added only as the profile or a verified per-spawn
grant permits. Fixed runtime support paths are a small, tested backend allowlist
and never imply general host access. Environment scrubbing and resource limits
are fixed executor safety behavior and cannot widen authority.

Filesystem rules resolve read, execute, and write independently. For literal
rules, the most-specific matching path wins; an explicit deny wins only a true
precedence tie. Exact scope outranks recursive scope at the same path, so an
exact allow can restore that object beneath a recursive deny without opening
its descendants. Glob denies are hard overrides regardless of literal
specificity. Backends must preserve this precedence or fail/narrow explicitly
under their documented compilation contract.

`IsolatedHome` points `HOME` at executor-owned owner-only storage. Every
executor has a separate owner-only TMPDIR beneath the set-owned root; the base
profile neither selects nor grants shared `/tmp`. `RealHome`
sets the real HOME path; access to that path is still governed by filesystem
rules. Absolute paths, traversal, symlinks, and working-directory changes may
not escape the compiled boundary.

## 4. Executor ownership

```go
func NewExecutorSet(*Profile, ...ExecutorSetOption) (*ExecutorSet, error)
func WithScratchRoot(string) ExecutorSetOption
func WithMaxExecutors(int) ExecutorSetOption
func WithGrantTTL(time.Duration) ExecutorSetOption
func WithEgressRoute(EgressRoute) ExecutorSetOption
func (s *ExecutorSet) For(key string) (*Executor, error)
func (s *ExecutorSet) Close() error
```

Scratch root and a positive executor limit are mandatory. The set creates one
owner-only child beneath the caller-owned root and removes only that child on
close. Each opaque key gets a separately keyed executor, HOME, and TMPDIR;
concurrent requests for the same key return the same executor. Closing the set
revokes all issued capabilities, cancels execution-scoped proxy activity, and
releases owned resources, including every compiled enforcement spec. There is
no public direct-executor constructor.
`WithGrantTTL` configures the positive maximum lifetime of grants minted by
every executor in the set; omission uses the fixed 15-minute default.

`RunCommand` selects the platform command interpreter: Darwin and Linux use
`/bin/sh -c`, while Windows uses the canonical System32
`cmd.exe /D /S /C` and never trusts `%ComSpec%`. `RunArgv` remains shell-free.

## 5. Grant lifecycle

The only capability-minting operation is post-decision issuance:

```go
func (e *Executor) GrantVersion() uint16
func (e *Executor) IssueGrant(
	ctx context.Context,
	executionID, command, workingDirectory string,
	kind, scope, enforcementClass, target string,
	expiresUnixMilli int64,
) (string, error)
```

Grant ABI version 1 accepts only these typed enforcement classes:

| Class | Binding |
|---|---|
| `filesystem.path.read.v1` | one canonical path |
| `filesystem.tree.read.v1` | one canonical tree |
| `filesystem.host.read.v1` | broad host read |
| `filesystem.path.write.v1` | one canonical path |
| `filesystem.tree.write.v1` | one canonical tree |
| `filesystem.host.write.v1` | broad host write |
| `network.proxy-target.v1` | normalized transport, hostname, and port |
| `network.broad.v1` | backend-enforceable broad TCP port plus platform resolver |
| `command.start.v1` | exact normalized command start |

Issuance occurs only after an external approval decision or compatible saved
rule satisfies a `Gated` requirement. Each token is short-lived and valid for
one spawn. It binds the executor, execution ID, exact normalized command,
canonical working directory, profile fingerprint, non-secret route fingerprint,
achieved guarantee set, typed class, normalized target, and expiry. It cannot
open `Deny`, cross executors, commands, directories, routes, or profiles, and is
never stored as a permission record. A filesystem token also binds the
canonical target and the device/inode/type identity of the deepest existing
ancestor. Verification walks that canonical ancestor without following
symlinks, rejects identity drift, and requires a suffix that was missing at
approval time to remain missing until spawn-policy compilation.

`filesystem.path.*` applies only to the exact canonical object;
`filesystem.tree.*` applies recursively. Seatbelt compiles those as `literal`
and `subpath`, respectively. Landlock accepts an exact grant only for an
existing regular file whose identity remains bound by the acquired descriptor
and whose link count is exactly one. An exact directory, non-regular file,
nonexistent target, or multiply-linked file is not representable and fails with
`ErrGrantUnsupported` rather than widening to a tree.

Verification alone is insufficient: the executor must use `command.start.v1`
to authorize the exact start and apply filesystem/network classes while
compiling the spawn policy. A valid token whose capability cannot be enforced
fails closed.

A prepared `command.execute` requirement uses `command.start.v1` and the exact
normalized command target. When access is `Gated`, an external saved exact,
wildcard, or family rule may satisfy the decision, after which `IssueGrant`
mints an exact-command, single-spawn token. `Allow` requires no command token,
and `Deny` never mints one. All gated requirements are resolved by one combined
decision; command start does not introduce a second prompt.

## 6. Network target enforcement

### 6.1 macOS v1

For `network.proxy-target.v1`, Seatbelt denies direct remote egress and allows
the child to contact only a randomly bound loopback proxy owned by the
executor. An execution-bound credential authenticates the child request. The
proxy supports HTTP forwarding and HTTPS `CONNECT`, normalizes and enforces the
transport/hostname/port target, strips local proxy credentials and hop-by-hop
headers, and leaves application TLS end-to-end. Releasing an execution
authorization cancels its in-flight forward requests and closes both sides of
its CONNECT tunnels, including tunnels racing registration; other execution
identities remain active.

An explicit organization HTTP/HTTPS proxy may be configured upstream. Its
credentials remain in the supervisor and are excluded from environments,
fingerprints, prompts, logs, and audit data. Route selection is fingerprinted
without secrets. Upstream connection, resolution, or authentication failure
fails closed and never retries directly.

Hostname/port and resolved address-class enforcement are distinct guarantees.
An upstream-resolved route reports address enforcement only when the upstream
provides a trusted guarantee contract. HTTPS method/path enforcement is not
claimed without TLS termination. `AddressNetwork` is composed only when the
backend reports `TargetNetwork` and the selected route reports its address
guarantee.

Proxy-unaware clients cannot use a target grant. Direct egress remains denied,
so ordinary Git-over-SSH fails closed. An external evaluator may instead request
a clearly displayed `network.broad.v1` grant bound to the exact command, but
only when the backend can enforce the described broad boundary.
The broad grant includes platform DNS resolution in the same approved delta.
On macOS this is the mDNSResponder socket. Linux rung 1 permits UDP/TCP port 53;
rung 2 narrows DNS to TCP/53 and injects `RES_OPTIONS=use-vc`, whose resolver
compatibility limitation remains visible in the compile report.

### 6.2 Linux v1

Neither Linux rung reports target-network enforcement in v1. The private
network namespace used by rung 1 has no bridge to the parent loopback proxy;
rung 2 can restrict ports but not destination addresses. A target grant fails
closed on both rungs. A broad exact-command grant is available only when that
rung can enforce its declared class; it never silently substitutes for a target
grant.

### 6.3 Deferred v2 work

- bridge a rung-1 private network namespace only to the parent enforcement
  proxy while preserving deny-direct-egress;
- add address-aware rung-2 enforcement before reporting target support;
- add SOCKS5 child and upstream support;
- define complete SSH proxy integration, including key/agent, known-hosts,
  isolated-HOME, host rewrite, and organization proxy port behavior;
- add transparent TCP interception only where it preserves confinement;
- add opt-in TLS termination with an explicit managed-CA lifecycle; and
- strengthen TLS destination binding for clients whose CONNECT hostname cannot
  be trusted.

## 7. Guarantees and platform behavior

Guarantees report achieved enforcement, not requested policy. Executor
construction or spawn fails when the backend cannot provide a guarantee needed
by a non-`Allow` filesystem or network field. `NewProfile` remains
platform-independent. Narrower compilation is permitted only when reported;
wider compilation is forbidden.

A compiled `enforce.Spec` may own immutable enforcement resources and exposes
an optional idempotent release operation. An executor owns its base compiled
spec until set close. A grant-recompiled spec is transient and is released only
after its spawn and process tree finish. Mutable per-spawn state remains owned
by the configure and cleanup closures returned by `Wrap`; compiled ownership
does not permit mutable state to be shared between concurrent spawns.

Windows policy intent and compile reports use the exact named entry
`windows.runtime-baseline` for the fixed operating-system runtime closure needed
to start supported targets. The entry records whether that closure is enforced,
narrowed, or unavailable; it is not general host-read authority and does not by
itself earn a guarantee bit.

macOS uses Seatbelt. Linux selects the strongest supported Landlock,
namespace, seccomp, nftables, and cgroup mechanisms. Linux consumers call
`Init()` first in `main` for confinement-helper dispatch; an executor requiring
that path rejects missing initialization. Unsupported production platforms fail
closed. Direct execution exists only for an explicitly acknowledged unconfined
profile.

The macOS Seatbelt profile has no unfiltered `file-read*` or `process-exec*`
allow. Its tested startup closure consists of process fork/info, sysctl and Mach
bootstrap access, data access to the literal root directory required by dyld,
the system shell-selector read, literal metadata on the ancestor chain of each
allowed root, and read/execute access scoped to fixed runtime or
consumer-configured roots. The compiler emits both canonical `/private/...`
and symlink-equivalent public spellings for the same configured object, for
both allows and later carveout denies. Network target enforcement permits only
the executor's exact loopback proxy listener port, denies direct remote egress,
and reports `TargetNetwork`; a host-read-denied profile reports `ReadBoundary`.
The fixed runtime closure does not grant broad `/usr`, `/etc`, `/System`, or
`/Library`: executable trees, library/certificate trees, and exact resolver or
loader configuration files have separate minimum access bits.

Linux preserves its explicit-root mount/Landlock, seccomp, nftables, and cgroup
mechanisms. A parent proxy listener is not reachable as a target-scoped route in
v1 and never earns `TargetNetwork`; issuing that target grant fails closed.
Failure to select a usable Linux rung returns `ErrSandboxUnavailable` rather
than a null backend. On other operating systems `Sandboxed` is unavailable;
the null backend accepts only an acknowledged `Unconfined` profile.

Supervised spawns (`Executor.PrepareProcess`/`Process.Start`) additionally
report a per-spawn process-tree teardown contract through
`Process.LifetimeContainment`. Linux and Windows retain kernel-enforced
teardown (`Enforced`: Rung 1's PID namespace, Rung 2's delegated cgroup v2, or
a Windows Job). macOS Supervised spawns instead receive best-effort lifetime
containment (`BestEffort`: process-group teardown plus process-table-closure
descendant tracking), with the downgrade reported per spawn rather than
assumed; Seatbelt access-confinement guarantees are unaffected. This
supersedes the earlier fail-closed posture (Task 12c), which rejected every
macOS Supervised spawn before it started; the 2026-08-06 acceptance decision
accepts the downgrade because an escaped descendant remains fully confined by
the spawn's Seatbelt profile, orphaned but never unconfined. See
`docs/lifetime-containment.md`.

### 7.5 Linux filesystem snapshots

Both Linux rungs share Landlock's additive allowlist. On each read, execute, or
write axis where a recursive allow contains a nested literal deny, they
enumerate unaffected siblings at spawn instead of granting the covering
directory as a whole on that axis. Pre-existing unaffected children retain
their compiled authority. A denied target that exists at spawn is omitted from
the enumerated rules for each denied axis.

Directory rules authorize hierarchies, but a directly enumerated regular-file
rule is inode-scoped in Landlock. Enumeration therefore opens the inspected
file without following symlinks, verifies that the opened descriptor names the
inspected identity and a single-link regular file, transports that descriptor
to stage 2, and validates its type and single-link count immediately before and
after adding the Landlock rule. A mismatch, unsupported node type, or
multiple-link inode is omitted or aborts setup in the fail-closed or
fail-narrow direction; the pathname is never reopened to grant a different
inode. Directory ancestor rules remain hierarchy-scoped.

Write narrowing also protects denied read and execute topology. A recursive
read or execute deny derives write denial throughout that denied subtree,
preventing the target from moving, linking, or recreating an allowed inode
under a protected pathname. An exact read or execute deny withholds
directory-entry mutation at the enumerated boundary while preserving
separately retained descendant authority according to exact-scope precedence.
Pre-existing unaffected writable siblings may remain writable; newly created
entries receive no authority on an axis whose covering directory rule was
withheld. The same rules apply when the protected target is absent at spawn.

Rung 1 additionally builds a mount view: read-only carveouts are mount
re-masked, fixed denies without restorations use empty masks, and paths outside
the explicit view remain invisible. Those mount mechanisms enforce the
protected path itself, but they do not remove the shared Landlock sibling
enumeration needed for defense in depth and restored literal precedence.
Therefore Rung 1 has the same per-axis snapshot narrowing as Rung 2 even when
its mount re-mask is fully enforced.

This spawn snapshot is intentionally narrower than the requested covering allow
on each affected axis. Against the sandboxed target and its descendants, it
prevents a future `.git`, `.looprig`, or fixed secret path from acquiring
authority on a denied axis after confinement and preserves the rule-precedence
contract in §3. It does not claim atomic protection against a process outside
the Landlock domain later hardlinking or renaming an allowed inode to a denied
pathname; that actor is outside §1's threat boundary. Both rungs record the
narrowing in `CompileReport` and never restore whole-root authority merely
because a literal deny or carveout is absent.

## 8. Security invariants

- Sandbox never prompts, reads permission files, or imports Harness.
- `Deny` is not grantable; `Gated` is blocked without a valid spawn token.
- Grant issuance happens only after the external decision and never persists.
- Filesystem targets are canonical and checked against traversal and symlink
  escape, then identity-revalidated without following components before spawn.
- Direct egress cannot bypass a target proxy.
- Secret route credentials never cross into the child or durable metadata.
- Executor and set closure revoke outstanding authority.
- An execution release cancels only that execution's active proxy work.
- On Linux, an exact file grant and every directly enumerated regular-file
  allow are descriptor-bound and require a single-link regular inode through
  Landlock rule installation; unsupported or changed identities fail closed or
  narrow.
- Missing enforcement fails closed; sandboxed execution never falls through to
  direct host execution.

## 9. Verification requirements

Tests cover every access field and value; validation and fail-closed zero
behavior; `Restrict`; fingerprint stability; executor memoization, limits,
per-key HOME/grant isolation, and close; command/cwd/profile/route/expiry grant
bindings; filesystem traversal and symlink escape; unconfined acknowledgement;
platform guarantee honesty; proxy authentication and direct-bypass denial;
organization-proxy chaining and credential containment; and the Linux target
grant failure behavior. Linux coverage includes direct-file descriptor
transport and closure, inspect/open identity swaps, pre-installation link-count
changes, pre-existing hardlink aliases, and target-attempted link and rename
replacement. Platform integration tests accompany each backend.
Conformance assertions are one-way security claims: when a backend claims a
boundary, every probe covered by that boundary must be denied. Withholding a
guarantee never requires an otherwise honest backend to permit the operation.
