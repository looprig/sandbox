# Windows Sandbox Dual-Tier Design

Status: approved direction, detailed design, 2026-07-21.

This document extends the canonical contract in `SPEC.md` to Windows. It adds
two Windows enforcement tiers while preserving the module's existing rule:
compiled enforcement may be narrower than requested, but it must never be
wider, and a backend must never claim a guarantee that its mechanism does not
enforce.

The design is informed by the Windows implementation in OpenAI Codex, the
subprocess and escape tests in Grok, and Looprig's existing profile, grant,
proxy, and Job Object machinery. Goose has permission prompts and container
integration but no native Windows OS-confinement backend to reuse.

## 1. Decision

Ship both Windows tiers:

1. `WindowsRestrictedToken`: no administrative setup. It confines the process
   tree and filesystem writes by running the current user through a restricted
   token with one or more restricting capability SIDs.
2. `WindowsElevated`: one-time administrative setup. It uses dedicated offline
   and online local accounts, account-scoped firewall rules, full restricting
   SIDs for read and write confinement, a protected runner, and a minimal
   LocalSystem broker that keeps account credentials out of the host process.

`WindowsAuto` is the default. It prefers a ready elevated installation. If the
elevated tier is unavailable, it uses the restricted-token tier only when that
tier can satisfy every guarantee required by the profile. It otherwise returns
a typed setup-required error. Auto mode never weakens a profile to make it run.

The Windows mode is an operational backend choice, not authority. It therefore
does not become part of `Profile`, `Restrict`, or the profile fingerprint.

### 1.1 Codex baseline and deliberate departures

Codex's unelevated backend adds capability-SID ACLs and starts the command with
a `CreateRestrictedToken` token carrying `WRITE_RESTRICTED`. It refuses direct
deny-read policies because that flag restricts only write access checks. Its
offline behavior also rewrites proxy/package-manager environment variables,
which is useful defense in depth but not kernel network enforcement.

Codex's elevated backend provisions separate offline and online accounts,
protects their passwords with DPAPI, applies filesystem ACLs, installs
account-scoped firewall rules, and launches a command runner under a further
restricted token. It also supports a private desktop. Its Windows smoke suite is
the primary test inspiration for reparse, extended-path, alternate-stream,
network-bypass, policy-tamper, and process-cleanup cases.

Looprig keeps those sound mechanisms but deliberately differs in four places:

- it assigns a suspended child to the Job before resume and treats every Job
  error as fatal;
- it never counts environment rewriting as `NetworkBoundary`;
- it keeps elevated-account secrets in a LocalSystem broker so a current-user
  unelevated child cannot decrypt them; and
- it binds every ACL mutation to a lease, identity handle, guarantee bit, and
  tested cleanup path instead of leaving enforcement strength implicit.

## 2. Goals

- Preserve exact Looprig `Deny` / `Gated` / `Allow` authority and grant classes.
- Provide a useful no-admin tier for write-confined development commands.
- Provide read, write, process, and network boundaries after one-time setup.
- Keep command approval and sandbox enforcement separate.
- Reuse the existing authenticated target proxy for target-scoped egress.
- Bind filesystem decisions to Windows object identity, not path spelling.
- Kill the entire descendant tree on cancellation, timeout, or host exit.
- Fail closed on stale setup, unsupported filesystems, ACL failures, firewall
  policy override, path races, runner tampering, and Job Object assignment.
- Add a Windows CI matrix and an adversarial suite broad enough to prevent
  regressions in the claimed guarantees.

## 3. Non-goals

- Defending against kernel, filesystem-driver, or administrator compromise.
- Treating environment proxy variables or command stubs as a network boundary.
- Supporting remote UNC roots, SMB shares, FAT/exFAT, raw device paths, or
  arbitrary Windows object-manager namespaces in v1.
- Direct arbitrary-protocol port grants in v1. The Windows elevated backend
  returns `ErrGrantUnsupported` for `network.broad.v1` until per-execution WFP
  filters exist.
- GUI application compatibility as a reason to relax confinement. Commands
  that cannot run on the private desktop fail rather than moving to the user's
  interactive desktop.
- Multiple host processes sharing one elevated installation in v1. A second
  process must use a different installation ID and reserved proxy-port set.

## 4. Threat model

The attacker controls a spawned command and all of its descendants. It may use
`cmd.exe`, PowerShell, scripts, native programs, junctions, symlinks, hard links,
alternate data streams, 8.3 names, extended path spellings, COM, named pipes,
raw devices, subprocess brokers, and races. It may inspect its own token and
environment and deliberately crash the host.

The trusted computing base is the Windows kernel and security subsystem, the
host process, the installed sandbox host binary, the broker protocol, and this
module. Other processes running as the interactive user and local
administrators are outside the threat model. Enterprise policy is not trusted
to preserve local firewall rules: setup and each elevated construction verify
that the rules are effective, and fail closed when Group Policy overrides them.

An unelevated child has the interactive user's ordinary read authority because
`WRITE_RESTRICTED` applies restricting SIDs only to write checks. It must
therefore never receive or be able to recover elevated-account credentials.
This is why the elevated tier uses a broker instead of a DPAPI blob readable by
the interactive user.

## 5. Guarantee contract

| Property | Restricted token | Elevated |
|---|---:|---:|
| `GuaranteeProcessBoundary` | yes | yes |
| `GuaranteeWriteBoundary` | yes when ACL projection succeeds | yes when ACL projection succeeds |
| `GuaranteeReadBoundary` | never | yes for local supported roots |
| `GuaranteeEnvScrub` | yes, executor-owned | yes, executor-owned |
| `GuaranteeNetworkBoundary` | never | yes for the offline account |
| `GuaranteeAddressNetwork` | never | only when the configured route earns it |
| `GuaranteeResourceLimits` | when every requested Job limit is installed | same |
| `GuaranteeTargetNetwork` | never | yes through the authenticated proxy |

Restricted-token mode is always `LevelDegraded` when it enforces an OS boundary.
It never reports `LevelFull`. Elevated mode reports `LevelFull` only when every
restricted policy axis was compiled without narrowing and every requested Job
limit is active; otherwise it reports `LevelDegraded` if all required guarantees
still hold.

Examples:

- Host reads and network are `Allow`, workspace writes are `Allow`, and host
  writes are `Deny`: restricted-token mode can run and claims process, write,
  and environment guarantees.
- Host reads are `Deny` or `Gated`: restricted-token mode cannot run because the
  profile requires `ReadBoundary`.
- Network is `Deny` or `Gated`: restricted-token mode cannot run because the
  profile requires `NetworkBoundary`.
- Elevated setup is ready and network is `Gated`: the offline account runs with
  no direct egress. A target grant opens only the authenticated proxy path.
- Network is `Allow`: the elevated online account runs without claiming a
  network boundary. Filesystem restrictions still use full restricting SIDs.

The executor's existing required-guarantee comparison remains the final
interlock. A Windows backend cannot bypass it.

## 6. Public API

The facade adds platform-neutral declarations so consumers can compile one
configuration on every OS:

```go
type WindowsSandboxMode uint8

const (
    WindowsAuto WindowsSandboxMode = iota
    WindowsRestrictedToken
    WindowsElevated
)

func WithWindowsSandboxMode(WindowsSandboxMode) ExecutorSetOption
func WithWindowsSandboxStateRoot(string) ExecutorSetOption

type WindowsSetupConfig struct {
    InstallationID string
    StateRoot      string
    HostBinary     string
    ProxyPorts     []uint16
}

type WindowsSetupStatus struct {
    Ready           bool
    Version         uint32
    InstallationID  string
    OwnerSID        string
    OfflineAccount  string
    OnlineAccount   string
    ProxyPorts      []uint16
    Problems        []string
}

func InspectWindowsSandbox(context.Context, WindowsSetupConfig) (WindowsSetupStatus, error)
func SetupWindowsSandbox(context.Context, WindowsSetupConfig) error
func RemoveWindowsSandbox(context.Context, WindowsSetupConfig) error
```

`InstallationID` is a stable application installation identifier, not a display
name. Account, service, mutex, pipe, and firewall names use a truncated SHA-256
digest of it so Windows account-name limits do not create collisions.

`StateRoot` must be an absolute local path. Elevated setup requires it to be
beneath `%ProgramData%` unless a future explicit unsafe override is added.
`HostBinary` names the companion executable built from `cmd/sandbox-host`; setup
copies and locks it beneath `StateRoot`. Runtime reads the installed path from
the protected, hash-bearing setup manifest and never executes the
caller-supplied source path.

`ProxyPorts` is a small, non-empty, deduplicated set of fixed loopback TCP ports.
The host binds every configured port before constructing an offline executor:
one carries the authenticated proxy and the others are deny-only guards. If any
port cannot be bound, construction fails. This makes the firewall exception
usable only by this host process and prevents an unrelated local forward proxy
from occupying an allowed port.

`SetupWindowsSandbox` and `RemoveWindowsSandbox` require an already elevated
process and return `ErrWindowsElevationRequired` otherwise. The library never
opens a UAC prompt. The consumer owns UI and elevation. `InspectWindowsSandbox`
is read-only and works without elevation.

On non-Windows platforms, inspection and setup return `ErrSandboxUnavailable`.
Non-default Windows executor options on non-Windows return an invalid-option
error rather than silently doing nothing.

New sentinels:

```go
var ErrWindowsSetupRequired = errors.New("sandbox: Windows elevated setup required")
var ErrWindowsSetupStale = errors.New("sandbox: Windows elevated setup is stale")
var ErrWindowsElevationRequired = errors.New("sandbox: Windows setup requires elevation")
```

Setup-required and setup-stale errors also unwrap to `ErrSandboxUnavailable`,
so existing callers retain a useful coarse check.

## 7. Component architecture

### 7.1 Platform selection

`internal/platform` accepts backend options instead of exposing a zero-argument
selector. Darwin and Linux ignore the zero-value Windows options. Windows sends
the selected mode and state root into `internal/windows`.

Auto selection occurs against the compiled effective policy:

1. Validate elevated state and broker health.
2. If ready, select elevated.
3. Otherwise compile the restricted-token posture.
4. If its bits cover `Profile.Settings().RequiredGuarantees`, use it.
5. Otherwise return `ErrWindowsSetupRequired` with the missing named guarantees.

Explicit `WindowsRestrictedToken` never contacts the service. Explicit
`WindowsElevated` never falls back.

### 7.2 `internal/windows`

This package owns:

- Windows capability SID generation and restricted-token creation.
- Full and write-only restriction modes.
- local-account token requests to the broker.
- handle-based canonicalization and file identity.
- ACL projection requests and projection leases.
- elevated setup/status/removal implementations.
- firewall and service health verification.
- the Windows backend and compilation report.
- Job Object resource-limit configuration shared with `internal/exec`.

It depends on stdlib and `golang.org/x/sys/windows`; it introduces no cgo.

### 7.3 Companion host and broker service

`cmd/sandbox-host` builds one companion executable with two entry modes:

- Windows service mode: a LocalSystem broker serving a versioned named-pipe
  protocol.
- Runner mode: a restricted process that creates a private window
  station/desktop, launches the requested target, forwards standard I/O, waits
  for the target, and exits with the target's code.

The broker deliberately has no arbitrary-process-launch request. Its allowed
operations are:

1. report status and protocol version;
2. acquire or release an ACL projection lease;
3. issue an offline or online restricted primary-token handle for an existing
   lease; and
4. reconcile leases after a client dies.

For ACL work, the broker impersonates the named-pipe client. It therefore cannot
change a DACL the caller could not change. The only principals it may add are
the installation's sandbox account and broker-generated restricting SID. The
operation is not a general privileged ACL editor.

The broker keeps local-account passwords in LocalSystem user-scope DPAPI state
whose ciphertext is readable only by SYSTEM and Administrators. It duplicates
restricted token handles into the authenticated client process; it never
returns a password or an unrestricted account token.

The named pipe:

- has a DACL limited to SYSTEM, Administrators, and the configured owner SID;
- obtains the real client PID and token from Windows rather than request data;
- rejects AppContainer clients and clients already carrying this installation's
  restricting SID namespace;
- uses a length-prefixed, versioned protocol with strict size and count limits;
- accepts canonical UTF-16 paths only after reopening or duplicating handles;
- binds leases to the client PID, process creation time, and connection nonce;
  and
- cleans every lease when the client pipe or process handle closes.

### 7.4 Enforcement spec ownership

Windows ACLs are resources, not just spawn attributes. `enforce.Spec` gains an
idempotent owner-level release callback in addition to its per-spawn cleanup:

```go
type Spec struct {
    Wrap    func(string, []string) ([]string, func(*exec.Cmd) error, func())
    Release func() error
}
```

The base executor owns its compiled `Spec` until `Executor.Close` or
`ExecutorSet.Close`. A grant-recompiled spec is transient and released after the
Job Object reports zero active processes. Compile failure rolls back any partial
lease before returning. Existing Darwin, Linux, and null specs have a nil
release callback.

This lifecycle permits one executor-scoped restricting SID and one recursive ACL
projection instead of rewriting a whole workspace on every spawn. New objects
inherit the executor SID. Grant-specific exact/tree leases use fresh one-shot
SIDs and live for one execution.

## 8. Process launch and containment

Both tiers reuse the existing Windows Job Object path:

1. create the process suspended;
2. assign it to a Job configured with kill-on-close and requested limits;
3. fail and terminate it if assignment fails;
4. resume only after assignment succeeds; and
5. after cancellation or exit, retain the Job handle until active process count
   reaches zero.

This ordering is stricter than Codex's current runner, which assigns after
creation and tolerates some Job errors.

Restricted-token mode launches the target directly using `SysProcAttr.Token`.
Elevated mode launches the installed host binary in runner mode using the token
handle returned by the broker. Because the runner is assigned before resume,
its target and all ordinary descendants join the same Job automatically.

The runner request is delivered through an inherited read-only pipe handle, not
through a shell command line. It contains the normalized inner argv, cwd, and a
protocol nonce. The runner inherits the already scrubbed environment and
standard handles. It creates a private desktop, launches the target there,
waits, and mirrors its exit status. The installed runner is owner- and
sandbox-read/execute only, SYSTEM/Administrators-write only, and hash-checked by
status and before every elevated construction.

Job limits map as follows:

- `MaxPIDs` -> `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`;
- `MaxMemBytes` -> per-job commit limit;
- `MaxCPUPct` -> Job CPU rate control in hard-cap mode.

`GuaranteeResourceLimits` is reported only when all non-zero requested limits
are supported, installed, and read back. Limits that cannot be expressed narrow
the compile and withhold the bit; invalid limits fail profile compilation.

`RunCommand` becomes platform-shell aware:

- Darwin/Linux: `/bin/sh -c <command>`;
- Windows: `%ComSpec%` is not trusted; use the canonical System32
  `cmd.exe /D /S /C <command>` path resolved by handle during backend setup.

`RunArgv` remains shell-free.

## 9. Tokens and accounts

### 9.1 Restricted-token tier

The parent duplicates its current primary token, removes privileges and
dangerous groups, and calls `CreateRestrictedToken` with:

- `DISABLE_MAX_PRIVILEGE`;
- `LUA_TOKEN`;
- `WRITE_RESTRICTED`; and
- the executor and grant capability SIDs as restricting SIDs.

The backend does not lower integrity because doing so would require invasive
low-integrity labels on normal workspaces. It denies raw-device and dangerous
named-pipe access through stripped privileges and the restricting-SID write
check, and verifies those cases in the adversarial suite.

Because `WRITE_RESTRICTED` does not restrict reads, this tier never claims
`ReadBoundary`. It also never claims a network guarantee; dead-proxy environment
variables may be added as defense in depth but are explicitly absent from the
guarantee calculation.

### 9.2 Elevated tier

Setup creates two non-administrator local accounts:

- an offline account covered by outbound firewall rules; and
- an online account used only for profiles whose network access is `Allow`.

Names are installation-hash-derived. Passwords are random, non-expiring, and
available only to the LocalSystem broker. Both accounts are hidden from the
logon UI, denied interactive/remote-interactive/network logon, and granted only
the logon right needed by the broker.

The broker creates a primary token with maximum privileges disabled, dangerous
groups disabled, and full restricting SIDs. Unlike `WRITE_RESTRICTED`, full
restriction runs the second SID-list access check for reads as well as writes.
The token contains:

- a persistent installation-runtime SID for the protected runner and required
  Windows runtime objects;
- an executor-scoped SID for configured roots and carveouts; and
- zero or more one-shot grant SIDs.

Both the sandbox account's normal access check and the restricting-SID access
check must pass. This supplies the elevated read boundary without placing broad
persistent deny-read ACEs across the user's profile.

## 10. Windows path and filesystem policy

### 10.1 Canonicalization

Windows path handling is a platform service rather than scattered
`filepath.Clean` calls. A canonical local path is obtained by:

1. rejecting NUL, relative, drive-relative, device, object-manager, and UNC
   spellings;
2. opening the object or deepest existing ancestor with `CreateFileW`,
   `FILE_FLAG_BACKUP_SEMANTICS`, and `FILE_FLAG_OPEN_REPARSE_POINT` where
   appropriate;
3. resolving the final DOS volume path from the handle;
4. obtaining volume serial, 128-bit file ID, type, reparse tag, and link count;
5. normalizing the drive letter and separators; and
6. comparing path keys case-insensitively with Windows ordinal semantics.

`\\?\C:\x`, `c:\x`, and `C:\X` therefore cannot name three policy entries.
Any colon after the drive designator is treated as an alternate-stream spelling
and rejected as a configuration or grant target. Access to a stream through a
permitted ordinary file is governed by that file's DACL and is covered by tests.

Supported roots must live on a local filesystem with persistent DACLs and stable
file IDs (NTFS or ReFS in v1). UNC/SMB, FAT/exFAT, volume GUID paths that cannot
be reduced safely, `\\.\`, `GLOBALROOT`, named-pipe paths, and raw device paths
are unsupported grant/configuration classes and fail closed.

The host-wide lexical root is replaced on Windows by an enumerated set of local
volume roots. `host:*` remains the grant vocabulary, but broad host read/write
grants return `ErrGrantUnsupported` in v1 rather than mutating every volume.

### 10.2 Identity-bound handles

Windows implements `FileIdentity` with volume serial + file ID + object type and
implements `AcquirePathHandle` by retaining a no-follow handle. Revalidation
checks final path, file ID, type, and every reparse transition. A swapped root,
junction, symlink, mount point, or replaced ancestor yields `ErrTargetChanged`.

The broker duplicates client handles rather than trusting transmitted paths.
ACLs are read and changed with `GetSecurityInfo` / `SetSecurityInfo` on those
handles. Recursive tree projection does not traverse reparse points. Denied
carveouts receive explicit deny ACEs ordered before inherited allow ACEs.

### 10.3 ACL leases

An ACL projection lease records:

- installation, client, executor, and random SID identity;
- every object handle/file ID touched;
- the exact ACEs inserted, never an entire replacement DACL;
- whether each ACE is account-normal, restricting-allow, or restricting-deny;
- projection state and rollback state; and
- the parent client process handle.

Tree projection is deterministic and fail-closed: sort paths, apply narrow
denies before broad allows, skip reparse traversal, read back each DACL, and
rollback all inserted ACEs if any object fails. Cleanup removes only ACEs whose
SID and lease marker match. It never restores a saved whole DACL over concurrent
user changes.

The service journal is SYSTEM/Administrators-only. Explicit release cleans the
lease after the Job empties. Client death triggers cleanup. Service startup
reconciles any incomplete journal before accepting token requests. Random SIDs
are never reused, so an ACE left by power loss is inert until reconciliation.

Existing exact-file grants are supported. Existing directory-tree grants are
supported. A nonexistent exact target and an exact-directory target return
`ErrGrantUnsupported` in v1; the backend never widens either to an ancestor
tree and never precreates a caller-visible file as a side effect of approval.

## 11. Network design

### 11.1 Offline account firewall

Setup installs account-scoped, all-profile outbound rules and verifies them by
read-back:

- block every non-loopback outbound protocol for the offline account;
- block all loopback UDP;
- block loopback TCP on the complement of `ProxyPorts`; and
- leave only the configured proxy TCP ports reachable.

If Windows reports that local policy modifications are ineffective, setup is
not ready. Construction rechecks rule identity, enabled state, profiles,
direction, action, protocol, addresses, ports, and account SID. A missing or
widened rule fails before token issuance.

The host binds every exception port before launching an offline process. The
selected proxy listener requires the existing per-execution random credential;
guard listeners reject all traffic. A sandbox with no target grant can reach at
most a listener that always rejects it.

### 11.2 Target grants

`network.proxy.target.v1` keeps the current flow:

1. authenticate and consume the grant;
2. authorize the normalized target under a random execution ID;
3. compile the offline token and proxy-only network posture;
4. inject authenticated HTTP(S) proxy environment variables;
5. launch under the offline account;
6. have the trusted parent-side proxy resolve/dial the approved target through
   the configured route; and
7. release credentials and tunnels when the execution ends.

Direct connections cannot bypass the proxy because the firewall blocks them.
The backend then earns `NetworkBoundary` and `TargetNetwork`; it earns
`AddressNetwork` only when the selected `EgressRoute` already reports trusted
address enforcement.

`network.broad.v1` is unsupported on Windows v1. Environment proxies are not a
substitute for arbitrary TCP/UDP port access. A later version may add ephemeral
WFP filters keyed to a per-execution AppContainer or token identity.

### 11.3 Online account

A profile with `Network == Allow` uses the online account. No network boundary
bit is reported. The token still carries full filesystem restricting SIDs, so
open egress does not imply open filesystem access.

## 12. Setup and removal

Setup is idempotent and transactional:

1. validate elevation, owner SID, local ProgramData state root, host binary,
   installation ID, and proxy ports;
2. create a staging state directory with a locked DACL;
3. copy, hash, and lock the companion host binary;
4. provision or rotate both local accounts and logon rights;
5. create the service with a restricted service SID and failure actions;
6. install firewall rules in their fail-closed broad-block form, then narrow the
   loopback TCP block to the proxy-port complement;
7. store credentials as LocalSystem user-scope DPAPI data in SYSTEM-only state;
8. start the service and run self-tests for token issuance, runner execution,
   ACL lease rollback, Job membership, and offline firewall enforcement;
9. atomically write a versioned manifest containing hashes and SIDs; and
10. replace prior ready state only after every self-test passes.

Refresh repeats validation and can rotate passwords, replace the host binary,
repair rules, and advance the protocol version. A partial refresh leaves the
previous verified installation active or marks the installation not ready; it
never records success early.

Removal requires elevation. It stops and deletes the service, reconciles ACL
leases, removes only installation-owned firewall rules and logon rights, deletes
the two derived accounts, and removes the protected state root. It verifies each
target against the manifest before deletion and reports any residual object.

Setup state becomes stale when the manifest version, host binary hash, service
configuration, account SIDs, credential records, firewall rules, owner SID, or
proxy-port set differs from the requested configuration.

## 13. Error and failure behavior

- Invalid mode/configuration: reject at `NewExecutorSet`.
- Auto mode missing elevated setup and missing restricted guarantees: return
  `ErrWindowsSetupRequired`, naming the missing guarantees.
- Explicit elevated mode with stale state: return `ErrWindowsSetupStale`.
- Broker unavailable, protocol mismatch, or token duplication failure: fail
  construction/spawn; never use the current token.
- ACL projection/read-back failure: rollback and fail compilation.
- Unsupported path/filesystem/grant: return the existing typed unsupported or
  grant error; never broaden a root.
- Firewall rule ineffective or widened: fail elevated construction and withhold
  all network guarantees.
- Runner hash mismatch: fail before launch.
- Job creation, configuration, assignment, or resume failure: terminate the
  suspended process and fail the spawn.
- Private desktop creation failure: fail the elevated spawn.
- Cleanup failure: retain the lease in the broker journal, mark elevated status
  unhealthy for new work, and retry reconciliation. Never reuse its SID.

Compile reports use stable feature names such as `windows.token`,
`windows.filesystem.read`, `windows.filesystem.write`, `windows.firewall`,
`windows.private-desktop`, `windows.job`, and `windows.resource-limits`.

## 14. Test strategy

### 14.1 Platform-independent and cross-compile tests

- Mode/config validation and non-Windows stubs.
- Auto-selection and required-guarantee matrices with fake status/backend probes.
- Compile report and Level/GuaranteeBits consistency.
- Windows path-key pure tests, including case, separators, drive roots, extended
  syntax, ADS, device paths, UNC, and malformed UTF-16.
- Broker protocol framing, versioning, size limits, invalid enums, and fuzzing.
- `GOOS=windows go test -c` for every package from Linux CI, catching build-tag
  gaps. Fix the existing `platform_other_test.go` typo as the first task.

### 14.2 Reusable `sandboxtest`

Make the suite shell-aware through platform-specific helpers and add checks for:

- write inside succeeds / write outside is equivalent to `WriteBoundary`;
- read inside succeeds / read outside is equivalent to `ReadBoundary`;
- planted parent environment secrets do not cross `EnvScrub`;
- direct non-loopback and loopback-bypass probes agree with `NetworkBoundary`;
- target proxy success and unapproved-target failure agree with
  `TargetNetwork`;
- cancellation kills a nested child and grandchild when `ProcessBoundary` is
  claimed;
- requested process/memory/CPU limits agree with `ResourceLimits`; and
- all guarantee implication invariants remain coherent.

Tests run in subprocesses where token, desktop, firewall, service, or ACL state
could outlive an assertion. Every material test has a positive control proving
the attempted operation would work without the relevant boundary.

### 14.3 Restricted-token Windows suite

Run on a standard-user Windows account with elevated installation absent:

- auto selects restricted mode for write-only-required profiles;
- explicit and auto modes reject read/network-required profiles;
- writes inside workspace/tmp succeed;
- writes to profile, sibling repo, `.git` carveout, setup state, and another
  drive fail;
- current-user reads remain possible and `ReadBoundary` is never claimed;
- nested `cmd`, PowerShell, Python, and native descendants stay in the Job;
- timeout and parent crash leave no descendant marker;
- junction/symlink creation cannot turn an allowed write into an outside write;
- `\\?\`, case variants, 8.3 names, ADS, raw devices, and named pipes do not
  bypass write restrictions; and
- stale random-SID ACEs cannot be used by a later token.

### 14.4 Elevated Windows suite

Run on an ephemeral elevated Windows CI worker. Setup and removal wrap the suite:

- setup is idempotent; corrupt manifest/hash/rule/account state is detected;
- sandbox children cannot read or change broker state, credentials, service,
  runner, manifest, or firewall configuration;
- exact/tree read and write allow/deny matrices pass;
- deny-read globs and protected carveouts survive case, extended-path, ADS,
  junction, symlink, root-swap, and post-grant races;
- UNC, device, unsupported filesystem, nonexistent exact, and broad network
  grants fail closed;
- offline direct TCP/UDP, DNS, metadata, loopback non-proxy, PowerShell web
  requests, curl, Python sockets, and proxy-variable deletion remain blocked;
- approved HTTP and CONNECT targets work through the authenticated proxy while
  direct-address and unapproved-target attempts fail;
- online mode allows network without claiming `NetworkBoundary`;
- private desktop and Job tests cover `Start-Process`, shell execution brokers,
  detached flags, scheduled-task attempts, WMI/COM launch attempts, and GUI
  children;
- PID, memory, and CPU Job limits are enforced and read back;
- concurrent spawns have independent credentials and grant SIDs;
- client kill and service restart reconcile ACL leases; and
- removal leaves no accounts, service, firewall rules, journal entries, or
  meaningful ACEs.

External internet is not required for firewall tests. CI starts listeners on
the worker's non-loopback interface and loopback ports. The trusted parent must
reach each positive-control listener while the offline account cannot.

### 14.5 Fuzz and race tests

- Fuzz canonical path parsing and normalization.
- Fuzz broker request decoding and grant-to-ACL projection planning.
- Race path replacement, junction insertion, DACL change, grant expiry, executor
  close, proxy release, service disconnect, and context cancellation.
- Repeat destructive escape attempts hundreds of times under `go test -race`
  where supported; use process-level stress without `-race` for timing-sensitive
  Windows token tests if the race runtime changes process behavior.

## 15. CI gates

Add:

1. `windows-cross-compile`: compile every package and test binary for Windows.
2. `windows-restricted`: run unit, conformance, and restricted-token integration
   suites as a standard user.
3. `windows-elevated`: install the broker/accounts/firewall on an ephemeral
   runner, run elevated integration and adversarial suites, and always remove
   setup in a final step.

The elevated job must fail, not skip, when administrative setup was requested
but a mechanism is unavailable. Tests may skip only for an explicitly detected
Windows edition/API limitation recorded in the test name and compile report.

No Windows backend may merge while its claimed guarantees rely solely on mocks.
Each claimed bit needs at least one live positive/negative mechanism test.

## 16. Delivery boundaries

Implementation is split into independently reviewable milestones:

1. portability seams, path model, shell selection, and cross-compilation;
2. Job limits and expanded conformance suite;
3. restricted-token write confinement;
4. broker protocol and protected setup lifecycle;
5. elevated filesystem/read boundary and private runner;
6. offline firewall and target proxy;
7. grant recompilation and ACL lease lifecycle;
8. adversarial Windows CI and documentation.

Restricted-token support may ship before elevated support, but `WindowsAuto`
must continue failing closed for read/network-required profiles. Elevated mode
may ship only after setup removal and crash reconciliation are implemented; a
persistent security mechanism without a safe uninstall/recovery path is not
complete.

## 17. Acceptance criteria

The feature is complete when:

- both explicit modes and auto selection are public and documented;
- restricted mode live-tests its process/write guarantees without admin rights;
- elevated mode live-tests read/write/process/network/target guarantees after
  one-time setup;
- every unsupported profile or grant fails before spawning;
- no account credential is readable by the interactive user or a sandbox child;
- setup, refresh, crash recovery, and removal are idempotent and tested;
- Windows paths cannot bypass policy via case, reparse, extended, stream, device,
  UNC, or identity-swap variants covered above;
- cancellation and host death leave no descendant process;
- ACL leases and proxy credentials do not survive their owner execution;
- the reusable conformance suite covers every guarantee bit; and
- macOS and Linux behavior and tests remain unchanged.
