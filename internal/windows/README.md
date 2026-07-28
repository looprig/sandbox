# Windows sandbox internals

This package owns Windows mechanism selection, path-to-ACL policy compilation,
restricted-token construction, Job and handle confinement, elevated
installation, the LocalSystem broker, account-scoped firewall policy, private
desktops, and crash recovery. The public facade is the root `sandbox` package;
consumers must not import this package.

## Tiers and guarantees

`RestrictedToken` runs as the interactive user with a restricted token, a Job,
an explicit handle list, UI restrictions, and temporary ACL restrictions.
Those mechanisms are defense in depth: Windows user-session brokers remain
reachable, so v1 honestly reports `LevelNone` and only the executor-owned
`GuaranteeEnvScrub`.

`Elevated` uses installation-owned local accounts and a LocalSystem broker.
When every prerequisite and requested policy axis verifies, it may report:

| Guarantee | Elevated v1 condition |
| --- | --- |
| process boundary | restricted account token, private desktop, no-breakaway Job, and explicit handle list |
| write boundary | identity-bound ACL projection succeeds |
| read boundary | local NTFS/ReFS roots plus the approved runtime baseline |
| environment scrub | executor-owned environment construction |
| network boundary | verified offline-account firewall posture |
| address network | the selected route also earns address enforcement |
| resource limits | every requested Job limit reads back correctly |
| target network | authenticated, target-scoped loopback proxy |

`Auto` tries verified elevated setup when the profile requires guarantees the
restricted tier cannot claim. It falls back only when setup is absent, never
when installed state is stale or corrupt. Explicit `Elevated` never falls back.

Elevated runtime readiness requires a protected approved evidence artifact from
the exact-token/runtime matrix on the matching supported disposable Windows 11
or Windows Server worker. Setup imports that artifact and inspection revalidates
its source revision, clean-build state, Go toolchain, platform/filesystem facts,
and all required runtime rows. Missing, skipped, stale, or mismatched evidence
fails closed and must not be described as production-ready.

## Trust boundary

Elevated setup installs a hash-pinned `sandbox-host.exe`, a protected manifest,
two installation-owned accounts, DPAPI-protected credentials, a LocalSystem
service, firewall rules, and a durable lease journal. The host application
never receives account passwords or an unrestricted account token.

The broker authenticates named-pipe clients from kernel process/token facts and
binds each request to PID, process creation time, a held process handle, and a
one-shot nonce. Paths are descriptive; duplicated object handles and stable
file identity are authority. The broker journals an exact ACL mutation before
applying it, issues only a fully restricted account token into the bound
client, and removes leases on release, disconnect, service restart, or
reconciliation.

## Cleanup invariants

- ACL cleanup removes only the byte-identical ACE occurrence recorded for an
  owned lease and preserves unrelated and pre-existing ACEs.
- Journal recovery completes before the broker serves status, lease, or token
  requests. A corrupt non-tail record fails closed.
- process cancellation and executor close terminate the Job and close proxy
  activity, desktop objects, handles, and live leases.
- setup rollback and removal act only on manifest-pinned SIDs, service identity,
  firewall rule identities, slot paths, and credential files.
- removal refuses ambiguous or unowned state; it never adopts a matching name
  as proof of ownership.

Always run elevated tests on a disposable worker and inspect for residual
accounts, services, firewall rules, journal entries, processes, and meaningful
lease ACEs in an unconditional cleanup step.

## Supported path classes

Windows v1 accepts canonical local DOS-drive paths on NTFS or ReFS, which
provide persistent DACLs and stable file IDs. It rejects UNC/SMB, FAT/exFAT,
drive-relative paths, alternate streams, object-manager and device namespaces,
`GLOBALROOT`, named pipes, and raw devices. Broad `host:*` filesystem grants,
nonexistent exact targets, exact directories, and multi-link exact files are
unsupported in v1 and fail closed.

## File map

- `types.go`, `setup_*`, `manifest.go`, and `host_install_windows.go`: public
  configuration vocabulary and transactional installation/removal.
- `backend_*`, `restricted_*`, and `elevated_*`: tier selection, policy
  compilation, leases, and launch composition.
- `token_windows.go`, `job_*`, `handlelist_windows.go`, `desktop_windows.go`,
  and `runner_windows.go`: child-process confinement.
- `acl_*`, `path_*`, and `grant_*`: identity-bound filesystem policy and
  temporary ACL projection.
- `protocol.go`, `pipe_windows.go`, `broker_*`, and
  `lease_journal_windows.go`: authenticated broker and recovery.
- `account_windows.go`, `dpapi_windows.go`, `service_windows.go`, and
  `firewall_*`: installation-owned machine state.
- `network_windows.go`, `ports_*`, and proxy integration: guarded loopback
  transport and account-scoped egress.

## Verification

Pure and cross-build checks can run on any development host:

```sh
go test ./internal/windows
./scripts/test-windows-build.sh
```

The restricted live suites require a standard-user disposable Windows worker:

```powershell
$env:SANDBOX_WINDOWS_DISPOSABLE_RESTRICTED_TEST = "1"
$env:SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST = "1"
go test -race -count=1 ./internal/windows ./internal/exec `
  -run 'RestrictedDisposable|RestrictedBrokerEscape|WindowsRestricted'
```

The elevated acceptance suite requires an elevated disposable Windows 11 or
Windows Server worker and an unconditional setup-removal/residue check. A skip
is not evidence that a requested mechanism works. At present the missing
approved runtime baseline means this live gate is outstanding.
