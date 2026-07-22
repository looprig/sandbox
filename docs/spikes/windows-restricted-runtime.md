# Windows Restricted Runtime Baseline

## Status

**Pending and unverified. No go/no-go result has been selected.**

The harness cross-compiles on the non-Windows development host, but no supported
disposable Windows image was available in this session. A skipped test is not a
pass, cross-compilation is not runtime evidence, and this document does not
authorize elevated implementation work that depends on the runtime baseline.

The sanctioned runner-only bootstrap has not been added. It may be evaluated
only after live results show failures limited to the cooperative protected
runner. No ACL on an operating-system runtime object is changed by this spike.

## Live command and required images

Run from a clean checkout on every Windows build/filesystem image the product
supports, using a disposable **standard-user** PowerShell. Never run the
baseline command from the elevated collector shell: that would derive the
restricted token from an administrator token and invalidate the experiment.

```powershell
go test -count=1 -v ./spikes/windows -run TestRestrictedRuntimeBaseline
```

The command must finish with `PASS`; `SKIP`, a compile-only result, or a result
copied from a different Windows image does not satisfy the gate. Preserve the
complete verbose log as CI evidence. If a worker-level timeout is available,
set it above the harness's per-process 20-second watchdog so the harness can
terminate and report a stuck target first.

Timeout cleanup has an independent two-second reap watchdog. It records the
`TerminateJobObject` result, closes the kill-on-close Job as escalation, kills
the root process, and reports whether `Wait` completed plus every cleanup error.
Neither timeout nor setup-failure cleanup waits without a bound.
If the second watchdog cannot reap the process, a terminal fatal boundary stops
the gate before another runtime row or selection evidence can run.

The explicit manifest supports `windows-11` and `windows-server`. The live
evidence record for each image must add:

- edition, version, build, servicing level, architecture, system-volume serial,
  filesystem name, and filesystem flags from the `platform=` line;
- the complete `exact_token=` JSON, including every group and attribute, every
  privilege and attribute, the sole restricting SID, and integrity SID;
- the complete `runtime_matrix=` JSON and `fixture_acl_delta=` line;
- the source revision and Go version used to build and run the probe;
- one reviewed selection from: exact token, trusted-runner-only bootstrap,
  narrowed target set, or elevated milestone blocked pending LPAC/AppContainer
  review.

No such per-image record exists yet.

## Exact token under test

The test opens the current process primary token, supplies every enabled token
group to `CreateRestrictedToken` as a SID to disable, and passes these flags:

- `DISABLE_MAX_PRIVILEGE` (`0x1`);
- `LUA_TOKEN` (`0x4`).

The restricting list contains exactly one entry: Restricted Code
(`S-1-5-12`). The harness asks Windows whether the result is restricted and
reads `TokenRestrictedSids` back, failing unless that list is exactly
`S-1-5-12`. It records all remaining groups, privileges, restricting SID
attributes, and the mandatory-integrity label from the created token. The
normal token user SID necessarily remains part of the primary token; it is not
added to the restricting list and cannot by itself satisfy the second access
check.

The test does not lower integrity and does not add `ALL APPLICATION PACKAGES`,
an installation SID, an executor SID, or a grant SID. This is deliberately the
narrow runtime-only feasibility token, not the eventual complete elevated
execution token.

The harness asserts the shape rather than merely logging it: source and result
are primary tokens, integrity is unchanged, every enabled source group is
deny-only in the result, every enabled privilege except Windows'
`SeChangeNotifyPrivilege` traversal exception is disabled/removed, and an
attempt to re-enable a removed privilege remains ineffective. No executor,
grant, installation, or Task 9 SID is added.

## Required runtime contract

`spikes/windows/internal/baseline/runtime-manifest.json` is the versioned source
of truth. All entries in `required` are fatal when missing or unlaunchable:

| Row | Probe |
|---|---|
| Installed runner | A statically built, installed-runner-shaped Go helper in a test-owned directory with an explicit inherited Restricted Code read/execute ACE |
| Go subprocess | The helper creates a second copy of itself and waits for it |
| CRT and DLL initializer | The helper loads and unloads `kernelbase.dll` and `ucrtbase.dll`; a successful `LoadLibraryEx` includes process-attach initializer execution |
| Locale and console | The helper queries the user locale and console code pages and is launched with a new console |
| PE TLS callback fixture | A deterministic owned PE32+ executable for the worker architecture, with an `IMAGE_TLS_DIRECTORY` callback that writes `TLS_CALLBACK_EXECUTED`, followed by an entrypoint that refuses success unless the callback set its flag and then writes `MAIN_AFTER_TLS` |
| Canonical command shell | `GetSystemDirectory()` + `cmd.exe /D /S /C "exit 0"` |
| Windows PowerShell | Canonical System32 Windows PowerShell with no profile and no interaction |

Python is named by the Windows conformance plan, so one of `python.exe` or
`py.exe` is required; its absence is fatal. Node.js, .NET, Java, Ruby, Perl, and
PowerShell Core are explicitly `inventory_only`, outside the current product
runtime contract, and reported as `NOT_INSTALLED` when absent. The whole test
never calls `t.Skip`.

The PE fixture is generated from reviewable Go source rather than a checked-in
binary. Portable tests parse both amd64 and arm64 images with `debug/pe` and
require a nonzero TLS directory, callback array, entrypoint, and both observable
markers. The live row passes only when captured output is exactly callback then
entrypoint. Cross-compilation is still not live proof that Windows accepted the
image or dispatched the callback.

## Object and ACL diagnostics

Every runtime row records a direct executable inventory:

- an image-startup access estimate:
  `FILE_EXECUTE|FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE`;
- canonical executable path;
- volume serial and file ID, plus link count;
- owner SID;
- security descriptor in SDDL form, including the DACL;
- process-creation or exit error, exit code, bounded output, and watchdog result.

These diagnostics do **not** identify every transitive loader or startup denial
and are not accepted as denial evidence. If any required row fails, the harness
reports `exact_token_gate_passed=false` and
`failure_selection_evidence_complete=false`. A reviewed failure-based selection
requires the separate validation-only invocation to accept evidence conforming to
`spikes/windows/internal/baseline/trace-evidence.schema.json`. For every failed
row the validator requires at least one trace denial and requires operation,
requested access, object path/identity, owner, and DACL on every denial. It also
requires collector name/version/command and the SHA-256 of the immutable raw
trace. Missing or partial evidence cannot be selected.

### Disposable-worker trace procedure

For filesystem, DLL, registry, named-pipe, process, locale, and console events,
the currently specified collector is Microsoft Sysinternals Process Monitor
4.01. Verify the file version is exactly `4.1.0.0`, then run in an elevated
PowerShell session on the disposable worker. Collection and the baseline use
two different shells and security contexts.

First, in an **elevated collector PowerShell**, verify and start ProcMon:

```powershell
(Get-Item .\procmon64.exe).VersionInfo.FileVersion
.\procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\runtime-baseline.pml
```

Then, in a separate **standard-user PowerShell**, choose a stable caller nonce
and run the baseline exactly once. The emitted invocation manifest binds source
revision, Windows build/architecture/filesystem, exact-token inventory digest,
required-runtime-manifest digest, executable path/identity/hash and PID for each
row, exit/diagnostic, and matrix digest:

```powershell
$env:LOOPRIG_RUNTIME_RUN_NONCE = [Guid]::NewGuid().ToString('N')
$env:LOOPRIG_RUNTIME_RUN_MANIFEST_OUT = 'C:\runtime-invocation.json'
go test -count=1 -v ./spikes/windows -run '^TestRestrictedRuntimeBaseline$'
```

Do not rerun the baseline to create evidence. A rerun has different PIDs and is
not the traced invocation even if the nonce is accidentally reused.

Back in the **elevated collector PowerShell**, stop/export the same capture,
then finalize the emitted invocation manifest against the immutable raw PML:

```powershell
.\procmon64.exe /Terminate
.\procmon64.exe /OpenLog C:\runtime-baseline.pml /SaveAs C:\runtime-baseline.csv
Get-FileHash -Algorithm SHA256 C:\runtime-baseline.pml
$env:LOOPRIG_RUNTIME_INVOCATION_MANIFEST = 'C:\runtime-invocation.json'
$env:LOOPRIG_RUNTIME_RAW_TRACE = 'C:\runtime-baseline.pml'
$env:LOOPRIG_RUNTIME_COLLECTOR_NAME = 'Microsoft Sysinternals Process Monitor'
$env:LOOPRIG_RUNTIME_COLLECTOR_VERSION = '4.01'
$env:LOOPRIG_RUNTIME_COLLECTOR_COMMAND = 'procmon64.exe /AcceptEula /Quiet /Minimized /BackingFile C:\runtime-baseline.pml'
$env:LOOPRIG_RUNTIME_FINAL_MANIFEST_OUT = 'C:\runtime-final.json'
go test -count=1 -v ./spikes/windows -run '^TestFinalizeRestrictedRuntimeRunManifest$'
```

Preserve the PML and CSV. Filter the CSV by the test and child PIDs and retain
every denial, not only `CreateFile`. For each filesystem object attach
`fsutil file queryfileid <path>` and `(Get-Acl -LiteralPath <path>).Sddl`; for
each registry object attach its canonical hive path and
`(Get-Acl -LiteralPath <registry-provider-path>).Sddl`. Record the exact
Process Monitor command line in the JSON.

Create trace evidence conforming to the v3 JSON schema. Each failed case must
repeat the exact runtime record from `runtime-final.json`, set `complete:true`,
and bind the caller PID, attempt ID, and same nonce. Failure evidence is
phase-specific; never invent a child PID, executable hash, or denial:

- `inventory_absent` records every verified lookup/canonical candidate and its
  absence result. It requires caller binding and forbids child PID, executable
  hash, collector event, Win32 spawn error, or denial records.
- `pre_spawn` records caller PID, nonce/attempt ID, requested canonical
  executable, identity/hash when actually available, Win32 error, and collector
  events keyed to the caller/attempt. Child PID is zero and optional security
  fields remain empty when the object could not be opened.
- `post_spawn` requires the real child PID, executable identity/hash, caller and
  child collector events, exit/diagnostic, and denial records when the trace
  actually contains access denials.

Every collector event carries its real PID, stable collector event ID and
sequence, UTC timestamp, run nonce, and attempt ID. The validator rejects
events outside the manifest's standard-user invocation start/finish window,
events from any PID other than the bound caller or child, stale nonce/attempt,
missing identity/time, and duplicate event IDs. Each denial references an
accepted denial-class event (`ACCESS DENIED` or `PRIVILEGE NOT HELD`) and must
match its PID, normalized operation/object path, and requested access. A success
or unrelated harmless event cannot anchor a denial. Runtime-name-only
association is not evidence.

JSON loading is fail-closed: the v3 schema declares
`additionalProperties:false` for every object, and the typed loader rejects
unknown fields, duplicate keys at any nesting depth, and trailing JSON before
provenance validation.

This permits honest narrowed-target or blocked selections for absence and
pre-spawn failures while `exact_token_gate_passed` remains false. Validate
without rerunning the baseline:

```powershell
$env:LOOPRIG_RUNTIME_FINAL_MANIFEST = 'C:\runtime-final.json'
$env:LOOPRIG_RUNTIME_TRACE_JSON = 'C:\runtime-evidence.json'
go test -count=1 -v ./spikes/windows -run '^TestValidateRestrictedRuntimeTraceEvidence$'
```

Success reports `exact_token_gate_passed=false` and
`failure_selection_evidence_complete=true`; it never converts a failed exact
token run into PASS. The validator opens and hashes the absolute raw trace path
and rejects stale nonce, platform, token, source revision, runtime manifest,
runtime path/identity/hash/PID/exit/diagnostic, matrix, collector, raw path, or
raw hash bindings.

Process Monitor does not provide a proven complete requested-access trace for
all NT Object Manager objects (for example every section/event/mutant used by
loader or console startup). No reviewed, repository-owned ETW profile covering
that remainder is available yet. If a failed row touches such an object, this
is a concrete external collector blocker: the schema entry cannot honestly be
completed and `failure_selection_evidence_complete` must remain false. Do not infer or fabricate
the missing access, owner, or DACL. Phase review must approve a reproducible
collector/profile for that class before selecting a result.

The only DACL mutation is on the test-owned installed-runner directory before
the helper is built. The harness records its before/after SDDL as
`fixture_acl_delta=`. The inherited ACE models an installed cooperative runner
without granting authority to an operating-system object. The spike never calls
`SetNamedSecurityInfo` (or `SetSecurityInfo`) for Windows, System32, WinSxS,
KnownDlls, PowerShell, CRT, or another OS/runtime object. Therefore the intended
OS-runtime DACL delta is exactly none; live evidence must record the observed
DACL inventory, not manufacture a delta.

## Result selection

No result is selected while live evidence and complete denial tracing remain
pending. In particular, this document does not select the exact token,
does not approve a runner bootstrap, does not narrow supported targets, and does
not approve LPAC/AppContainer work. The Phase 2 review must resolve the fixture
review complete logs from every supported disposable Windows image, and validate
trace evidence for every failure before changing this section.
