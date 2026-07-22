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
supports, using a disposable standard-user worker:

```powershell
go test -count=1 -v ./spikes/windows -run TestRestrictedRuntimeBaseline
```

The command must finish with `PASS`; `SKIP`, a compile-only result, or a result
copied from a different Windows image does not satisfy the gate. Preserve the
complete verbose log as CI evidence. If a worker-level timeout is available,
set it above the harness's per-process 20-second watchdog so the harness can
terminate and report a stuck target first.

The live evidence record for each image must add:

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

## Runtime table

The required rows are:

| Row | Probe |
|---|---|
| Installed runner | A statically built, installed-runner-shaped Go helper in a test-owned directory with an explicit inherited Restricted Code read/execute ACE |
| Go subprocess | The helper creates a second copy of itself and waits for it |
| CRT and DLL initializer | The helper loads and unloads `kernelbase.dll` and `ucrtbase.dll`; a successful `LoadLibraryEx` includes process-attach initializer execution |
| Locale and console | The helper queries the user locale and console code pages and is launched with a new console |
| Callback fixture | The helper allocates Windows Fiber Local Storage, sets a value, frees it, and verifies synchronous cleanup-callback dispatch |
| Canonical command shell | `GetSystemDirectory()` + `cmd.exe /D /S /C "exit 0"` |
| Windows PowerShell | Canonical System32 Windows PowerShell with no profile and no interaction |

The callback row exercises Windows per-thread storage callback dispatch but is
not a synthetic PE image TLS-directory callback. Before a reviewed result can
claim the plan's stronger loader-callback coverage, the live review must either
identify an already-present, safely loadable runtime module with an observable
PE TLS callback or add an architecture-specific owned fixture. This limitation
is recorded rather than disguised as live proof.

Python is named by the Windows conformance plan, so installed `python.exe` or
`py.exe` is run. The inventory also discovers installed Node.js, .NET, Java,
Ruby, Perl, and PowerShell Core runtimes. An absent optional runtime is recorded
as `NOT_INSTALLED`; the whole test itself never calls `t.Skip`. `cmd.exe`,
Windows PowerShell, and all helper rows are required and fail if absent or
unlaunchable.

## Object and ACL diagnostics

Every runtime row records:

- requested image/loader startup access:
  `FILE_EXECUTE|FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE`;
- canonical executable path;
- volume serial and file ID, plus link count;
- owner SID;
- security descriptor in SDDL form, including the DACL;
- process-creation or exit error, exit code, bounded output, and watchdog result.

These diagnostics identify the executable object requested at the failed
creation boundary. A loader denial involving a transitive DLL may surface from
Windows only as a process-start or early-exit error; in that case the retained
log is evidence of the gap but the denied dependent object still requires a
disposable-worker trace before selecting a result.

The only DACL mutation is on the test-owned installed-runner directory before
the helper is built. The harness records its before/after SDDL as
`fixture_acl_delta=`. The inherited ACE models an installed cooperative runner
without granting authority to an operating-system object. The spike never calls
`SetNamedSecurityInfo` (or `SetSecurityInfo`) for Windows, System32, WinSxS,
KnownDlls, PowerShell, CRT, or another OS/runtime object. Therefore the intended
OS-runtime DACL delta is exactly none; live evidence must record the observed
DACL inventory, not manufacture a delta.

## Result selection

No result is selected while live evidence and the PE TLS-callback fixture gap
remain pending. In particular, this document does not select the exact token,
does not approve a runner bootstrap, does not narrow supported targets, and does
not approve LPAC/AppContainer work. The Phase 2 review must resolve the fixture
gap and review complete logs from every supported disposable Windows image
before changing this section.
