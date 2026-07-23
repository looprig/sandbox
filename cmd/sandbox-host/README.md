# sandbox-host

`sandbox-host.exe` is the protected Windows companion installed by
`sandbox.SetupWindowsSandbox`. It is an internal component, not a general
command-line interface. Setup copies and hash-pins the binary in one protected
generation slot; the service and runner refuse mutable source paths or a
manifest/hash mismatch.

The executable has two roles:

- service mode runs the LocalSystem broker, either through the Service Control
  Manager dispatcher or the internal `--service` entry used by tests;
- runner mode (`--runner`) receives a bounded request over inherited standard
  I/O, switches to the broker-created private desktop, and directly creates
  the requested executable with the fully restricted duplicated token.

Runner requests contain only argv, working directory, private desktop, and a
nonce. They carry no paths, SIDs, credentials, ACLs, grants, or other authority.
The request pipe is closed before untrusted code starts, and only standard I/O
handles enter the child. Batch files are rejected because they require an
implicit shell; an explicitly requested `cmd.exe`, `powershell.exe`, or
`pwsh.exe` remains an ordinary direct executable target.

## Broker protocol v1

The broker uses a strict length-prefixed binary protocol over a protected named
pipe. V1 is closed to five operations: status, acquire lease, release lease,
issue restricted token, and reconcile. It limits frames to 1 MiB, requests to
4,096 object references, paths to 32,767 UTF-16 units, and desktop names to 255
UTF-16 units. Unknown, duplicate, direction-inappropriate, malformed, or
non-canonical fields fail closed.

Pipe ACLs admit only LocalSystem, Administrators, and the installation owner.
Authorization additionally uses kernel-reported client identity, PID, creation
time, a held process handle, and a one-shot nonce. The broker rejects
AppContainer/install-restricted callers, verifies duplicated object handles,
and never treats a string path or caller-supplied PID as authority.

V1 deliberately runs one installed host service per installation. A
SYSTEM-only first-instance anchor prevents named-pipe namespace squatting, and
installation-wide port reservation serializes proxy ownership. Horizontal
service sharding is deferred.

The `--self-test` switch verifies that the installed executable starts; it does
not prove sandbox readiness. Readiness also requires protected setup state,
accounts, credentials, firewall readback, broker reconciliation, and approved
Windows 11/Server runtime evidence. That final live-evidence gate remains
outstanding.
