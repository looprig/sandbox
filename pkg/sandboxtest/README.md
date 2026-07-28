# sandboxtest

`sandboxtest` is a reusable, standard-library-only conformance suite for
sandbox executors. External backends implement the small structural `SUT`
interface rather than importing this module's internal packages:

```go
type SUT interface {
	RunCommand(context.Context, string, string) ([]byte, int, error)
	Level() uint8
	GuaranteeBits() uint64
}
```

`ArgvSUT` is an optional shell-free extension used by platform probes when an
operation has a direct executable form. `RunSuite` accepts a factory that
returns a fresh SUT for each check, so state and planted environment values do
not leak between cases.

## One-way assertions

The suite tests claimed implications, not mechanism names. A set guarantee bit
must survive its negative probes, and every negative probe needs an unconfined
positive control. A missing bit does not require permissive behavior: a backend
may enforce defense in depth without claiming an end-to-end guarantee.

The base suite checks in-policy reads/writes, claimed read/write boundaries,
environment scrubbing, and level/bit consistency. `CheckClaimedImplications`
adds scenario-specific process, network, address, target, and resource probes.
A claimed bit without a supplied probe fails.

## Platform command helpers

The package keeps shell details behind platform files. Unix helpers use the
platform shell only where a direct argv operation is unavailable. Windows
helpers prefer `ArgvSUT` and otherwise construct explicit `cmd.exe` commands
with Windows quoting. Consumers call `RunSuite` and implication probes; they do
not need to select a shell themselves.

## Reuse from another module

```go
func TestBackendConformance(t *testing.T) {
	sandboxtest.RunSuite(t, "backend", func(t *testing.T, workspace string) sandboxtest.SUT {
		sut := newBackendForTest(t, workspace)
		t.Cleanup(func() { _ = sut.Close() })
		return sut
	})
}
```

Mirror the exported guarantee-bit positions exactly and add a drift test if
your package also exposes named constants. Supply a fresh writable workspace,
ensure the outside positive-control targets are usable, and clean up every
process, listener, grant, ACL, and machine object your factory owns. Never
convert an unavailable requested mechanism into a passing skip.
