# Windows path identity

`winpath` is the leaf Windows object-path service. It accepts only absolute
local DOS drive paths (ordinary or `\\?\C:\...` spelling), opens without
following the leaf reparse point, and derives the canonical DOS name and stable
identity from the resulting handle.

The package deliberately rejects UNC, object-manager/device, `GLOBALROOT`,
named-pipe, raw-device, volume-GUID, drive-relative, alternate-stream, and
non-NTFS/ReFS targets. It does not reinterpret an unsupported spelling as a
broader path.

## Handle ownership

`Open` returns an `Object` that exclusively owns its no-follow Windows handle.
The handle pins the opened identity while callers compare the canonical DOS
path, volume serial, 128-bit file ID, type, reparse tag, and link count. Copying
an `Object` does not duplicate the kernel handle. The owner must call `Close`
exactly once and must keep the object alive for the entire authorization or ACL
mutation. Callers that need independent lifetimes must open independent
objects.

Path strings never substitute for the retained handle. Revalidation fails when
the final name, stable ID, type, or any ancestor/reparse transition changes.
Unsupported namespace syntax is rejected before it can be normalized into a
different authority class.

## Live verification status

Cross-builds do not execute Windows syscalls. The required live gate remains
pending on a supported Windows worker:

```powershell
go test -race -count=1 ./internal/winpath ./pkg/profile ./internal/policy
```

Until that command passes on NTFS and ReFS fixtures, the implementation has
compile/test-shape evidence only for Windows-specific behavior.
