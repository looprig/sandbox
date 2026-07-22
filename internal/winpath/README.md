# Windows path identity

`winpath` is the leaf Windows object-path service. It accepts only absolute
local DOS drive paths (ordinary or `\\?\C:\...` spelling), opens without
following the leaf reparse point, and derives the canonical DOS name and stable
identity from the resulting handle.

The package deliberately rejects UNC, object-manager/device, `GLOBALROOT`,
volume-GUID, drive-relative, alternate-stream, and non-NTFS/ReFS targets. It
does not reinterpret an unsupported spelling as a broader path. `Object` owns
its handle; callers must call `Close`.

## Live verification status

Cross-builds do not execute Windows syscalls. The required live gate remains
pending on a supported Windows worker:

```powershell
go test -race -count=1 ./internal/winpath ./pkg/profile ./internal/policy
```

Until that command passes on NTFS and ReFS fixtures, the implementation has
compile/test-shape evidence only for Windows-specific behavior.
