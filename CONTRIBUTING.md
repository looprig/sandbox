# Contributing to looprig/sandbox

Thanks for considering a contribution. `sandbox` is a standalone Go module
that constructs explicit access profiles and enforces them around spawned
commands: Landlock, seccomp, namespaces, nftables, and cgroups on Linux;
Seatbelt (SBPL) on macOS. It answers "what can a spawned process touch?",
as distinct from an approval system deciding whether a call should run at
all. See [`doc.go`](doc.go) and [`README.md`](README.md) for the module
layout and the profile/guarantee contract before making non-trivial changes.

## Before you write code

Skim the design docs in [`docs/plans/`](docs/plans/) and the enforcement
spikes in [`docs/spikes/`](docs/spikes/) for the reasoning behind the current
approach on each platform. Non-trivial work — a new enforcement primitive, a
profile or guarantee change, a new platform backend — should get a short
design doc in `docs/plans/` (dated `YYYY-MM-DD-<topic>-design.md`, and a
matching `-implementation.md` once the plan is agreed) before the code PR, so
the design conversation happens before review. Open an issue first for
anything that isn't a small, self-contained fix.

## Build, test, and secure

Run these before pushing. CI runs the same.

```sh
make fmt            # gofmt the whole module in place
make test           # go test -race ./...
make test-os        # the OS enforcement suite for the host you're on
make test-linux-build  # cross-compile the linux test binaries from any host
make secure         # fmt-check + vet + staticcheck + gosec + go mod verify + govulncheck
```

- `make test` runs the full race suite; Go picks the `//go:build`-tagged
  files for your host automatically.
- `make test-os` runs the platform enforcement suite un-cached (`-count=1`)
  because OS confinement is environment-sensitive (kernel/ABI/capabilities):
  on darwin it's the Seatbelt suite, on linux it's the namespace/Landlock/
  seccomp/nftables ladder. On any other GOOS it fails loudly rather than
  silently no-op'ing, since enforcement is only implemented for darwin and
  linux.
- `make test-linux-build` cross-compiles the linux enforcement tests
  (`GOOS=linux GOARCH=amd64`) from any host, including macOS, so you can
  prove the linux-only code still builds even when you can't run it locally.
- `make vet` vets both the host platform and linux/amd64 explicitly, because
  half this module lives behind `//go:build linux` and a host-only `go vet`
  would silently skip the namespace, Landlock, seccomp, nftables, and cgroup
  code — exactly the code most worth checking.
- `make lint` scopes `gosec` to this module's own package directories (via
  `go list`), since gosec isn't module-aware and would otherwise walk into
  any nested module beneath this one.

## Tests

- OS enforcement tests are environment-sensitive by nature (kernel version,
  ABI, capabilities, whether Landlock/seccomp/nftables are available on the
  box). They run un-cached (`-count=1`) via `make test-os` for exactly that
  reason. A host missing a prerequisite should record an explicit skip
  reason — but a skip is never a pass. Don't read a green `test-os` run as
  confirmation of enforcement on a host you haven't verified has the
  relevant kernel features; check the skip output.
- Table-driven tests where several cases share setup and assertion shape.
  Cover the happy path, boundary values, error cases, and — for this module
  especially — the denied/blocked paths, since a permissive false-negative
  here is a security bug.
- A test that passes without `-race` but fails with it is not passing.

## Pull requests

- Branch from `main`; name the branch something descriptive.
- One logical change per PR.
- Don't commit secrets, tokens, or credentials.
- Changes to kernel/OS enforcement primitives — Landlock rules, seccomp
  filters, namespace setup, nftables rules, Seatbelt profile generation, the
  policy-compilation logic — warrant extra scrutiny and a clear description
  of what was verified and how, since a mistake here means a process escapes
  confinement rather than just failing a test.

### Suspected sandbox-escape bugs

If you believe you've found a way for a confined process to escape or
exceed its granted access profile, please don't file a public issue with
exploit details. Open a private security advisory on GitHub, or otherwise
contact the maintainers directly.

## Code of conduct

Be excellent to each other. Discussions stay technical and respectful;
personal attacks, harassment, and discrimination are not welcome.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0, as described in [`LICENSE`](LICENSE).
