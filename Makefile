.PHONY: test test-os test-linux-build test-windows-build fmt fmt-check vet staticcheck lint vuln secure fuzz

GO ?= go
GOOS := $(shell go env GOOS)

# This module's own package dirs. `go list` stops at nested module boundaries,
# so this is also what scopes gosec away from any foreign tree beneath us.
GO_DIRS = $(shell go list -f '{{.Dir}}' ./...)

# Full race suite. Go selects the OS-appropriate `//go:build` test files for the
# host automatically, so this already runs the correct platform's tests.
test:
	go test -race ./...

# OS enforcement suite for the host this runs on. Run un-cached (-count=1) because
# OS confinement is environment-sensitive (kernel/ABI/capabilities). The platform
# enforcement tests live under internal/, so target those alongside the root
# acceptance suite. On a host missing a prerequisite the tests record an explicit
# skip reason — a skip is never a pass.
test-os:
ifeq ($(GOOS),darwin)
	@echo "==> macOS Seatbelt enforcement suite (GOOS=darwin)"
	go test -race -count=1 . ./internal/...
else ifeq ($(GOOS),linux)
	@echo "==> Linux enforcement suite (GOOS=linux): rung-1 user/mount/net namespaces + nftables, rung-2 Landlock-v4/seccomp"
	go test -race -count=1 . ./internal/...
else
	@echo "sandbox OS confinement is implemented only on darwin and linux (GOOS=$(GOOS)); nothing to run" >&2
	@exit 1
endif

# Cross-compile the linux enforcement tests from any host (e.g. macOS) to prove
# they still build for linux/amd64 without executing them.
test-linux-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o /dev/null ./...
	@echo "linux/amd64 test binaries build OK"

# Cross-compile every package's tests independently for both supported Windows
# architectures. The helper owns a temporary output directory and leaves no
# .exe files in the repository.
test-windows-build:
	@GO="$(GO)" ./scripts/test-windows-build.sh

# Format the whole module in place.
fmt:
	gofmt -w $(GO_DIRS)

# Fail (non-zero exit) if any tracked Go file is not gofmt-clean. Wired into lint.
fmt-check:
	@unformatted=$$(gofmt -l $(GO_DIRS)); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
	fi

# Vet both platforms. Half this module is behind //go:build linux, so a
# host-only vet silently skips the namespace, Landlock, seccomp, nftables, and
# cgroup code — exactly the code most worth checking.
vet:
	go vet ./...
	@echo "==> vetting linux/amd64 (platform files this host would otherwise skip)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go vet ./...

lint: fmt-check
	$(MAKE) vet
	$(MAKE) staticcheck
	# gosec is NOT module-aware: its ./... is a filesystem walk that would descend
	# into any nested module. Scope it to THIS module's package dirs via GO_DIRS
	# (the same go-list idiom fmt/fmt-check use). go vet and staticcheck are
	# module-aware, so they need no scoping.
	go tool gosec $(GO_DIRS)

staticcheck:
	@GO="$(GO)" ./scripts/run-staticcheck.sh

vuln:
	go mod verify
	go tool govulncheck ./...

secure: lint vuln

fuzz:
	@echo "Usage: go test -fuzz=FuzzXxx ./path/to/pkg -fuzztime=30s"
