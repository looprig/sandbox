.PHONY: test test-os test-linux-build test-windows-build test-windows-restricted test-windows-elevated test-async-ci fmt fmt-check vet staticcheck lint vuln secure fuzz

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
else ifeq ($(GOOS),windows)
	@echo "==> Windows pure suite; use test-windows-restricted/elevated for disposable live gates"
	go test -race -count=1 ./...
else
	@echo "sandbox OS confinement is unavailable on GOOS=$(GOOS)" >&2
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
	@./scripts/test-windows-build_test.sh
	@GO="$(GO)" ./scripts/test-windows-build.sh

# These live gates intentionally set the destructive-test opt-ins. Run them
# only on disposable workers with the privilege posture named by the target.
test-windows-restricted:
ifeq ($(GOOS),windows)
	powershell -NoProfile -Command 'if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "restricted gate requires a standard-user token" }'
	go test -count=1 -v ./spikes/windows -run "^TestRestrictedRuntimeBaseline$$"
	go test -race -count=1 ./internal/winpath ./internal/policy ./pkg/profile
	powershell -NoProfile -Command '$$env:SANDBOX_WINDOWS_DISPOSABLE_RESTRICTED_TEST="1"; $$env:SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST="1"; go test -race -count=1 ./internal/windows ./internal/exec ./pkg/sandboxtest -run "Disposable|RestrictedBrokerEscape|WindowsRestricted|WindowsPath|ACLProjection|ProcessTreeWindows"'
else
	@echo "test-windows-restricted requires a disposable Windows standard-user worker" >&2
	@exit 1
endif

test-windows-elevated:
ifeq ($(GOOS),windows)
	powershell -NoProfile -Command 'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "elevated gate requires an elevated disposable worker" }'
	powershell -NoProfile -Command '$$env:SANDBOX_WINDOWS_ELEVATED_TEST="1"; go test -race -count=1 ./internal/windows ./internal/exec -run "Elevated|SetupIntegration|RecoveryIntegration|ProcessTreeWindows"'
	powershell -NoProfile -Command 'go test -count=100 ./internal/windows -run "Elevated.*Race|RecoveryIntegration|Broker.*Recovery"'
else
	@echo "test-windows-elevated requires a disposable elevated Windows worker" >&2
	@exit 1
endif

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

# Task 13 CI phase-gate guard: statically verifies .github/workflows/ci.yml
# still extends the existing platform jobs with the async sandbox-process
# selectors from Tasks 10-12 (rather than silently dropping/replacing them).
# Local-only, no network call.
test-async-ci:
	sh scripts/test-async-ci-workflow.sh
