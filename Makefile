.PHONY: test test-os test-linux-build vet

GOOS := $(shell go env GOOS)

# Full race suite. Go selects the OS-appropriate `//go:build` test files for the
# host automatically, so this already runs the correct platform's tests.
test:
	go test -race ./...

# OS enforcement suite for the host this runs on. Run un-cached (-count=1) because
# OS confinement is environment-sensitive (kernel/ABI/capabilities), and target the
# root package where the platform enforcement tests live. On a host missing a
# prerequisite the tests record an explicit skip reason — a skip is never a pass.
test-os:
ifeq ($(GOOS),darwin)
	@echo "==> macOS Seatbelt enforcement suite (GOOS=darwin)"
	go test -race -count=1 .
else ifeq ($(GOOS),linux)
	@echo "==> Linux enforcement suite (GOOS=linux): rung-1 user/mount/net namespaces + nftables, rung-2 Landlock-v4/seccomp"
	go test -race -count=1 .
else
	@echo "sandbox OS confinement is implemented only on darwin and linux (GOOS=$(GOOS)); nothing to run" >&2
	@exit 1
endif

# Cross-compile the linux enforcement tests from any host (e.g. macOS) to prove
# they still build for linux/amd64 without executing them.
test-linux-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o /dev/null ./...
	@echo "linux/amd64 test binaries build OK"

vet:
	go vet ./...
