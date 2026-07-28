#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/looprig-windows-build-test.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

log="$test_dir/go-test.log"
: >"$log"
WINDOWS_BUILD_TEST_LOG="$log" GO="$script_dir/testdata/fake-go-windows-enumeration.sh" \
	"$script_dir/test-windows-build.sh" >/dev/null

require_line() {
	if ! grep -Fqx "$1" "$log"; then
		echo "missing cross-build invocation: $1" >&2
		return 1
	fi
}

for arch in amd64 arm64; do
	require_line "$arch example/always"
	require_line "$arch example/windows-$arch"
done
if grep -Fq 'host-only' "$log"; then
	echo "cross-build compiled a package from host-only enumeration" >&2
	exit 1
fi
