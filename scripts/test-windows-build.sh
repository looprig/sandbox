#!/bin/sh
set -eu

GO=${GO:-go}
output_dir=$(mktemp -d "${TMPDIR:-/tmp}/looprig-windows-build.XXXXXX")
trap 'rm -rf "$output_dir"' EXIT HUP INT TERM

for arch in amd64 arm64; do
	packages=$(CGO_ENABLED=0 GOOS=windows GOARCH="$arch" "$GO" list ./...)
	if [ -z "$packages" ]; then
		echo "no packages found for windows/$arch" >&2
		exit 1
	fi
	arch_dir="$output_dir/$arch"
	mkdir -p "$arch_dir"
	index=0
	for package in $packages; do
		index=$((index + 1))
		CGO_ENABLED=0 GOOS=windows GOARCH="$arch" \
			"$GO" test -c -o "$arch_dir/$index.test.exe" "$package"
		# Also compile (never run) the SAME package under -tags integration.
		# A helper referenced only from an integration-tagged file can
		# compile fine under plain `windows` and still break specifically
		# under `windows + integration` (Task 22C's own skipIfNoRealBackend
		# fix was exactly this class of break); without this second compile,
		# nothing catches that on an ordinary PR — only the self-hosted
		# windows-restricted/windows-elevated jobs would, and only as a side
		# effect of running on live, infrastructure-gated hardware.
		CGO_ENABLED=0 GOOS=windows GOARCH="$arch" \
			"$GO" test -tags integration -c -o "$arch_dir/$index-integration.test.exe" "$package"
	done
	echo "windows/$arch test binaries build OK"
done
