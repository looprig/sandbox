#!/bin/sh
set -eu

GO=${GO:-go}
output_dir=$(mktemp -d "${TMPDIR:-/tmp}/looprig-windows-build.XXXXXX")
trap 'rm -rf "$output_dir"' EXIT HUP INT TERM

packages=$("$GO" list ./...)
for arch in amd64 arm64; do
	arch_dir="$output_dir/$arch"
	mkdir -p "$arch_dir"
	index=0
	for package in $packages; do
		index=$((index + 1))
		CGO_ENABLED=0 GOOS=windows GOARCH="$arch" \
			"$GO" test -c -o "$arch_dir/$index.test.exe" "$package"
	done
	echo "windows/$arch test binaries build OK"
done
