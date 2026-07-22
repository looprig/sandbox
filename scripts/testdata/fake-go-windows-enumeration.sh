#!/bin/sh
set -eu

: "${WINDOWS_BUILD_TEST_LOG:?}"

case "${1-} ${2-}" in
"list ./...")
	if [ "${GOOS-}" = windows ]; then
		printf '%s\n' example/always "example/windows-${GOARCH-unknown}"
	else
		printf '%s\n' example/host-only
	fi
	;;
"test -c")
	package=
	for argument in "$@"; do
		package=$argument
	done
	printf '%s %s\n' "${GOARCH-unknown}" "$package" >>"$WINDOWS_BUILD_TEST_LOG"
	;;
*)
	printf 'unexpected fake go invocation: %s\n' "$*" >&2
	exit 1
	;;
esac
