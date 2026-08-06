#!/bin/sh
set -eu

: "${WINDOWS_BUILD_TEST_LOG:?}"

case "${1-}" in
list)
	if [ "${GOOS-}" = windows ]; then
		printf '%s\n' example/always "example/windows-${GOARCH-unknown}"
	else
		printf '%s\n' example/host-only
	fi
	;;
test)
	# Matched on $1 alone (not the old "$1 $2" == "test -c" exact shape) so
	# this fake tool also recognizes the -tags integration compile
	# test-windows-build.sh now issues alongside its plain one: -tags's
	# value is recorded separately so the self-test can assert BOTH the
	# untagged and the integration-tagged compile happened for every
	# enumerated package/arch, regardless of flag ordering. The package
	# name is always the last positional argument, exactly like the
	# original script relied on.
	tags=none
	package=
	previous=
	for argument in "$@"; do
		if [ "$previous" = "-tags" ]; then
			tags=$argument
		fi
		previous=$argument
		package=$argument
	done
	printf '%s %s %s\n' "${GOARCH-unknown}" "$tags" "$package" >>"$WINDOWS_BUILD_TEST_LOG"
	;;
*)
	printf 'unexpected fake go invocation: %s\n' "$*" >&2
	exit 1
	;;
esac
