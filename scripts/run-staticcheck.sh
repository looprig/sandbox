#!/bin/sh

set -u

go_command=${GO:-go}

packages=$("$go_command" list ./...)
list_status=$?
if [ "$list_status" -ne 0 ]; then
	echo "staticcheck: go list ./... failed" >&2
	exit "$list_status"
fi
if [ -z "$packages" ]; then
	echo "staticcheck: go list ./... returned no packages" >&2
	exit 1
fi

set --
while IFS= read -r package; do
	if [ -n "$package" ]; then
		set -- "$@" "$package"
	fi
done <<EOF
$packages
EOF

if [ "$#" -eq 0 ]; then
	echo "staticcheck: go list ./... returned no packages" >&2
	exit 1
fi

exec "$go_command" tool staticcheck "$@"
