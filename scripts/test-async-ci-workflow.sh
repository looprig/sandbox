#!/bin/sh
# Task 13 CI phase-gate guard.
#
# Statically verifies .github/workflows/ci.yml still wires the async
# sandbox-process acceptance coverage from Tasks 10-12 into the EXISTING
# platform jobs (test-linux-rung1, test-linux-rung2, test-macos,
# windows-restricted, windows-elevated) instead of inventing replacement job
# keys or silently dropping the selectors. It makes no network call and does
# not treat a missing workflow file, a missing job, or a missing selector as
# anything other than a hard failure.
#
# This is a lightweight line-based parser, not a real YAML parser (the
# repository's `python3 -c "import yaml..."` check in the verification
# recipe covers general syntactic validity separately). It only needs to
# reliably slice this file's own two-space-indented `jobs:` block, which is
# a much narrower and stable contract.
#
# Usage: sh scripts/test-async-ci-workflow.sh

set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORKFLOW="$REPO_ROOT/.github/workflows/ci.yml"

fail() {
	echo "test-async-ci-workflow: FAIL: $1" >&2
	exit 1
}

note() {
	echo "test-async-ci-workflow: $1"
}

[ -f "$WORKFLOW" ] || fail "workflow file not found: $WORKFLOW"

# --- required, pre-existing platform job keys -------------------------------
#
# Task 13 extends these; it must never require (or tolerate silently
# accepting) an invented replacement job key instead.
REQUIRED_JOBS="test-linux-rung1 test-linux-rung2 test-macos windows-restricted windows-elevated"

# job_block NAME prints the lines of NAME's job block (its own top-level
# `  NAME:` line up to, but excluding, the next top-level two-space-indented
# job key line, or EOF). Empty output means the job key does not exist.
job_block() {
	name="$1"
	awk -v name="$name" '
		/^jobs:[[:space:]]*$/ { in_jobs = 1; next }
		in_jobs && /^[A-Za-z]/ { in_jobs = 0 }
		!in_jobs { next }
		/^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
			key = $0
			sub(/^  /, "", key)
			sub(/:[[:space:]]*$/, "", key)
			capture = (key == name) ? 1 : 0
			if (capture) print
			next
		}
		capture { print }
	' "$WORKFLOW"
}

for job in $REQUIRED_JOBS; do
	block=$(job_block "$job")
	[ -n "$block" ] || fail "required existing platform job '$job' is missing from $WORKFLOW (Task 13 must extend it, not replace/rename it)"
done

# require_in NAME PATTERN DESCRIPTION fails unless PATTERN (a literal
# fixed-string grep pattern) appears in job NAME's block.
require_in() {
	job="$1"
	pattern="$2"
	description="$3"
	block=$(job_block "$job")
	if ! printf '%s\n' "$block" | grep -qF -- "$pattern"; then
		fail "job '$job' is missing $description (expected to find literal text: $pattern)"
	fi
}

# require_not_in NAME PATTERN DESCRIPTION fails if PATTERN DOES appear.
require_not_in() {
	job="$1"
	pattern="$2"
	description="$3"
	block=$(job_block "$job")
	if printf '%s\n' "$block" | grep -qF -- "$pattern"; then
		fail "job '$job' unexpectedly $description (found literal text: $pattern)"
	fi
}

note "checking test-linux-rung1 / test-linux-rung2 async selectors"
for job in test-linux-rung1 test-linux-rung2; do
	require_in "$job" '-tags integration' "the integration build tag"
	require_in "$job" '-race' "race mode"
	# The exact focused Phase-Gate-3 selector this plan's own text queues:
	# TestIntegration(ProcessPipe|ProcessPreparedGrant|ProcessTree) — this
	# single regex covers the Unix process-tree parent-death/double-fork/
	# setsid-escape containment proofs (...ProcessTree...) and the prepared
	# grant lifetime proof (...ProcessPreparedGrant...); ProcessPipe is kept
	# in the alternation for forward compatibility even though no test
	# currently carries that exact name (see Task 13's own reconciliation
	# note: the Task 10 pipe-lifecycle behaviors landed as untagged tests in
	# process_test.go, which already run under plain `go test ./...` with no
	# tag needed).
	require_in "$job" "TestIntegration(ProcessPipe|ProcessPreparedGrant|ProcessTree)" \
		"the async process-lifecycle selector (parent-death/double-fork/setsid-escape + grant lifetime)"
done

note "checking test-macos Darwin pre-spawn fail-closed selector"
require_in test-macos '-tags integration' "the integration build tag"
require_in test-macos "TestIntegrationProcessTreeDarwinSetsidFailsClosed" \
	"the Darwin pre-spawn fail-closed selector"
# Darwin explicitly does not claim async pipe-process execution in this
# phase (Task 12c): the macOS job must not carry the broader selector that
# would advertise live async pipe/grant-lifetime execution there.
require_not_in test-macos "TestIntegration(ProcessPipe|ProcessPreparedGrant|ProcessTree)" \
	"advertises the cross-platform async pipe/grant selector"
require_not_in test-macos "TestIntegrationProcessPreparedGrantLifetime" \
	"advertises live grant-lifetime async execution"

note "checking windows-restricted / windows-elevated live Job selectors"
for job in windows-restricted windows-elevated; do
	block=$(job_block "$job")
	# Live runtime requirement: cross-build success on windows-cross-compile
	# is not a substitute. Both jobs must run on a real self-hosted Windows
	# worker.
	printf '%s\n' "$block" | grep -q 'runs-on:.*self-hosted.*Windows' \
		|| fail "job '$job' does not run on a live self-hosted Windows worker (cross-build is not a substitute for a runtime job)"
	# Task 12D's queued phase-gate selector: TestProcessTreeWindows(JobBeforeResume|JobEmptyOnClose).
	# No //go:build integration Windows test was ever created by this plan's
	# tasks (12D's tests are plain //go:build windows tests, already
	# OS-gated) — so unlike Linux/Darwin this is not `-tags integration`.
	require_in "$job" "ProcessTreeWindows" \
		"the live restricted/elevated Job path selector (TestProcessTreeWindowsJobBeforeResume / TestProcessTreeWindowsJobEmptyOnClose)"
done

note "checking windows-cross-compile is not mistaken for runtime evidence"
cross_block=$(job_block windows-cross-compile)
if [ -n "$cross_block" ]; then
	if printf '%s\n' "$cross_block" | grep -q 'runs-on:.*self-hosted'; then
		fail "windows-cross-compile runs on a self-hosted worker; it must remain a cross-build-only job, not a substitute for windows-restricted/windows-elevated runtime evidence"
	fi
fi

note "PASS: async sandbox process selectors are wired into the existing platform jobs"
