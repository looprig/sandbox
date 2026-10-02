package windows

import (
	"fmt"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// unixSocketsReportFeature and unixSocketsUnavailableDetail are the stable
// compile-report entry both Windows tiers emit for a profile that asks for any
// AF_UNIX posture other than the default denial.
const (
	unixSocketsReportFeature     = "unix-sockets"
	unixSocketsUnavailableStatus = "unavailable"
	unixSocketsUnavailableDetail = "AF_UNIX endpoints are not mediated on Windows"
)

// unixSocketsRequested reports whether p leaves the default AF_UNIX denial:
// any mode other than UnixSocketsDenied, or any explicitly named endpoint.
//
// Windows AF_UNIX sockets (afunix.sys, Windows 10 1803+) are file-backed: a
// pathname socket is a reparse point in the file system, so whether a connect
// succeeds is decided by that file's DACL and its owning service, not by any
// mechanism this module installs. Neither tier has a tested mediation for it:
// the restricted tier claims no boundary at all, and the elevated tier's ACL
// leases project only the configured filesystem roots, never a named endpoint
// such as an agent socket. Admitting the escape hatch would therefore be an
// unverified widening (Local, or a named Paths entry, granted by whatever DACL
// the service set) or an unverified narrowing (a named endpoint the leases
// silently cannot reach). The honest answer is a typed refusal.
func unixSocketsRequested(p policy.Effective) bool {
	return p.UnixSockets.Mode != profile.UnixSocketsDenied || len(p.UnixSockets.Paths) != 0
}

// refuseUnixSockets is the typed refusal both tiers return for such a
// profile. It wraps enforce.ErrUnavailable (the backend cannot provide the
// requested posture, so construction must fail rather than downgrade) and
// policy.ErrUnsupportedClass (the request names a class of authority this
// platform does not support), matching the restricted tier's refusal of
// network grants. Neither sentinel is ErrSetupRequired, so Auto never falls
// back from one tier to the other on it: neither tier could satisfy it.
func refuseUnixSockets(tier string) error {
	return fmt.Errorf("%w: %w: Windows %s mode does not mediate AF_UNIX sockets (profile.UnixSocketPolicy must stay at its default denial)",
		enforce.ErrUnavailable, policy.ErrUnsupportedClass, tier)
}

// withUnixSocketsReport appends the unix-sockets entry to report when p asks
// for any AF_UNIX posture; a default-denial profile's report is unchanged.
func withUnixSocketsReport(report profile.CompileReport, p policy.Effective) profile.CompileReport {
	if !unixSocketsRequested(p) {
		return report
	}
	report.Entries = append(report.Entries, profile.ReportEntry{
		Feature: unixSocketsReportFeature, Status: unixSocketsUnavailableStatus, Detail: unixSocketsUnavailableDetail,
	})
	return report
}
