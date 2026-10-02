package windows

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// TestUnixSocketsRequestedIsAnyNonDefaultPolicy pins the trigger both Windows
// tiers refuse on: any mode other than the default denial, or any named
// endpoint, alone or together. Only the zero policy compiles.
func TestUnixSocketsRequestedIsAnyNonDefaultPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy profile.UnixSocketPolicy
		want   bool
	}{
		{"default denial", profile.UnixSocketPolicy{}, false},
		{"local mode", profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal}, true},
		{"named endpoint only", profile.UnixSocketPolicy{Paths: []string{`C:\agent\ssh.sock`}}, true},
		{"local and named", profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal, Paths: []string{`C:\agent\ssh.sock`}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := unixSocketsRequested(policy.Effective{UnixSockets: test.policy}); got != test.want {
				t.Fatalf("unixSocketsRequested = %v, want %v", got, test.want)
			}
		})
	}
}

// TestRefuseUnixSocketsIsTypedAndNeverSetupRequired proves the refusal carries
// both the backend-unavailable and the unsupported-class sentinels, and is not
// ErrSetupRequired (which would make Auto fall back to a tier that cannot
// mediate AF_UNIX either).
func TestRefuseUnixSocketsIsTypedAndNeverSetupRequired(t *testing.T) {
	err := refuseUnixSockets("restricted")
	if !errors.Is(err, enforce.ErrUnavailable) || !errors.Is(err, policy.ErrUnsupportedClass) {
		t.Fatalf("refusal = %v, want ErrUnavailable and ErrUnsupportedClass", err)
	}
	if errors.Is(err, ErrSetupRequired) || errors.Is(err, ErrSetupStale) {
		t.Fatalf("refusal = %v must not be a setup state", err)
	}
}

// TestUnixSocketsReportEntryOnlyForNonDefaultPolicy pins the exact report
// entry and proves a default-denial profile's report is left untouched.
func TestUnixSocketsReportEntryOnlyForNonDefaultPolicy(t *testing.T) {
	base := profile.CompileReport{Entries: []profile.ReportEntry{{Feature: "windows.token", Status: "Narrowed"}}}
	if got := withUnixSocketsReport(base, policy.Effective{}); len(got.Entries) != 1 {
		t.Fatalf("default policy report = %#v, want unchanged", got)
	}
	got := withUnixSocketsReport(base, policy.Effective{UnixSockets: profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal}})
	want := profile.ReportEntry{Feature: "unix-sockets", Status: "unavailable", Detail: "AF_UNIX endpoints are not mediated on Windows"}
	if len(got.Entries) != 2 || got.Entries[1] != want {
		t.Fatalf("report = %#v, want trailing %#v", got, want)
	}
}
