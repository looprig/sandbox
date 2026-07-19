//go:build darwin

package sandbox

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSeatbeltProfileUsesScopedRuntimeReadExecAndExactProxyListener(t *testing.T) {
	policy := effectivePolicy{
		Workspace: "/workspace",
		FS: []fsEntry{
			{Path: "/usr", Access: readFSAccess | execFSAccess},
			{Path: "/bin", Access: readFSAccess | execFSAccess},
			{Path: "/workspace", Access: readFSAccess | writeFSAccess | execFSAccess},
		},
		Net:       effectiveNetPolicy{ProxyPort: 43123},
		Env:       effectiveEnvPolicy{Set: map[string]string{}},
		Isolation: Sandboxed,
	}
	profile, report, level, bits := compileSBPL(policy)
	for _, forbidden := range []string{
		"(allow file-read*)\n",
		"(allow file-read-metadata)\n",
		"(allow process-exec*)\n",
		`(allow network-outbound (remote tcp "*:43123"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
	} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("Seatbelt profile contains broad rule %q:\n%s", forbidden, profile)
		}
	}
	for _, required := range []string{
		`(allow file-read-data (literal "/"))`,
		`(allow file-read* (subpath "/private/var/select"))`,
		`(allow file-read* (subpath "/usr"))`,
		`(allow process-exec (subpath "/bin"))`,
		`(allow network-outbound (remote tcp "localhost:43123"))`,
	} {
		if !strings.Contains(profile, required) {
			t.Errorf("Seatbelt profile missing scoped rule %q:\n%s", required, profile)
		}
	}
	if level != LevelFull || bits&GuaranteeReadBoundary == 0 || bits&GuaranteeTargetNetwork == 0 || bits&GuaranteeNetworkBoundary == 0 {
		t.Fatalf("Seatbelt posture = level %d bits %#b report %+v", level, bits, report.Entries)
	}
}

func TestSeatbeltScopedRuntimeRulesLaunch(t *testing.T) {
	requireSandboxExec(t)
	policy := effectivePolicy{
		FS: []fsEntry{
			{Path: "/usr", Access: readFSAccess | execFSAccess},
			{Path: "/bin", Access: readFSAccess | execFSAccess},
			{Path: "/sbin", Access: readFSAccess | execFSAccess},
			{Path: "/lib", Access: readFSAccess | execFSAccess},
			{Path: "/lib64", Access: readFSAccess | execFSAccess},
			{Path: "/etc", Access: readFSAccess | execFSAccess},
			{Path: "/System", Access: readFSAccess | execFSAccess},
			{Path: "/Library", Access: readFSAccess | execFSAccess},
		},
		Net:       effectiveNetPolicy{ProxyPort: 43123},
		Env:       effectiveEnvPolicy{Set: map[string]string{}},
		Isolation: Sandboxed,
	}
	profile, _, _, _ := compileSBPL(policy)
	if err := exec.Command("/usr/bin/sandbox-exec", "-p", profile, "--", "/usr/bin/true").Run(); err != nil {
		t.Fatalf("scoped runtime profile could not launch /usr/bin/true: %v\n%s", err, profile)
	}
}
