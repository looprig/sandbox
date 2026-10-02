package policy

import (
	"path"
	"runtime"
	"slices"
	"testing"
)

// TestBaselineEnvAllowlistSelectsPlatformList pins which list the exported
// accessor returns on the host running the test: the Windows list on Windows,
// the unchanged Unix list everywhere else.
func TestBaselineEnvAllowlistSelectsPlatformList(t *testing.T) {
	want := unixBaselineEnvAllowlist()
	if runtime.GOOS == "windows" {
		want = windowsBaselineEnvAllowlist()
	}
	if got := BaselineEnvAllowlist(); !slices.Equal(got, want) {
		t.Fatalf("BaselineEnvAllowlist() = %v, want %v", got, want)
	}
}

// TestUnixBaselineEnvAllowlistUnchanged guards the Unix list against drift
// while the Windows list is maintained beside it.
func TestUnixBaselineEnvAllowlistUnchanged(t *testing.T) {
	want := []string{"PATH", "HOME", "TERM", "LANG", "LC_*", "USER", "LOGNAME", "SHELL", "TZ"}
	if got := unixBaselineEnvAllowlist(); !slices.Equal(got, want) {
		t.Fatalf("unixBaselineEnvAllowlist() = %v, want %v", got, want)
	}
}

// TestWindowsBaselineEnvAllowlist pins what a scrubbed Windows child inherits:
// the variables the loader, CRT and common toolchains need to start, and none
// of the variables that name a user-writable or credential-bearing location
// (those are set by ExecutorSet to executor-owned paths instead) or ComSpec,
// which SPEC §4 never trusts.
func TestWindowsBaselineEnvAllowlist(t *testing.T) {
	list := windowsBaselineEnvAllowlist()
	for _, name := range []string{
		"PATH", "PATHEXT", "SystemRoot", "windir", "SystemDrive", "OS",
		"PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "NUMBER_OF_PROCESSORS",
		"ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
		"CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
		"ALLUSERSPROFILE", "USERNAME", "COMPUTERNAME", "USERDOMAIN",
		"TERM", "LANG", "LC_ALL", "TZ",
	} {
		if !windowsListAdmits(list, name) {
			t.Errorf("Windows baseline does not admit %q: %v", name, list)
		}
	}
	for _, name := range []string{
		"ComSpec", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE",
		"HOMEPATH", "HOME", "TEMP", "TMP", "TMPDIR", "PUBLIC", "LOGONSERVER",
		"USERDOMAIN_ROAMINGPROFILE", "PSModulePath", "GITHUB_TOKEN",
	} {
		if windowsListAdmits(list, name) {
			t.Errorf("Windows baseline admits %q, want it excluded: %v", name, list)
		}
	}
}

// TestWindowsEnvNameFold proves the Windows fold is case-insensitive in the
// way the exec matcher relies on: every spelling of a name folds to one key.
func TestWindowsEnvNameFold(t *testing.T) {
	for _, spelling := range []string{"Path", "PATH", "path", "pAtH"} {
		if got := windowsEnvNameFold(spelling); got != "PATH" {
			t.Errorf("windowsEnvNameFold(%q) = %q, want PATH", spelling, got)
		}
	}
	if got := windowsEnvNameFold("ProgramFiles(x86)"); got != "PROGRAMFILES(X86)" {
		t.Errorf("windowsEnvNameFold(ProgramFiles(x86)) = %q", got)
	}
}

// TestEnvNameFoldSelectsPlatformFold pins the exported fold: identity on Unix,
// where environment names are case-sensitive, upper-casing on Windows.
func TestEnvNameFoldSelectsPlatformFold(t *testing.T) {
	want := "Path"
	if runtime.GOOS == "windows" {
		want = "PATH"
	}
	if got := EnvNameFold("Path"); got != want {
		t.Fatalf("EnvNameFold(Path) = %q, want %q", got, want)
	}
}

// windowsListAdmits reports whether name matches an entry of list under the
// Windows fold, mirroring the exec matcher (path.Match on the folded name and
// the folded pattern).
func windowsListAdmits(list []string, name string) bool {
	folded := windowsEnvNameFold(name)
	for _, pattern := range list {
		if ok, err := path.Match(windowsEnvNameFold(pattern), folded); err == nil && ok {
			return true
		}
	}
	return false
}
