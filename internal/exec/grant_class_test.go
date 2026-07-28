package exec

import (
	"errors"
	"testing"
)

// TestGrantClassValues pins the exact string VALUE of every exported grant
// enforcement-class constant. These values are the shipped wire/enforcement
// contract between sandbox and its producers (the tools permission layer). A
// rename that changed a value would silently break the seam; this test makes
// such a change fail in sandbox. The tools module independently pins the same
// literals (it must not depend on sandbox), so both sides guard the seam.
func TestGrantClassValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"GrantClassCommandStart", GrantClassCommandStart, "command.start.v1"},
		{"GrantClassNetworkProxyTarget", GrantClassNetworkProxyTarget, "network.proxy-target.v1"},
		{"GrantClassNetworkBroad", GrantClassNetworkBroad, "network.broad.v1"},
		{"GrantClassFilesystemPathRead", GrantClassFilesystemPathRead, "filesystem.path.read.v1"},
		{"GrantClassFilesystemTreeRead", GrantClassFilesystemTreeRead, "filesystem.tree.read.v1"},
		{"GrantClassFilesystemHostRead", GrantClassFilesystemHostRead, "filesystem.host.read.v1"},
		{"GrantClassFilesystemPathWrite", GrantClassFilesystemPathWrite, "filesystem.path.write.v1"},
		{"GrantClassFilesystemTreeWrite", GrantClassFilesystemTreeWrite, "filesystem.tree.write.v1"},
		{"GrantClassFilesystemHostWrite", GrantClassFilesystemHostWrite, "filesystem.host.write.v1"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestValidGrantTextRejectsInvalidUTF8 proves the enforcement-side grant-text
// validator is at least as strict as the harness producer: a grant-bound text
// containing invalid UTF-8 is rejected even though it carries no NUL and no
// surrounding whitespace, so the utf8.ValidString check is what rejects it.
func TestValidGrantTextRejectsInvalidUTF8(t *testing.T) {
	invalid := "echo\xff"
	if validGrantText(invalid) {
		t.Fatalf("validGrantText(%q) = true, want false (invalid UTF-8 must be rejected)", invalid)
	}
	if !validGrantText("echo hello") {
		t.Fatalf("validGrantText rejected a valid command")
	}
}

// TestValidateGrantClassRejectsInvalidUTF8Command proves the invalid-UTF-8
// rejection flows through the enforcement path: a command.start.v1 grant whose
// bound command is not valid UTF-8 is malformed.
func TestValidateGrantClassRejectsInvalidUTF8Command(t *testing.T) {
	_, _, err := validateGrantClass("command.execute", "", GrantClassCommandStart, "echo\xff")
	if !errors.Is(err, ErrGrantMalformed) {
		t.Fatalf("validateGrantClass invalid-UTF-8 command err = %v, want ErrGrantMalformed", err)
	}
	// A valid UTF-8 command still passes.
	if _, _, err := validateGrantClass("command.execute", "", GrantClassCommandStart, "echo hello"); err != nil {
		t.Fatalf("validateGrantClass valid command err = %v, want nil", err)
	}
}
