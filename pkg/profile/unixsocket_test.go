package profile

import (
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestUnixSocketsDefaultDeniedAndFingerprintStable(t *testing.T) {
	workspace := t.TempDir()
	plain := mustProfile(t, ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow})
	explicit := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Mode: UnixSocketsDenied},
	})
	if got := plain.UnixSockets(); got.Mode != UnixSocketsDenied || len(got.Paths) != 0 {
		t.Fatalf("default UnixSockets = %+v, want denied with no paths", got)
	}
	// The zero policy is the pre-existing contract, so a profile that never
	// names it keeps the fingerprint it always had.
	if plain.Fingerprint() != explicit.Fingerprint() {
		t.Fatal("an explicit zero UnixSocketPolicy changed the fingerprint")
	}
	if plain.Settings().UnixSockets.Mode != UnixSocketsDenied {
		t.Fatal("Settings does not carry the unix-socket policy")
	}
}

func TestUnixSocketsNormalizeAndFingerprint(t *testing.T) {
	workspace := t.TempDir()
	agent := filepath.Join(t.TempDir(), "agent.sock")
	docker := filepath.Join(t.TempDir(), "docker.sock")
	// The trailing-separator spelling is the platform's own separator (a
	// filepath.Join-built path ending in one), plus a literal "/": on Windows
	// filepath treats '/' as a separator too, so `C:\...\agent.sock/` is the
	// same tolerated spelling; on darwin and Linux the two cases coincide.
	a := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Mode: UnixSocketsLocal, Paths: []string{
			docker, agent, agent + string(filepath.Separator), agent + "/",
		}},
	})
	got := a.UnixSockets()
	if got.Mode != UnixSocketsLocal {
		t.Fatalf("Mode = %d, want UnixSocketsLocal", got.Mode)
	}
	want := []string{agent, docker}
	slices.Sort(want)
	if !slices.Equal(got.Paths, want) {
		t.Fatalf("Paths = %v, want sorted, deduplicated %v", got.Paths, want)
	}
	// The accessor hands out a copy.
	got.Paths[0] = "/mutated"
	if a.UnixSockets().Paths[0] == "/mutated" {
		t.Fatal("UnixSockets returned the internal slice")
	}

	plain := mustProfile(t, ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow})
	local := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Mode: UnixSocketsLocal},
	})
	paths := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Paths: []string{agent}},
	})
	for name, pair := range map[string][2]*Profile{
		"local vs denied": {plain, local}, "paths vs denied": {plain, paths}, "local vs paths": {local, paths}, "local vs both": {local, a},
	} {
		if pair[0].Fingerprint() == pair[1].Fingerprint() {
			t.Errorf("%s: unix-socket authority change did not change the fingerprint", name)
		}
	}
}

func TestUnixSocketsRejectsInvalidInput(t *testing.T) {
	workspace := t.TempDir()
	for name, policy := range map[string]UnixSocketPolicy{
		"unknown mode":  {Mode: UnixSocketMode(7)},
		"relative path": {Paths: []string{"run/agent.sock"}},
		"unclean path":  {Paths: []string{"/run/../run/agent.sock"}},
		"empty path":    {Paths: []string{""}},
		"root path":     {Paths: []string{"/"}},
		// The two Unix spellings above are not even absolute on Windows, so
		// they are refused there for the wrong reason. These are the same
		// cases spelled for the platform: a ".." under the absolute
		// workspace, and the root of the volume holding it ("/" again off
		// Windows), each refused on every GOOS.
		"platform unclean path": {Paths: []string{strings.Join([]string{workspace, "run", "..", "agent.sock"}, string(filepath.Separator))}},
		"volume root path":      {Paths: []string{filepath.VolumeName(workspace) + string(filepath.Separator)}},
	} {
		_, err := NewProfile(ProfileConfig{
			WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow, UnixSockets: policy,
		})
		if !errors.Is(err, ErrInvalidProfile) {
			t.Errorf("%s: NewProfile error = %v, want ErrInvalidProfile", name, err)
		}
	}
}

// TestUnixSocketsTrailingBackslashIsPlatformSpecific pins the other half of
// the trailing-separator rule: only bytes filepath treats as separators are
// trimmed. On Windows a trailing '\' is the separator and folds into the
// bare path; on darwin and Linux '\' is an ordinary filename byte, so
// "agent.sock\" names a different socket and must survive as its own grant
// rather than being silently re-spelled onto "agent.sock".
func TestUnixSocketsTrailingBackslashIsPlatformSpecific(t *testing.T) {
	workspace := t.TempDir()
	agent := filepath.Join(t.TempDir(), "agent.sock")
	p := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Paths: []string{agent, agent + `\`}},
	})
	want := []string{agent}
	if runtime.GOOS != "windows" {
		want = append(want, agent+`\`)
	}
	slices.Sort(want)
	if got := p.UnixSockets().Paths; !slices.Equal(got, want) {
		t.Fatalf("Paths = %q, want %q on %s", got, want, runtime.GOOS)
	}
}

func TestUnixSocketsUnconfinedRequiresNothing(t *testing.T) {
	// An unconfined profile has every socket anyway; the policy is accepted
	// and recorded so Restrict against a sandboxed ceiling still intersects.
	p := mustProfile(t, unconfinedConfig(t.TempDir(), true))
	if p.UnixSockets().Mode != UnixSocketsDenied {
		t.Fatalf("unconfined default = %+v", p.UnixSockets())
	}
}

func TestRestrictIntersectsUnixSockets(t *testing.T) {
	workspace := t.TempDir()
	agent := filepath.Join(t.TempDir(), "agent.sock")
	docker := filepath.Join(t.TempDir(), "docker.sock")
	base := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Mode: UnixSocketsLocal, Paths: []string{agent, docker}},
	})
	ceiling := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		UnixSockets: UnixSocketPolicy{Mode: UnixSocketsDenied, Paths: []string{agent}},
	})
	got, err := Restrict(base, ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if us := got.UnixSockets(); us.Mode != UnixSocketsDenied || !slices.Equal(us.Paths, []string{agent}) {
		t.Fatalf("Restrict unix sockets = %+v, want denied mode with only the shared path", us)
	}
	same, err := Restrict(base, base)
	if err != nil {
		t.Fatal(err)
	}
	if same.Fingerprint() != base.Fingerprint() {
		t.Fatal("Restrict(p, p) changed the unix-socket authority")
	}
	// Neither input was mutated.
	if base.UnixSockets().Mode != UnixSocketsLocal || len(base.UnixSockets().Paths) != 2 {
		t.Fatal("Restrict mutated its base input")
	}
}

func TestDangerousUnixSocket(t *testing.T) {
	for _, path := range []string{
		"/run/user/1000/bus", "/var/run/user/1000/bus", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
		"/run/user/1000/systemd/private", "/run/systemd/private", "/run/systemd/notify",
		"/var/run/docker.sock", "/run/docker.sock", "/run/user/1000/podman/podman.sock", "/run/podman/podman.sock",
		"/tmp/.X11-unix/X0", "/run/user/1000/wayland-0",
		"/private/var/run/mDNSResponder", // darwin spelling of a system daemon is NOT dangerous; see below
	} {
		reason, dangerous := DangerousUnixSocket(path)
		if path == "/private/var/run/mDNSResponder" {
			if dangerous {
				t.Errorf("%s flagged dangerous: %s", path, reason)
			}
			continue
		}
		if !dangerous || reason == "" {
			t.Errorf("%s not flagged as a known broker socket", path)
		}
	}
	for _, path := range []string{"/tmp/agent.sock", "/home/u/.gnupg/S.gpg-agent", "/run/user/1000/keyring/ssh"} {
		if reason, dangerous := DangerousUnixSocket(path); dangerous {
			t.Errorf("%s wrongly flagged: %s", path, reason)
		}
	}
}
