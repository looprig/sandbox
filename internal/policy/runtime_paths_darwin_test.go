//go:build darwin

package policy

import "testing"

// TestMinimalRuntimeEntriesDarwinKeepsSystemLibrary pins Darwin's side of the
// per-OS split: the Seatbelt profile is generated from these entries, so the
// paths macOS CI already proves must not drift when Linux's list changes.
func TestMinimalRuntimeEntriesDarwinKeepsSystemLibrary(t *testing.T) {
	want := map[string]bool{"/System/Library": false, "/usr/lib": false, "/etc/ssl/cert.pem": false}
	for _, entry := range MinimalRuntimeEntries() {
		if _, tracked := want[entry.Path]; tracked {
			want[entry.Path] = true
		}
	}
	for path, seen := range want {
		if !seen {
			t.Errorf("Darwin runtime baseline is missing %q", path)
		}
	}
}
