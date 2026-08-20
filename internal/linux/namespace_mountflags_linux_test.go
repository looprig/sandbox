//go:build linux

package linux

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestMapLockedFlagsPreservesUserNamespaceLockedBits pins the translation the
// read-only remount depends on. A user namespace locks these flags on any
// mount it did not create, so a MS_REMOUNT that omits one is asking to clear
// it and is refused with EPERM -- how the Rung-1 mount view died on
// /etc/resolv.conf and surfaced as exit code 126.
func TestMapLockedFlagsPreservesUserNamespaceLockedBits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		statfs int64
		want   uintptr
	}{
		{name: "none", statfs: 0, want: 0},
		{name: "nosuid", statfs: unix.ST_NOSUID, want: unix.MS_NOSUID},
		{name: "nodev", statfs: unix.ST_NODEV, want: unix.MS_NODEV},
		{name: "noexec", statfs: unix.ST_NOEXEC, want: unix.MS_NOEXEC},
		{name: "noatime", statfs: unix.ST_NOATIME, want: unix.MS_NOATIME},
		{name: "nodiratime", statfs: unix.ST_NODIRATIME, want: unix.MS_NODIRATIME},
		{name: "relatime", statfs: unix.ST_RELATIME, want: unix.MS_RELATIME},
		{
			name:   "typical /etc bind",
			statfs: unix.ST_NOSUID | unix.ST_NODEV | unix.ST_RELATIME,
			want:   unix.MS_NOSUID | unix.MS_NODEV | unix.MS_RELATIME,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapLockedFlags(tc.statfs); got != tc.want {
				t.Fatalf("mapLockedFlags(%#x) = %#x, want %#x", tc.statfs, got, tc.want)
			}
		})
	}
}

// TestMapLockedFlagsIgnoresReadOnly guards against folding ST_RDONLY in: the
// remount sets MS_RDONLY itself, and a writable source must not be treated as
// carrying a locked read-only bit.
func TestMapLockedFlagsIgnoresReadOnly(t *testing.T) {
	if got := mapLockedFlags(unix.ST_RDONLY); got != 0 {
		t.Fatalf("mapLockedFlags(ST_RDONLY) = %#x, want 0", got)
	}
}
