//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	lsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// linuxCaps is the runtime capability snapshot the Linux backend selector reads
// while constructing an executor to pick the strongest achievable enforcement rung
// (SPEC §7.2). Every field is a MEASURED fact about THIS host, taken by an
// active probe (not assumed): a mechanism that cannot be confirmed is reported
// absent (false / 0 / ""), which is the fail-secure default — an over-reported
// capability would let the selector claim a rung the kernel will not enforce.
type linuxCaps struct {
	// landlockABI is the kernel's Landlock ABI version, or 0 when Landlock is
	// unavailable. Rung 1 needs >=1 (any FS rules); rung 2 needs >=4 (that is
	// where Landlock TCP port rules land, which rung 2's port allowlist uses).
	landlockABI int
	// seccomp reports whether SECCOMP_MODE_FILTER (classic-BPF filters) can be
	// installed — probed side-effect-free via SECCOMP_GET_ACTION_AVAIL, which
	// installs nothing. Both rungs apply a seccomp filter in the stage-2 child.
	seccomp bool
	// userns reports a USABLE unprivileged user namespace: one that can be
	// created AND grants effective privilege inside it (at least one of the
	// rung-1 capabilities — CAP_SYS_ADMIN for the mount view or CAP_NET_ADMIN
	// for the netns). A userns that CREATES but is stripped of effective
	// capabilities (Ubuntu's apparmor_restrict_unprivileged_userns=1) is
	// reported false, because it cannot support rung 1. It is exactly
	// (mountns || netns), so the invariants "netns implies userns" and
	// "mountns implies userns" hold by construction.
	userns bool
	// netns reports a net namespace created together with a userns in which
	// CAP_NET_ADMIN is EFFECTIVE (proven by bringing loopback up). This is what
	// rung 1 needs to run in-namespace nftables (SPEC §5.2). Implies userns.
	netns bool
	// mountns reports a mount namespace created together with a userns in which
	// CAP_SYS_ADMIN is EFFECTIVE (proven by a private recursive remount of /,
	// confined to the throwaway child's own mount namespace). This is what
	// rung 1 needs for its bind-mount view. Implies userns.
	mountns bool
	// cgroupV2 reports the cgroup v2 unified hierarchy is mounted (used by the
	// resource-limit backend, SPEC §7.4). Not part of the rung ladder.
	cgroupV2 bool
	// cgroupPids is the nearest writable cgroup ancestor that distributes the
	// pids controller to its children, or "" when none exists. A non-empty
	// value implies cgroupV2. Not part of the rung ladder.
	cgroupPids string
}

// rung is the OS-enforcement tier a Linux host can achieve (SPEC §7.2),
// strongest last so the numeric order matches strength.
type rung uint8

const (
	// rungNone means no usable OS enforcement mechanism -> LevelNone.
	rungNone rung = iota
	// rungTwo means Landlock (v4+) + seccomp with NO namespaces: FS by
	// enumerated allowlist and a TCP port allowlist, no address scoping.
	rungTwo
	// rungOne means namespaces (user+mount+net) + Landlock + seccomp: the full
	// ladder, including in-netns nftables address scoping and the mount view.
	rungOne
)

// selectRung picks the strongest achievable rung from a capability snapshot,
// per the SPEC §7.2 ladder. Rung 1 requires the three namespaces plus Landlock
// (any ABI >= 1, since it scopes network with nftables rather than Landlock TCP
// rules) plus seccomp. Rung 2 requires Landlock ABI >= 4 (TCP port rules) plus
// seccomp. Anything less is rungNone. It is fail-secure: a missing capability
// can only ever LOWER the rung.
func (c linuxCaps) selectRung() rung {
	switch {
	case c.userns && c.mountns && c.netns && c.landlockABI >= 1 && c.seccomp:
		return rungOne
	case c.landlockABI >= 4 && c.seccomp:
		return rungTwo
	default:
		return rungNone
	}
}

// probeLinuxCaps actively measures every capability the rung ladder depends on.
// It has NO lasting side effects on the calling process: the namespace probes
// run in throwaway forked children (see probeNamespaceCap), the seccomp probe
// only queries availability, and the Landlock/cgroup probes are read-only.
func probeLinuxCaps() linuxCaps {
	c := linuxCaps{
		landlockABI: probeLandlockABI(),
		seccomp:     probeSeccompFilter(),
		mountns:     probeNamespaceCap(nsProbeMount),
		netns:       probeNamespaceCap(nsProbeNet),
		cgroupV2:    probeCgroupV2Unified(),
		cgroupPids:  probeDelegatedPidsAncestor(),
	}
	// userns is the usable-userns rollup: a user namespace is only useful to
	// rung 1 if it grants at least one effective privilege. Deriving it from
	// the two capability probes guarantees the "netns/mountns implies userns"
	// invariants hold.
	c.userns = c.mountns || c.netns
	return c
}

// probeLandlockABI returns the kernel Landlock ABI version, or 0 when Landlock
// is unavailable. LandlockGetABIVersion is a pure query (no ruleset created).
func probeLandlockABI() int {
	abi, err := lsyscall.LandlockGetABIVersion()
	if err != nil || abi < 0 {
		return 0
	}
	return abi
}

// probeSeccompFilter reports whether SECCOMP_MODE_FILTER is usable, WITHOUT
// installing a filter. seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action) asks the
// kernel whether it recognizes a given filter return action; a zero errno means
// the seccomp filter machinery is present and usable. It is unprivileged and
// side-effect-free. (A pre-4.14 kernel lacks GET_ACTION_AVAIL and would report
// false even though filter mode exists — that under-reports, which is
// fail-secure, and is irrelevant on the modern kernels this ships against.)
func probeSeccompFilter() bool {
	action := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_GET_ACTION_AVAIL),
		0,
		uintptr(unsafe.Pointer(&action)),
	)
	return errno == 0
}

// probeSentinelEnv is the reserved environment variable that flags a re-exec'd
// throwaway namespace-probe child. Init() (init_linux.go) dispatches on it before
// the normal program runs; no other code path sets it, so a normal harness process
// (where it is unset) is entirely unaffected.
const probeSentinelEnv = "LRSANDBOX_PROBE_NS"

// The two capability probes carried in probeSentinelEnv.
const (
	nsProbeMount = "mount" // CAP_SYS_ADMIN via a private remount inside a new mount ns
	nsProbeNet   = "net"   // CAP_NET_ADMIN via bringing loopback up inside a new net ns
)

// probeCapEffectiveCode is the DISTINCTIVE exit code a namespace-probe child uses
// to report "the probed capability is effective". It is deliberately NOT 0:
// probeNamespaceCap must distinguish a genuinely-dispatched probe child from a
// process that never dispatched (Init not called -> the re-exec'd child fell
// through to run its normal main() and happened to exit 0). Reading exit 0 as
// "effective" would be a fail-OPEN — an over-claimed rung the kernel will not
// enforce. Only this exact code counts as success; everything else (including 0)
// reads as "absent" (fail-secure). 66 is arbitrary, outside the common
// 0/1/2/126/127 range.
const probeCapEffectiveCode = 66

// probeChildTimeout bounds a throwaway probe child. The child does one syscall
// and exits, so this is only a guard against a wedged fork; it is never the
// happy path.
const probeChildTimeout = 5 * time.Second

// runNamespaceProbeChild runs inside the throwaway child, already placed in the
// new namespaces (and mapped to root within its user namespace) by the parent's
// SysProcAttr. It attempts the single capability-requiring operation for mode and
// returns a process exit code: probeCapEffectiveCode means the capability is
// EFFECTIVE; any other code means it was denied (EPERM/EACCES under
// apparmor_restrict_unprivileged_userns) or the operation otherwise failed. The
// success code is distinctive (not 0) so a non-dispatching child cannot be misread
// as success (see probeCapEffectiveCode). Every mutation is confined to this
// child's own namespaces, which vanish when it exits — the parent is never touched.
func runNamespaceProbeChild(mode string) int {
	switch mode {
	case nsProbeMount:
		// A recursive private remount of / needs CAP_SYS_ADMIN and is confined
		// to this child's own (unshared) mount namespace: nothing the parent or
		// host can observe.
		if err := unix.Mount("none", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			return 1
		}
		return probeCapEffectiveCode
	case nsProbeNet:
		if err := bringLoopbackUp(); err != nil {
			return 1
		}
		return probeCapEffectiveCode
	default:
		return 2
	}
}

// bringLoopbackUp sets the loopback interface UP inside the child's own network
// namespace — a CAP_NET_ADMIN operation. In a fresh netns lo starts DOWN, so
// SIOCSIFFLAGS here exercises the capability rung 1 needs for in-netns nftables.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// probeNamespaceCap answers, side-effect-free, whether THIS host can create an
// unprivileged user namespace (plus the mode's companion namespace) in which
// the corresponding capability is EFFECTIVE.
//
// It is deliberately NOT done in-process: calling unshare(CLONE_NEWUSER) on the
// probe's own thread would move the harness into a new namespace (or, on a
// partial failure, corrupt that thread's state). Instead it re-execs
// /proc/self/exe with SysProcAttr.Cloneflags + uid/gid maps, so the kernel
// forks a fresh child directly into the new namespaces; that child's Init()
// (init_linux.go) runs one capability op and exits. The child's namespaces are
// entirely its own and are torn down when it exits, so the parent's namespaces,
// mounts and network are untouched no matter the outcome. The capability is
// effective ONLY when the child exits with the distinctive probeCapEffectiveCode
// (entered the namespaces AND the op succeeded); every other outcome is read as
// absent (fail-secure) — see the exit-code check below.
func probeNamespaceCap(mode string) bool {
	var companion uintptr
	switch mode {
	case nsProbeMount:
		companion = unix.CLONE_NEWNS
	case nsProbeNet:
		companion = unix.CLONE_NEWNET
	default:
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeChildTimeout)
	defer cancel()

	// /proc/self/exe re-execs this exact binary; on a deleted binary the kernel
	// still resolves it, which os.Executable would not.
	cmd := exec.CommandContext(ctx, "/proc/self/exe")
	cmd.Env = append(os.Environ(), probeSentinelEnv+"="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | companion,
		// Map the caller's uid/gid to root inside the new user namespace so the
		// child holds (subject to host policy) the capabilities being probed.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// GidMappingsEnableSetgroups defaults to false, so Go writes "deny" to
		// /proc/<pid>/setgroups before gid_map — required for an unprivileged map.
	}
	// Discard the child's stdio; the result is carried solely by the exit code.
	cmd.Stdout = nil
	cmd.Stderr = nil

	// The capability is effective ONLY if the child exited with the distinctive
	// probeCapEffectiveCode. A nil error (exit 0) is NOT treated as success: a
	// child that never dispatched (Init not called, so it fell through to its
	// normal main() and exited 0) must not be misread as "capability present" —
	// that would be a fail-OPEN over-claim of the rung. Any error, any other exit
	// code, a signal, or the context timeout all read as "absent" (fail-secure).
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode() == probeCapEffectiveCode
	}
	return false
}

// cgroupMountRoot is the well-known cgroup v2 unified mount point.
const cgroupMountRoot = "/sys/fs/cgroup"

// probeCgroupV2Unified reports whether the cgroup v2 unified hierarchy is
// mounted, detected by the presence of its root cgroup.controllers file (absent
// under cgroup v1 or a hybrid layout).
func probeCgroupV2Unified() bool {
	_, err := os.Stat(filepath.Join(cgroupMountRoot, "cgroup.controllers"))
	return err == nil
}

// probeDelegatedPidsAncestor returns the nearest ancestor of this process's own
// cgroup that is BOTH writable AND distributes the pids controller to its
// children (so a fresh child cgroup created there immediately has a working
// pids.max), or "" when no such ancestor exists. It walks up from the unified
// ("0::") cgroup of /proc/self/cgroup, never escaping the mount root.
func probeDelegatedPidsAncestor() string {
	if !probeCgroupV2Unified() {
		return ""
	}
	selfDir, ok := selfCgroupDir()
	if !ok {
		return ""
	}
	for cur := selfDir; ; {
		if unix.Access(cur, unix.W_OK) == nil && subtreeHasPids(cur) {
			return cur
		}
		if cur == cgroupMountRoot {
			return ""
		}
		parent := filepath.Dir(cur)
		// Guard against escaping the mount root (defence-in-depth on the path).
		if len(parent) < len(cgroupMountRoot) || !strings.HasPrefix(parent, cgroupMountRoot) {
			return ""
		}
		cur = parent
	}
}

// selfCgroupDir resolves the absolute directory of this process's own cgroup v2
// node from the unified ("0::") line of /proc/self/cgroup. The relative path is
// cleaned and re-anchored under the mount root so a crafted cgroup path cannot
// escape it.
func selfCgroupDir() (string, bool) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		rel, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok {
			continue
		}
		return filepath.Join(cgroupMountRoot, filepath.Clean("/"+rel)), true
	}
	return "", false
}

// subtreeHasPids reports whether dir distributes the pids controller to its
// children via cgroup.subtree_control.
func subtreeHasPids(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == "pids" {
			return true
		}
	}
	return false
}
