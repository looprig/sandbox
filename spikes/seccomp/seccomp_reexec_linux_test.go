//go:build linux

// Package seccompspike is a THROWAWAY Phase 0.5 spike (Task M3). It proves that
// a hand-built (pure-Go, NO cgo, NO libseccomp) seccomp-BPF filter — installed
// in a re-exec'd stage-2 child after PR_SET_NO_NEW_PRIVS — denies a marker
// syscall (UDP/IPv4 socket() ) in the CHILD only, and that the denial SURVIVES
// execve into the target. seccomp filters and no_new_privs are inherited across
// execve, which is exactly what the real rung-2 seccomp backend (Task 12b)
// relies on: stage-2 installs the filter, then execve's the target, and the
// target runs confined.
//
// The filter is arg-scoped, not a blanket socket() ban: it denies
// socket(AF_INET, SOCK_DGRAM) (UDP) while ALLOWING socket(AF_INET, SOCK_STREAM)
// (TCP). The TCP-allowed positive control is the anti-fail-open proof — a
// blanket deny (or a no-op filter) would fail the TCP=OK assertion.
//
// It is NOT shipped code. It lives in its own package, isolated from the root
// `package sandbox`, and runs only as a capability-gated test.
package seccompspike

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Sentinel env vars driving the two re-exec hops. The parent sets envStage2 to
// launch the stage-2 child; the stage-2 child installs the seccomp filter and
// then execve's the TARGET (envTarget) — a fresh program image that runs the
// probes. A passing UDP=EACCES in the target therefore proves the filter
// SURVIVED the second execve, not merely that it applied in the stage-2 process.
const (
	envStage2 = "LRSANDBOX_SECCOMP_STAGE2"
	envTarget = "LRSANDBOX_SECCOMP_TARGET"
)

// Marker keys the target prints (one "KEY=VALUE" line each) and the parent
// parses. Shared constants stop the two halves from drifting.
const (
	keyApply = "APPLY" // reached target => filter applied AND survived execve
	keyUDP   = "UDP"   // socket(AF_INET, SOCK_DGRAM) outcome (marker: denied)
	keyTCP   = "TCP"   // socket(AF_INET, SOCK_STREAM) outcome (positive control)
	keyNNP   = "NNP"   // PR_GET_NO_NEW_PRIVS value after execve
)

// Probe outcome values.
const (
	valOK     = "OK"
	valEACCES = "EACCES"
	valNNPSet = "1"
)

// Child exit codes.
const (
	exitNNPErr    = 2 // PR_SET_NO_NEW_PRIVS failed
	exitFilterErr = 3 // seccomp filter install failed
	exitExecErr   = 4 // execve into the target failed after the filter applied
)

// sockTypeMask strips SOCK_CLOEXEC / SOCK_NONBLOCK (and any future) flags that
// callers OR into the socket() `type` argument, leaving just the base type.
// Go's net stack, for one, always sets SOCK_CLOEXEC|SOCK_NONBLOCK — so a filter
// that compared `type` raw against SOCK_DGRAM would never match and fail open.
const sockTypeMask = 0xff

// seccomp_data field byte offsets (see <linux/seccomp.h>). On little-endian
// x86_64 the low 32 bits of a u64 arg live at the arg's base offset, so a single
// BPF_W|BPF_ABS load at the base offset yields the low word we compare.
const (
	offNR   = 0  // int    nr
	offArch = 4  // __u32  arch
	offArg0 = 16 // __u64  args[0]  (socket domain) — low word at offset 16
	offArg1 = 24 // __u64  args[1]  (socket type)   — low word at offset 24
)

// x32SyscallBit is __X32_SYSCALL_BIT. The x32 ABI shares AUDIT_ARCH_X86_64 with
// native x86_64 (so it passes the arch guard), but its syscall numbers are OR'd
// with this bit — an x32 socket() has nr = 41|0x40000000, which would NOT match
// SYS_socket and would fall through to ALLOW: a silent bypass of an nr-based
// filter. We reject any syscall carrying this bit (fail-closed) right after the
// arch guard. (The arch guard alone stops i386, which uses a *different* arch
// value; it does NOT stop x32.)
const x32SyscallBit = 0x40000000

// udpDenyFilter builds the classic-BPF program as a []unix.SockFilter. See the
// annotated instruction listing inline. Structure:
//
//	arch guard  -> KILL_PROCESS on mismatch (stops i386 — a different arch value)
//	x32 guard   -> KILL_PROCESS if nr carries __X32_SYSCALL_BIT (x32 shares the
//	               x86_64 arch value, so the arch guard alone does NOT stop it)
//	nr != socket -> ALLOW (don't over-restrict the Go runtime)
//	domain != AF_INET -> ALLOW
//	(type & 0xff) == SOCK_DGRAM -> ERRNO(EACCES)  else ALLOW
func udpDenyFilter() []unix.SockFilter {
	const (
		retKill  = unix.SECCOMP_RET_KILL_PROCESS
		retAllow = unix.SECCOMP_RET_ALLOW
		retErrno = unix.SECCOMP_RET_ERRNO | (uint32(unix.EACCES) & unix.SECCOMP_RET_DATA)
	)
	return []unix.SockFilter{
		// [0] A = seccomp_data.arch
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArch),
		// [1] if A == AUDIT_ARCH_X86_64 -> [3], else fall to [2]
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AUDIT_ARCH_X86_64, 1, 0),
		// [2] arch mismatch (e.g. i386): kill the whole process (fail-closed)
		stmt(unix.BPF_RET|unix.BPF_K, retKill),
		// [3] A = seccomp_data.nr
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offNR),
		// [4] if (A & __X32_SYSCALL_BIT) != 0 -> [5] kill, else fall through to [6]
		jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, x32SyscallBit, 0, 1),
		// [5] x32 syscall: kill (it shares the x86_64 arch value but its nr would
		//     dodge the SYS_socket compare below and fall through to ALLOW)
		stmt(unix.BPF_RET|unix.BPF_K, retKill),
		// [6] if A == SYS_socket -> [8], else fall to [7]
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SOCKET, 1, 0),
		// [7] not socket(): allow (the Go runtime needs its other syscalls)
		stmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [8] A = args[0] low word (socket domain)
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArg0),
		// [9] if A == AF_INET -> [11], else fall to [10]
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET, 1, 0),
		// [10] non-AF_INET socket: allow
		stmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [11] A = args[1] low word (socket type, incl. SOCK_CLOEXEC/NONBLOCK)
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArg1),
		// [12] A = A & 0xff  (strip the flag bits, keep the base type)
		stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, sockTypeMask),
		// [13] if A == SOCK_DGRAM -> [15] (deny), else fall to [14]
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_DGRAM), 1, 0),
		// [14] AF_INET but not UDP (e.g. TCP): allow — proves arg-scoping
		stmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [15] AF_INET UDP: deny cleanly with EACCES (target sees syscall.EACCES)
		stmt(unix.BPF_RET|unix.BPF_K, retErrno),
	}
}

// stmt builds a non-branching BPF instruction (jt/jf = 0).
func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// jump builds a conditional BPF instruction. jt/jf are relative instruction
// skips taken when the comparison is true / false.
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// installSeccompFilter sets PR_SET_NO_NEW_PRIVS (mandatory without
// CAP_SYS_ADMIN — otherwise SET_MODE_FILTER returns EACCES) and then installs
// the classic-BPF program via PR_SET_SECCOMP (SECCOMP_MODE_FILTER). x/sys
// v0.40.0 exposes no unix.Seccomp wrapper, so PR_SET_SECCOMP is the pure-Go,
// cgo-free install path; it is per-thread, which is why the caller locks the OS
// thread and execve's on that same thread.
//
// The uintptr(unsafe.Pointer(&prog)) conversion is passed directly as a
// unix.Syscall argument — the vet-recognized idiom that keeps prog (and the
// backing filter slice) live across the syscall.
func installSeccompFilter(filter []unix.SockFilter) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_, _, errno := unix.Syscall(
		unix.SYS_PRCTL,
		uintptr(unix.PR_SET_SECCOMP),
		uintptr(unix.SECCOMP_MODE_FILTER),
		uintptr(unsafe.Pointer(&prog)),
	)
	runtime.KeepAlive(&prog)
	if errno != 0 {
		return fmt.Errorf("PR_SET_SECCOMP: %w", errno)
	}
	return nil
}

// TestMain multiplexes the two re-exec hops. envTarget is checked FIRST: the
// post-execve target runs the probes. envStage2 next: the stage-2 child installs
// the filter and execve's the target. Neither set: run the normal suite.
func TestMain(m *testing.M) {
	if os.Getenv(envTarget) != "" {
		os.Exit(runTarget())
	}
	if os.Getenv(envStage2) != "" {
		os.Exit(runStage2Child())
	}
	os.Exit(m.Run())
}

// runStage2Child installs the seccomp filter on a locked OS thread and then
// execve's the target (a fresh image of this test binary in envTarget mode) on
// that same thread. Locking is required because PR_SET_SECCOMP and
// PR_SET_NO_NEW_PRIVS are per-thread: the thread that installs the filter must
// be the thread that calls execve, so the new image inherits it. It does NOT
// run the probes — the whole point is that the probes run AFTER a second
// execve, proving the filter survives execve into the target. On success this
// never returns; it returns only on a setup/exec failure.
func runStage2Child() int {
	runtime.LockOSThread()
	if err := installSeccompFilter(udpDenyFilter()); err != nil {
		if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "NO_NEW_PRIVS") {
			fmt.Printf("%s=ERR:nnp:%v\n", keyApply, err)
			return exitNNPErr
		}
		fmt.Printf("%s=ERR:filter:%v\n", keyApply, err)
		return exitFilterErr
	}
	env := append(os.Environ(), envTarget+"=1")
	if err := syscall.Exec(os.Args[0], []string{os.Args[0]}, env); err != nil {
		fmt.Printf("%s=ERR:exec:%v\n", keyApply, err)
		return exitExecErr
	}
	return 0 // unreachable: Exec replaced the process image on success
}

// runTarget is the post-execve target: it runs under the seccomp filter
// INHERITED across the stage-2 execve. Reaching here at all proves the filter
// applied AND execve of a fresh image succeeded under it, so it emits APPLY=OK
// and then runs the three probes as a table.
func runTarget() int {
	fmt.Printf("%s=%s\n", keyApply, valOK)
	probes := []struct {
		key    string
		result string
	}{
		{keyUDP, classifySocket(unix.AF_INET, unix.SOCK_DGRAM)},
		{keyTCP, classifySocket(unix.AF_INET, unix.SOCK_STREAM)},
		{keyNNP, classifyNoNewPrivs()},
	}
	for _, p := range probes {
		fmt.Printf("%s=%s\n", p.key, p.result)
	}
	return 0
}

// classifySocket attempts socket(domain, typ, 0) and reports the outcome as a
// marker value: valOK (and closes the fd), valEACCES, or "ERR:<detail>".
func classifySocket(domain, typ int) string {
	fd, err := unix.Socket(domain, typ, 0)
	if err == nil {
		if cerr := unix.Close(fd); cerr != nil {
			return "ERR:close:" + cerr.Error()
		}
		return valOK
	}
	if errors.Is(err, syscall.EACCES) {
		return valEACCES
	}
	return "ERR:" + err.Error()
}

// classifyNoNewPrivs reads PR_GET_NO_NEW_PRIVS and reports "1" if set. It proves
// the security precondition (no_new_privs) held across the execve.
func classifyNoNewPrivs() string {
	v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return "ERR:" + err.Error()
	}
	if v == 1 {
		return valNNPSet
	}
	return fmt.Sprintf("ERR:nnp=%d", v)
}

// parseMarkers turns the target's "KEY=VALUE" lines into a map.
func parseMarkers(out []byte) map[string]string {
	markers := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		markers[key] = val
	}
	return markers
}

// TestSeccompReexecUDPDeny drives the full backend-shaped flow: the parent
// re-execs the test binary as a stage-2 child, the stage-2 child installs the
// hand-built seccomp filter (after PR_SET_NO_NEW_PRIVS) and execve's the TARGET,
// and the target runs the probes under the filter inherited across that execve.
// It then makes the 4-way anti-fail-open assertion:
//
//	(1) target UDP socket denied with EACCES (marker survived execve),
//	(2) target TCP socket still succeeds (deny is arg-scoped, not blanket),
//	(3) no_new_privs is set in the target (precondition held across execve),
//	(4) the PARENT (never seccomp'd) can still open a UDP socket
//	    (confinement is child-local and did not leak).
func TestSeccompReexecUDPDeny(t *testing.T) {
	// Capability gate: confirm this kernel accepts a seccomp filter after
	// no_new_privs. A probe subprocess would be heavier; instead we rely on the
	// host facts (kernel 6.8, seccomp on) and let the stage-2 child surface any
	// install failure as a non-zero exit with an APPLY=ERR marker, which the
	// t.Fatalf below reports verbatim. This host runs the spike (no skip).

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), envStage2+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stage-2 child exited non-zero: %v\nchild output:\n%s", err, out)
	}
	got := parseMarkers(out)

	childChecks := []struct {
		name string
		key  string
		want string
	}{
		{"filter applied and survived execve into target", keyApply, valOK},
		{"target UDP socket denied with EACCES", keyUDP, valEACCES},
		{"target TCP socket still allowed (deny is arg-scoped)", keyTCP, valOK},
		{"no_new_privs set in target (precondition held across execve)", keyNNP, valNNPSet},
	}
	for _, tt := range childChecks {
		t.Run(tt.name, func(t *testing.T) {
			if got[tt.key] != tt.want {
				t.Errorf("child %s = %q, want %q\nfull child output:\n%s", tt.key, got[tt.key], tt.want, out)
			}
		})
	}

	// Assertion 4: the parent (this process) was never confined.
	t.Run("parent UDP socket unaffected (child-local)", func(t *testing.T) {
		fd, werr := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if werr != nil {
			t.Fatalf("parent UDP socket failed (confinement leaked into parent): %v", werr)
		}
		if cerr := unix.Close(fd); cerr != nil {
			t.Errorf("close parent fd: %v", cerr)
		}
	})
}
