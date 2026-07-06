//go:build linux

package sandbox

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file builds and installs the rung-2 seccomp-BPF filter in the stage-2
// child, AFTER Landlock (applyLandlockRules) and BEFORE chdir/execve (SPEC
// §7.2, Task 12b). The filter is a hand-built classic-BPF program — pure Go, NO
// cgo, NO libseccomp — installed via PR_SET_SECCOMP (SECCOMP_MODE_FILTER). It
// and PR_SET_NO_NEW_PRIVS are INHERITED across the execve into the target, so a
// rung-2 spawn's target additionally runs with the dangerous syscalls below
// soft-denied. The construction mirrors the proven Task M3 spike
// (docs/spikes/seccomp-reexec.md): arch guard FIRST, then a MANDATORY x32 guard,
// then the nr/arg policy checks, then allow-default.
//
// What the filter denies (all EACCES, all arch- and x32-guarded):
//
//   - UDP sockets: socket(AF_INET|AF_INET6, SOCK_DGRAM, *). Rung 2's network
//     boundary is a TCP-port allowlist (Landlock, Task 12c); UDP has no address
//     scoping so it is denied. DNS is forced over TCP (RES_OPTIONS=use-vc, 12c),
//     so denying UDP does not break resolution.
//   - IPPROTO_MPTCP (protocol 262): socket(AF_INET|AF_INET6, SOCK_STREAM, 262).
//     LOAD-BEARING: Landlock's TCP ConnectTCP/BindTCP port rules (12c) do NOT
//     cover Multipath TCP, and Go 1.24+ defaults net.Dial/net.Listen to MPTCP —
//     so without this block a confined child bypasses the port allowlist.
//   - ptrace: prevents debugging-based escapes / inspection of other processes.
//   - io_uring (setup/enter/register): io_uring can dispatch operations that
//     bypass syscall-based filtering — a well-known seccomp-evasion surface.
//
// Everything else is ALLOWED: the target and the Go runtime must run.
//
// Ordering vs Landlock. Landlock is applied first, seccomp second. Both survive
// execve, so the order does not change the confinement the target inherits;
// seccomp is placed last (immediately before chdir/execve) so the filter thread
// is the execve thread with no intervening work that could migrate the goroutine
// (see installSeccompFilter's runtime.LockOSThread).

// seccomp_data field byte offsets (see <linux/seccomp.h>). On little-endian
// x86_64 the low 32 bits of a u64 arg live at the arg's base offset, so a single
// BPF_W|BPF_ABS load at the base offset yields the low word we compare. The args
// array starts at offset 16, each entry 8 bytes wide.
const (
	seccompOffNR   = 0  // int    nr
	seccompOffArch = 4  // __u32  arch
	seccompOffArg0 = 16 // __u64  args[0] — socket domain   (low word @16)
	seccompOffArg1 = 24 // __u64  args[1] — socket type     (low word @24)
	seccompOffArg2 = 32 // __u64  args[2] — socket protocol (low word @32)
)

// seccompSockTypeMask strips SOCK_CLOEXEC / SOCK_NONBLOCK (and any future) flags
// that callers OR into the socket() `type` argument, leaving just the base type.
// Go's net stack always sets SOCK_CLOEXEC|SOCK_NONBLOCK, so a filter comparing
// `type` raw against SOCK_DGRAM would never match and fail open.
const seccompSockTypeMask = 0xff

// seccompX32SyscallBit is __X32_SYSCALL_BIT. The x32 ABI shares
// AUDIT_ARCH_X86_64 with native x86_64 (so it passes the arch guard), but its
// syscall numbers are OR'd with this bit — an x32 socket() has nr = 41|0x40000000,
// which would NOT match SYS_socket and would fall through to ALLOW: a silent
// bypass of every nr-based rule. Any syscall carrying this bit is killed
// (fail-closed) right after the arch guard. (The arch guard alone stops i386,
// which uses a DIFFERENT arch value; it does NOT stop x32.)
const seccompX32SyscallBit = 0x40000000

// ipprotoMPTCP is IPPROTO_MPTCP (protocol 262). Named locally so the filter reads
// clearly; it equals unix.IPPROTO_MPTCP.
const ipprotoMPTCP = unix.IPPROTO_MPTCP

// buildSeccompFilter builds the rung-2 classic-BPF program as a []unix.SockFilter.
// See the annotated instruction listing inline. Structure:
//
//	arch guard  -> KILL_PROCESS on mismatch (stops i386 — a different arch value)
//	x32 guard   -> KILL_PROCESS if nr carries __X32_SYSCALL_BIT (x32 shares the
//	               x86_64 arch value, so the arch guard alone does NOT stop it)
//	ptrace / io_uring{setup,enter,register} -> ERRNO(EACCES)
//	nr != socket -> ALLOW
//	domain != AF_INET && != AF_INET6 -> ALLOW
//	(type & 0xff) == SOCK_DGRAM -> ERRNO(EACCES)          (UDP)
//	protocol == IPPROTO_MPTCP    -> ERRNO(EACCES)          (Multipath TCP)
//	else -> ALLOW                                          (e.g. plain TCP)
func buildSeccompFilter() []unix.SockFilter {
	const (
		retKill  = unix.SECCOMP_RET_KILL_PROCESS
		retAllow = unix.SECCOMP_RET_ALLOW
		retErrno = unix.SECCOMP_RET_ERRNO | (uint32(unix.EACCES) & unix.SECCOMP_RET_DATA)
	)
	return []unix.SockFilter{
		// --- arch guard ---------------------------------------------------------
		// [0] A = seccomp_data.arch
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArch),
		// [1] if A == AUDIT_ARCH_X86_64 -> skip the kill, else fall to [2]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AUDIT_ARCH_X86_64, 1, 0),
		// [2] arch mismatch (e.g. i386): kill the whole process (fail-closed)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retKill),

		// --- x32 guard ----------------------------------------------------------
		// [3] A = seccomp_data.nr
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffNR),
		// [4] if (A & __X32_SYSCALL_BIT) != 0 -> fall to [5] kill, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, seccompX32SyscallBit, 0, 1),
		// [5] x32 syscall: kill (shares the x86_64 arch value but its nr would dodge
		//     the nr compares below and fall through to ALLOW)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retKill),

		// A still holds nr (loaded at [3]) for the nr-only denials below.
		// --- ptrace -------------------------------------------------------------
		// [6] if A == SYS_ptrace -> fall to [7] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_PTRACE, 0, 1),
		// [7] ptrace: deny with EACCES
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- io_uring_setup -----------------------------------------------------
		// [8] if A == SYS_io_uring_setup -> fall to [9] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_IO_URING_SETUP, 0, 1),
		// [9] io_uring_setup: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- io_uring_enter -----------------------------------------------------
		// [10] if A == SYS_io_uring_enter -> fall to [11] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_IO_URING_ENTER, 0, 1),
		// [11] io_uring_enter: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- io_uring_register --------------------------------------------------
		// [12] if A == SYS_io_uring_register -> fall to [13] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_IO_URING_REGISTER, 0, 1),
		// [13] io_uring_register: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- socket(): arg-scoped UDP / MPTCP denial ----------------------------
		// [14] if A == SYS_socket -> proceed to the domain load, else allow at [15]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SOCKET, 1, 0),
		// [15] not socket(): allow (the Go runtime needs its other syscalls)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [16] A = args[0] low word (socket domain)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg0),
		// [17] if A == AF_INET  -> jump +2 to the type load [20]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET, 2, 0),
		// [18] if A == AF_INET6 -> jump +1 to the type load [20], else fall to [19]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET6, 1, 0),
		// [19] non-inet socket (e.g. AF_UNIX): allow
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [20] A = args[1] low word (socket type, may carry SOCK_CLOEXEC/NONBLOCK)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg1),
		// [21] A = A & 0xff  (strip the flag bits, keep the base type)
		seccompStmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, seccompSockTypeMask),
		// [22] if A == SOCK_DGRAM -> fall to [23] deny (UDP), else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_DGRAM), 0, 1),
		// [23] AF_INET* UDP: deny with EACCES
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [24] A = args[2] low word (socket protocol)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg2),
		// [25] if A == IPPROTO_MPTCP -> fall to [26] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(ipprotoMPTCP), 0, 1),
		// [26] AF_INET* MPTCP: deny with EACCES (closes the port-allowlist bypass)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [27] AF_INET* stream/other, not MPTCP (e.g. plain TCP): allow — the
		//      positive control proving the socket denials are arg-scoped, not a
		//      blanket socket() ban.
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
	}
}

// seccompStmt builds a non-branching BPF instruction (jt/jf = 0).
func seccompStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// seccompJump builds a conditional BPF instruction. jt/jf are relative
// instruction skips taken when the comparison is true / false.
func seccompJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// seccompError is the typed, fail-closed failure of the stage-2 seccomp install
// (SPEC §7.2). It names the failing step (PR_SET_NO_NEW_PRIVS or PR_SET_SECCOMP)
// and wraps the underlying errno for errors.As/Unwrap. runStage2 surfaces it as a
// stage2Error{Op:"seccomp"} so the child fails closed rather than running the
// target unconfined.
type seccompError struct {
	Op  string // the failing step, e.g. "PR_SET_NO_NEW_PRIVS", "PR_SET_SECCOMP"
	Err error  // the wrapped underlying error (typically a syscall.Errno)
}

func (e *seccompError) Error() string { return "sandbox: seccomp: " + e.Op + ": " + e.Err.Error() }
func (e *seccompError) Unwrap() error { return e.Err }

// installSeccompFilter installs the rung-2 filter on the CURRENT OS thread and
// leaves that thread pinned so the caller's subsequent syscall.Exec runs on it.
//
// PR_SET_SECCOMP and PR_SET_NO_NEW_PRIVS are PER-THREAD, so the thread that
// installs the filter MUST be the thread that execve's — otherwise the target
// could run on a sibling thread that never got the filter. runtime.LockOSThread
// pins this goroutine to its thread and is deliberately NEVER unlocked: the
// stage-2 child does install -> chdir -> execve on this one goroutine, so the
// pinned thread is the execve thread, and execve collapses the process to that
// single filtered thread. Every thread the target later spawns inherits the
// filter (seccomp filters propagate across clone), so the whole target is
// confined. (Landlock (12a) already restricts all threads via psx and sets
// no_new_privs; PR_SET_NO_NEW_PRIVS is set again here, idempotently, so the
// SET_MODE_FILTER install can never EACCES on the precondition.)
//
// golang.org/x/sys v0.40.0 exposes no unix.Seccomp wrapper, so the install uses
// the classic PR_SET_SECCOMP / SECCOMP_MODE_FILTER path via unix.Syscall. The
// uintptr(unsafe.Pointer(&prog)) conversion is passed directly as a unix.Syscall
// argument — the vet-recognized idiom that keeps prog (and its backing filter
// slice) live across the call; runtime.KeepAlive is belt-and-braces.
func installSeccompFilter() error {
	runtime.LockOSThread() // pin: this thread installs AND execve's; never unlocked.

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return &seccompError{Op: "PR_SET_NO_NEW_PRIVS", Err: err}
	}

	filter := buildSeccompFilter()
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
		return &seccompError{Op: "PR_SET_SECCOMP", Err: errno}
	}
	return nil
}
