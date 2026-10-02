//go:build linux

package linux

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// This file builds and installs the Seccomp-BPF filter in the stage-2 child of
// BOTH rungs, AFTER Landlock (applyLandlockRules) and BEFORE chdir/execve (SPEC
// §7.2, Task 12b). The filter is a hand-built classic-BPF program — pure Go, NO
// cgo, NO libseccomp — installed via PR_SET_SECCOMP (SECCOMP_MODE_FILTER). It
// and PR_SET_NO_NEW_PRIVS are INHERITED across the execve into the target, so
// a confined target additionally runs with the syscalls below soft-denied. The
// construction mirrors the proven Task M3 spike (docs/spikes/Seccomp-reexec.md):
// arch guard FIRST, then a MANDATORY x32 guard, then the nr/arg policy checks,
// then allow-default for every syscall that is not socket().
//
// What the filter denies (all EACCES, all arch- and x32-guarded):
//
//   - socket() is an ALLOWLIST, not a denylist (review C2/H1). Only these
//     creations are allowed:
//     AF_INET/AF_INET6 with base type SOCK_STREAM and protocol 0 or
//     IPPROTO_TCP — the only egress Landlock's TCP port rules (Rung 2, Task
//     12c) and nftables (Rung 1) both mediate;
//     AF_NETLINK with protocol 0 (NETLINK_ROUTE) and base type SOCK_RAW or
//     SOCK_DGRAM — glibc's getaddrinfo enumerates local addresses over it, and
//     it carries no egress;
//     AF_INET/AF_INET6 SOCK_DGRAM with protocol 0 or IPPROTO_UDP ONLY when the
//     filter is built with SeccompPolicy.AllowUDP (below).
//     Everything else is refused, including:
//     AF_UNIX — Landlock (≤ ABI 8) does not mediate a pathname or abstract
//     connect(), and Rung 2 has no mount namespace, so a same-user socket
//     (the D-Bus session bus at /run/user/$UID/bus, the systemd user manager,
//     ssh/gpg agents, docker.sock, abstract X11) would let `systemd-run --user`
//     or a raw StartTransientUnit launch a command outside every confinement
//     layer. socketpair() is a different syscall and stays ALLOWED: the
//     anonymous connected pair Go, Node and Chromium use for in-process IPC
//     reaches nothing outside the sandbox;
//     IPPROTO_MPTCP (262) and IPPROTO_SCTP / IPPROTO_SMC streams, AF_SMC,
//     AF_VSOCK, AF_RDS, AF_PACKET, raw and ICMP sockets — each an egress path
//     Landlock's TCP port rules do not cover. (MPTCP is load-bearing: Go 1.24+
//     defaults net.Dial/net.Listen to MPTCP.)
//   - UDP unless SeccompPolicy.AllowUDP. UDP has no Landlock address or port
//     scoping, so a Rung-2 spawn whose network is Confined refuses it; DNS is
//     then forced over TCP (RES_OPTIONS=use-vc, 12c). A spawn whose network is
//     Open (Net.Open) allows it — otherwise glibc's UDP-first resolver, and
//     every other UDP client, fails under `Network: Allow` (review H2) — and
//     Rung 1 always allows it, because its in-Netns nftables filter scopes UDP
//     (dropped except DNS, SPEC §6.1).
//   - ptrace: prevents debugging-based escapes / inspection of other processes.
//   - io_uring (setup/enter/register): io_uring can dispatch operations that
//     bypass syscall-based filtering — a well-known Seccomp-evasion surface.
//   - keyctl / add_key / request_key: Rung 2 has no user namespace, so the
//     target would otherwise read and use the invoking user's keyrings.
//
// Everything else is ALLOWED: the target and the Go runtime must run.
//
// COMPATIBILITY CONSEQUENCE, by design: a confined program that needs a
// pathname or abstract AF_UNIX CLIENT (or server) socket fails with EACCES —
// D-Bus clients, X11 clients, ssh-agent / gpg-agent, the docker CLI, syslog /
// journald writers, and Python multiprocessing's forkserver start method
// (which listens on an AF_UNIX socket; the fork and spawn methods use pipes
// and are unaffected). Such programs need an unconfined executor; the sandbox
// will not reopen same-user IPC that it cannot scope.
//
// Ordering vs Landlock. Landlock is applied first, Seccomp second. Both survive
// execve, so the order does not change the confinement the target inherits;
// Seccomp is placed last (immediately before chdir/execve) so the filter thread
// is the execve thread with no intervening work that could migrate the goroutine
// (see installSeccompFilter's runtime.LockOSThread). The Rung-1 nftables setup,
// which needs its own netlink socket, runs before both.

// seccomp_data field byte offsets (see <linux/Seccomp.h>). On little-endian
// x86_64 the low 32 bits of a u64 arg live at the arg's base offset, so a single
// BPF_W|BPF_ABS load at the base offset yields the low word we compare. The args
// array starts at offset 16, each entry 8 bytes wide.
const (
	SeccompOffNR   = 0  // int    nr
	SeccompOffArch = 4  // __u32  arch
	seccompOffArg0 = 16 // __u64  args[0] — socket domain   (low word @16)
	seccompOffArg1 = 24 // __u64  args[1] — socket type     (low word @24)
	seccompOffArg2 = 32 // __u64  args[2] — socket protocol (low word @32)
)

// seccompSockTypeMask strips SOCK_CLOEXEC / SOCK_NONBLOCK (and any future) flags
// that callers OR into the socket() `type` argument, leaving just the base type.
// Go's net stack always sets SOCK_CLOEXEC|SOCK_NONBLOCK, so a filter comparing
// `type` raw against SOCK_STREAM would never match and refuse every Go socket
// (and a denylist comparing it raw would fail open).
const seccompSockTypeMask = 0xff

// SeccompX32SyscallBit is __X32_SYSCALL_BIT. The x32 ABI shares
// AUDIT_ARCH_X86_64 with native x86_64 (so it passes the arch guard), but its
// syscall numbers are OR'd with this bit — an x32 socket() has nr = 41|0x40000000,
// which would NOT match SYS_socket and would fall through to ALLOW: a silent
// bypass of every nr-based rule. Any syscall carrying this bit is killed
// (fail-closed) right after the arch guard. (The arch guard alone stops i386,
// which uses a DIFFERENT arch value; it does NOT stop x32.)
const SeccompX32SyscallBit = 0x40000000

// IPProtoMPTCP is IPPROTO_MPTCP (protocol 262). Named locally so the filter reads
// clearly; it equals unix.IPPROTO_MPTCP. The socket() allowlist refuses it like
// every other inet protocol that is not TCP (or UDP when permitted).
const IPProtoMPTCP = unix.IPPROTO_MPTCP

// netlinkRoute is NETLINK_ROUTE (protocol 0), the only netlink family the
// allowlist admits.
const netlinkRoute = unix.NETLINK_ROUTE

// SeccompPolicy parameterises the filter per spawn. Its zero value is the
// strictest filter (no UDP).
type SeccompPolicy struct {
	// AllowUDP admits AF_INET/AF_INET6 SOCK_DGRAM sockets with protocol 0 or
	// IPPROTO_UDP. linuxWrap sets it when the policy's network is Open at Rung
	// 2 (nothing scopes egress there, so refusing UDP only breaks resolution)
	// and always at Rung 1 (nftables scopes UDP inside the Netns). It is false
	// for a Confined Rung-2 spawn, whose Landlock port rules cannot scope UDP.
	AllowUDP bool
}

// BuildSeccompFilter builds the classic-BPF program for p as a
// []unix.SockFilter. See the annotated instruction listing inline; the
// bracketed indices are the amd64 layout, and the x32 guard ([4]-[5]) exists
// only there, so later instructions sit two earlier on arm64. Every jump is
// relative, so dropping the guard moves no branch target. The UDP tail
// ([44]-[50]) is emitted only for p.AllowUDP; otherwise [44] is a single
// deny. Every syscall number is a golang.org/x/sys/unix SYS_* constant,
// generated per GOARCH, and the argument offsets assume a little-endian ABI,
// which both supported architectures are. Structure:
//
//	arch guard  -> KILL_PROCESS on mismatch (stops i386 / AArch32 — a different
//	               arch value; see SeccompAuditArch)
//	x32 guard   -> amd64 only: KILL_PROCESS if nr carries __X32_SYSCALL_BIT (x32
//	               shares the x86_64 arch value, so the arch guard alone does
//	               NOT stop it)
//	ptrace / io_uring{setup,enter,register} / keyctl / add_key / request_key
//	            -> ERRNO(EACCES)
//	nr != socket -> ALLOW
//	domain AF_NETLINK: protocol == NETLINK_ROUTE && (type & 0xff) in
//	                   {SOCK_RAW, SOCK_DGRAM} -> ALLOW, else ERRNO(EACCES)
//	domain AF_INET / AF_INET6:
//	    (type & 0xff) == SOCK_STREAM: protocol in {0, IPPROTO_TCP} -> ALLOW,
//	                                  else ERRNO(EACCES)  (MPTCP, SCTP, SMC)
//	    (type & 0xff) == SOCK_DGRAM && AllowUDP: protocol in {0, IPPROTO_UDP}
//	                                  -> ALLOW, else ERRNO(EACCES)
//	    anything else -> ERRNO(EACCES)                     (raw, ICMP, UDP)
//	any other domain -> ERRNO(EACCES)  (AF_UNIX, AF_VSOCK, AF_SMC, AF_RDS, ...)
func BuildSeccompFilter(p SeccompPolicy) []unix.SockFilter {
	const (
		retKill  = unix.SECCOMP_RET_KILL_PROCESS
		retAllow = unix.SECCOMP_RET_ALLOW
		retErrno = unix.SECCOMP_RET_ERRNO | (uint32(unix.EACCES) & unix.SECCOMP_RET_DATA)
	)
	// --- arch guard ------------------------------------------------------------
	filter := []unix.SockFilter{
		// [0] A = seccomp_data.arch
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, SeccompOffArch),
		// [1] if A == the native arch -> skip the kill, else fall to [2]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, SeccompAuditArch(), 1, 0),
		// [2] arch mismatch (i386 on x86_64, AArch32 on arm64): kill the whole
		//     process (fail-closed)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retKill),
		// [3] A = seccomp_data.nr
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, SeccompOffNR),
	}
	if seccompGuardX32 {
		// --- x32 guard (amd64 only) -----------------------------------------------
		filter = append(filter,
			// [4] if (A & __X32_SYSCALL_BIT) != 0 -> fall to [5] kill, else skip it
			seccompJump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, SeccompX32SyscallBit, 0, 1),
			// [5] x32 syscall: kill (shares the x86_64 arch value but its nr would
			//     dodge the nr compares below and fall through to ALLOW)
			seccompStmt(unix.BPF_RET|unix.BPF_K, retKill),
		)
	}
	filter = append(filter, []unix.SockFilter{
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

		// --- keyrings -----------------------------------------------------------
		// [14] if A == SYS_keyctl -> fall to [15] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_KEYCTL, 0, 1),
		// [15] keyctl: deny (the invoking user's keyrings; no userns at Rung 2)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [16] if A == SYS_add_key -> fall to [17] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_ADD_KEY, 0, 1),
		// [17] add_key: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [18] if A == SYS_request_key -> fall to [19] deny, else skip it
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_REQUEST_KEY, 0, 1),
		// [19] request_key: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- socket(): domain/type/protocol allowlist ---------------------------
		// [20] if A == SYS_socket -> proceed to the domain load, else allow at [21]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SOCKET, 1, 0),
		// [21] not socket(): allow (the Go runtime needs its other syscalls;
		//      socketpair() is a distinct nr and lands here)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [22] A = args[0] low word (socket domain)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg0),
		// [23] if A == AF_INET  -> jump +12 to the inet type load [36]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET, 12, 0),
		// [24] if A == AF_INET6 -> jump +11 to the inet type load [36]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET6, 11, 0),
		// [25] if A == AF_NETLINK -> jump +1 to the netlink checks [27], else
		//      fall to [26]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_NETLINK, 1, 0),
		// [26] any other family (AF_UNIX, AF_VSOCK, AF_SMC, AF_RDS, AF_PACKET, ...):
		//      deny with EACCES
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- AF_NETLINK: NETLINK_ROUTE datagram/raw only -------------------------
		// [27] A = args[2] low word (netlink protocol)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg2),
		// [28] if A == NETLINK_ROUTE -> skip the deny to the type load [30]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, netlinkRoute, 1, 0),
		// [29] another netlink family (audit, xfrm, netfilter, ...): deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [30] A = args[1] low word (socket type, may carry SOCK_CLOEXEC/NONBLOCK)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg1),
		// [31] A = A & 0xff  (strip the flag bits, keep the base type)
		seccompStmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, seccompSockTypeMask),
		// [32] if A == SOCK_RAW -> jump +1 to the allow [34]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_RAW), 1, 0),
		// [33] if A == SOCK_DGRAM -> fall to the allow [34], else skip to the
		//      deny [35]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_DGRAM), 0, 1),
		// [34] NETLINK_ROUTE raw/dgram: allow (glibc getaddrinfo address lookup)
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
		// [35] NETLINK_ROUTE of another type: deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),

		// --- AF_INET / AF_INET6 -------------------------------------------------
		// [36] A = args[1] low word (socket type, may carry SOCK_CLOEXEC/NONBLOCK)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg1),
		// [37] A = A & 0xff  (strip the flag bits, keep the base type)
		seccompStmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, seccompSockTypeMask),
		// [38] if A == SOCK_STREAM -> fall to the protocol load [39], else jump
		//      +5 to the non-stream branch [44] (A still holds the base type)
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_STREAM), 0, 5),
		// [39] A = args[2] low word (socket protocol)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg2),
		// [40] if A == 0 (the default, TCP) -> jump +2 to the allow [43]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 2, 0),
		// [41] if A == IPPROTO_TCP -> jump +1 to the allow [43], else fall to [42]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.IPPROTO_TCP, 1, 0),
		// [42] inet stream that is not plain TCP (MPTCP 262, SCTP 132, SMC 256):
		//      deny with EACCES — Landlock's TCP port rules do not cover it
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [43] plain TCP: allow — the positive control proving the socket rule is
		//      an allowlist and not a blanket socket() ban
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
	}...)
	if !p.AllowUDP {
		return append(filter,
			// [44] inet non-stream (UDP, raw, ICMP, SEQPACKET): deny with EACCES —
			//      UDP has no Landlock address/port scoping on a Confined spawn
			seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		)
	}
	return append(filter, []unix.SockFilter{
		// [44] if A == SOCK_DGRAM -> skip the deny to the protocol load [46]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(unix.SOCK_DGRAM), 1, 0),
		// [45] inet raw / ICMP / SEQPACKET: deny with EACCES
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [46] A = args[2] low word (socket protocol)
		seccompStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompOffArg2),
		// [47] if A == 0 (the default, UDP) -> jump +2 to the allow [50]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 2, 0),
		// [48] if A == IPPROTO_UDP -> jump +1 to the allow [50], else fall to [49]
		seccompJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.IPPROTO_UDP, 1, 0),
		// [49] inet datagram that is not UDP (ICMP ping, UDP-Lite): deny
		seccompStmt(unix.BPF_RET|unix.BPF_K, retErrno),
		// [50] UDP on an Open-network or Rung-1 spawn: allow
		seccompStmt(unix.BPF_RET|unix.BPF_K, retAllow),
	}...)
}

// SeccompAuditArch is the seccomp_data.arch value the filter accepts: the
// native architecture this binary was built for (seccomp_arch_*.go), or 0 where
// no filter is supported.
func SeccompAuditArch() uint32 { return seccompAuditArch }

// seccompStmt builds a non-branching BPF instruction (jt/jf = 0).
func seccompStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// seccompJump builds a conditional BPF instruction. jt/jf are relative
// instruction skips taken when the comparison is true / false.
func seccompJump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// errUnsupportedSeccompArch refuses to install a filter on an architecture with
// no seccomp_arch_*.go binding (ProbeSeccompFilter already reports it absent).
var errUnsupportedSeccompArch = errors.New("no seccomp filter for this architecture (" + runtime.GOARCH + ")")

// seccompError is the typed, fail-closed failure of the stage-2 Seccomp install
// (SPEC §7.2). It names the failing step (PR_SET_NO_NEW_PRIVS or PR_SET_SECCOMP)
// and wraps the underlying errno for errors.As/Unwrap. RunStage2 surfaces it as a
// Stage2Error{Op:"Seccomp"} so the child fails closed rather than running the
// target unconfined.
type seccompError struct {
	Op  string // the failing step, e.g. "PR_SET_NO_NEW_PRIVS", "PR_SET_SECCOMP"
	Err error  // the wrapped underlying error (typically a syscall.Errno)
}

func (e *seccompError) Error() string { return "sandbox: Seccomp: " + e.Op + ": " + e.Err.Error() }
func (e *seccompError) Unwrap() error { return e.Err }

// installSeccompFilter installs the filter built for p on the CURRENT OS thread and
// leaves that thread pinned so the caller's subsequent syscall.Exec runs on it.
//
// PR_SET_SECCOMP and PR_SET_NO_NEW_PRIVS are PER-THREAD, so the thread that
// installs the filter MUST be the thread that execve's — otherwise the target
// could run on a sibling thread that never got the filter. runtime.LockOSThread
// pins this goroutine to its thread and is deliberately NEVER unlocked: the
// stage-2 child does install -> chdir -> execve on this one goroutine, so the
// pinned thread is the execve thread, and execve collapses the process to that
// single filtered thread. Every thread the target later spawns inherits the
// filter (Seccomp filters propagate across clone), so the whole target is
// Confined. (Landlock (12a) already restricts all threads via psx and sets
// no_new_privs; PR_SET_NO_NEW_PRIVS is set again here, idempotently, so the
// SET_MODE_FILTER install can never EACCES on the precondition.)
//
// golang.org/x/sys v0.40.0 exposes no unix.Seccomp wrapper, so the install uses
// the classic PR_SET_SECCOMP / SECCOMP_MODE_FILTER path via unix.Syscall. The
// uintptr(unsafe.Pointer(&prog)) conversion is passed directly as a unix.Syscall
// argument — the vet-recognized idiom that keeps prog (and its backing filter
// slice) live across the call; runtime.KeepAlive is belt-and-braces.
func installSeccompFilter(p SeccompPolicy) error {
	runtime.LockOSThread() // pin: this thread installs AND execve's; never unlocked.

	if !seccompArchSupported {
		return &seccompError{Op: "build filter", Err: errUnsupportedSeccompArch}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return &seccompError{Op: "PR_SET_NO_NEW_PRIVS", Err: err}
	}

	filter := BuildSeccompFilter(p)
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
