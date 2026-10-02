//go:build linux

package exec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"net"
	"os"
	osexec "os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// requireSeccompArch skips on an architecture with no filter binding, where
// BuildSeccompFilter's arch guard accepts nothing (TestSeccompAuditArchMatchesGOARCH
// proves that fails closed).
func requireSeccompArch(t *testing.T) {
	t.Helper()
	if linux.SeccompAuditArch() == 0 {
		t.Skipf("no seccomp filter binding for GOARCH=%s", runtime.GOARCH)
	}
}

// requireSeccomp skips a test on a host without SECCOMP_MODE_FILTER (rung 2).
// This host has it, so these tests RUN for real; the skip keeps the suite honest
// on weaker kernels rather than silently passing an unenforced filter.
func requireSeccomp(t *testing.T) {
	t.Helper()
	if !linux.ProbeSeccompFilter() {
		t.Skip("SECCOMP_MODE_FILTER unavailable on this host; linux.Rung-2 Seccomp filter cannot run")
	}
}

// --- Structural proof: a tiny classic-BPF interpreter over linux.BuildSeccompFilter() -
//
// The interpreter runs the SHIPPED filter against synthetic seccomp_data and
// asserts the return action for each (nr, args) case. This isolates the
// anti-fail-open logic — a missing x32 guard, an unmasked SOCK type, or an
// unfiltered io_uring is a real bypass — from the kernel, so a regression is
// caught even on a host without Seccomp.

// seccompData is the little-endian seccomp_data layout the kernel presents to a
// classic-BPF filter: nr@0, arch@4, instruction_pointer@8, args[0..5]@16.
func seccompData(arch uint32, nr uint32, args [6]uint64) []byte {
	buf := make([]byte, 64)
	binary.LittleEndian.PutUint32(buf[linux.SeccompOffNR:], nr)
	binary.LittleEndian.PutUint32(buf[linux.SeccompOffArch:], arch)
	for i := 0; i < 6; i++ {
		binary.LittleEndian.PutUint64(buf[16+i*8:], args[i])
	}
	return buf
}

// runBPF executes the subset of classic BPF that linux.BuildSeccompFilter() uses
// (BPF_LD|W|ABS, BPF_JMP|JEQ/JSET|K, BPF_ALU|AND|K, BPF_RET|K) against data and
// returns the SECCOMP_RET_* action. It faithfully models forward relative jumps
// and the accumulator, so it verifies the exact jt/jf offsets in the shipped
// program — an off-by-one in a jump is a real fail-open and this catches it.
func runBPF(t *testing.T, prog []unix.SockFilter, data []byte) uint32 {
	t.Helper()
	const (
		classLD  = unix.BPF_LD
		classJMP = unix.BPF_JMP
		classALU = unix.BPF_ALU
		classRET = unix.BPF_RET
	)
	var a uint32
	pc := 0
	for steps := 0; steps < 1000; steps++ {
		if pc < 0 || pc >= len(prog) {
			t.Fatalf("BPF pc out of range: %d (len %d)", pc, len(prog))
		}
		ins := prog[pc]
		class := ins.Code & 0x07
		switch class {
		case classLD:
			// Only BPF_W|BPF_ABS is used: load a 32-bit word at absolute offset K.
			off := int(ins.K)
			if off < 0 || off+4 > len(data) {
				t.Fatalf("BPF load out of range: off=%d", off)
			}
			a = binary.LittleEndian.Uint32(data[off:])
			pc++
		case classALU:
			// Only BPF_AND|BPF_K is used.
			a &= ins.K
			pc++
		case classJMP:
			op := ins.Code & 0xf0
			var cond bool
			switch op {
			case unix.BPF_JEQ:
				cond = a == ins.K
			case unix.BPF_JSET:
				cond = (a & ins.K) != 0
			default:
				t.Fatalf("BPF unsupported jump op: %#x", op)
			}
			if cond {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case classRET:
			return ins.K
		default:
			t.Fatalf("BPF unsupported class: %#x (code %#x)", class, ins.Code)
		}
	}
	t.Fatalf("BPF program did not terminate")
	return 0
}

// TestBuildSeccompFilterStructure runs the shipped filter through the
// interpreter for the full anti-fail-open table, against BOTH builds — the
// strict filter (SeccompPolicy{}, a Confined Rung-2 spawn) and the UDP-admitting
// filter (AllowUDP, an Open Rung-2 network or any Rung-1 spawn). Every row
// states its result under each, so the only difference the AllowUDP bit may
// make is to inet UDP. It covers the arch/x32 kill guards, the nr-only denials
// (ptrace, io_uring, keyrings), the socket() allowlist (review C2/H1: AF_UNIX,
// AF_VSOCK, AF_SMC, MPTCP, SCTP, SMC refused; TCP and NETLINK_ROUTE allowed)
// and unrelated syscalls, including socketpair. SOCK_CLOEXEC-flagged types
// exercise the 0xff mask.
func TestBuildSeccompFilterStructure(t *testing.T) {
	t.Parallel()
	confinedProg := linux.BuildSeccompFilter(linux.SeccompPolicy{})
	openProg := linux.BuildSeccompFilter(linux.SeccompPolicy{AllowUDP: true})
	// unixProg is the escape-hatch build (profile.UnixSocketPolicy non-zero):
	// it may differ from confinedProg ONLY on well-formed AF_UNIX socket()
	// calls; unixOpenProg composes both bits.
	unixProg := linux.BuildSeccompFilter(linux.SeccompPolicy{AllowUnix: true})
	unixOpenProg := linux.BuildSeccompFilter(linux.SeccompPolicy{AllowUDP: true, AllowUnix: true})

	// The filter binds the architecture it was built for; x86 below is that
	// native arch value on every GOARCH (the name predates arm64 support), and
	// foreign is a compat arch the guard must kill.
	requireSeccompArch(t)
	x86 := linux.SeccompAuditArch()
	foreign := uint32(unix.AUDIT_ARCH_I386)
	if runtime.GOARCH == "arm64" {
		foreign = unix.AUDIT_ARCH_ARM
	}
	const retErrno = unix.SECCOMP_RET_ERRNO | (uint32(unix.EACCES) & unix.SECCOMP_RET_DATA)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	kill := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	dgram := uint64(unix.SOCK_DGRAM)
	stream := uint64(unix.SOCK_STREAM)
	raw := uint64(unix.SOCK_RAW)
	seqpacket := uint64(unix.SOCK_SEQPACKET)
	cloexec := uint64(unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK)
	const (
		afSMC      = 43  // AF_SMC
		ipprotoSMC = 256 // IPPROTO_SMC
	)

	type row struct {
		name         string
		arch         uint32
		nr           uint32
		args         [6]uint64
		wantConfined uint32 // SeccompPolicy{}
		wantOpen     uint32 // SeccompPolicy{AllowUDP: true}
		// wantUnix is the result under SeccompPolicy{AllowUnix: true} (and,
		// with wantOpen's UDP result, under both bits). Zero means "same as
		// wantConfined": only AF_UNIX rows set it.
		wantUnix uint32
	}
	same := func(name string, arch, nr uint32, args [6]uint64, want uint32) row {
		return row{name: name, arch: arch, nr: nr, args: args, wantConfined: want, wantOpen: want}
	}
	// unixRow is an AF_UNIX socket() row: refused by default, admitted only
	// by the escape-hatch build.
	unixRow := func(name string, args [6]uint64, wantUnix uint32) row {
		return row{name: name, arch: x86, nr: unix.SYS_SOCKET, args: args, wantConfined: retErrno, wantOpen: retErrno, wantUnix: wantUnix}
	}
	sock := func(domain, typ, proto uint64) [6]uint64 { return [6]uint64{domain, typ, proto} }
	ioctlReq := func(request uint64) [6]uint64 { return [6]uint64{0, request} }
	tests := []row{
		// Kill guards (anti-fail-open, fail-closed).
		same("foreign arch killed", foreign, unix.SYS_SOCKET, sock(unix.AF_INET, stream, 0), kill),
		// UDP: refused on a Confined spawn, admitted (protocol 0/UDP only) when Open.
		{"AF_INET dgram", x86, unix.SYS_SOCKET, sock(unix.AF_INET, dgram, 0), retErrno, allow, 0},
		{"AF_INET6 dgram", x86, unix.SYS_SOCKET, sock(unix.AF_INET6, dgram, 0), retErrno, allow, 0},
		{"AF_INET dgram with CLOEXEC flags (mask)", x86, unix.SYS_SOCKET, sock(unix.AF_INET, dgram|cloexec, 0), retErrno, allow, 0},
		{"AF_INET dgram IPPROTO_UDP", x86, unix.SYS_SOCKET, sock(unix.AF_INET, dgram, unix.IPPROTO_UDP), retErrno, allow, 0},
		same("AF_INET dgram ICMP ping socket denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, dgram, unix.IPPROTO_ICMP), retErrno),
		same("AF_INET dgram UDP-Lite denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, dgram, unix.IPPROTO_UDPLITE), retErrno),
		same("AF_INET raw denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, raw, unix.IPPROTO_ICMP), retErrno),
		same("AF_INET seqpacket SCTP denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, seqpacket, unix.IPPROTO_SCTP), retErrno),
		// Stream protocols Landlock's TCP port rules do not cover.
		same("AF_INET stream MPTCP denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream, uint64(linux.IPProtoMPTCP)), retErrno),
		same("AF_INET6 stream MPTCP denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET6, stream, uint64(linux.IPProtoMPTCP)), retErrno),
		same("AF_INET stream MPTCP with CLOEXEC denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream|cloexec, uint64(linux.IPProtoMPTCP)), retErrno),
		same("AF_INET stream SCTP denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream, unix.IPPROTO_SCTP), retErrno),
		same("AF_INET6 stream SCTP denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET6, stream, unix.IPPROTO_SCTP), retErrno),
		same("AF_INET stream IPPROTO_SMC denied", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream, ipprotoSMC), retErrno),
		// Families outside the allowlist (review C2/H1).
		// AF_UNIX: refused by default, admitted by the escape hatch (stream,
		// datagram, seqpacket; protocol 0 only; flag bits masked).
		unixRow("AF_UNIX stream", sock(unix.AF_UNIX, stream, 0), allow),
		unixRow("AF_UNIX stream with CLOEXEC", sock(unix.AF_UNIX, stream|cloexec, 0), allow),
		unixRow("AF_UNIX dgram", sock(unix.AF_UNIX, dgram, 0), allow),
		unixRow("AF_UNIX dgram with CLOEXEC", sock(unix.AF_UNIX, dgram|cloexec, 0), allow),
		unixRow("AF_UNIX seqpacket", sock(unix.AF_UNIX, seqpacket, 0), allow),
		unixRow("AF_UNIX stream nonzero protocol denied even by the escape hatch", sock(unix.AF_UNIX, stream, 1), retErrno),
		unixRow("AF_UNIX raw type denied even by the escape hatch", sock(unix.AF_UNIX, raw, 0), retErrno),
		unixRow("AF_UNIX rdm type denied even by the escape hatch", sock(unix.AF_UNIX, uint64(unix.SOCK_RDM), 0), retErrno),
		unixRow("AF_UNIX with high domain bits is still AF_UNIX (the kernel takes an int)", sock(1<<32|unix.AF_UNIX, stream, 0), allow),
		same("AF_VSOCK stream denied", x86, unix.SYS_SOCKET, sock(unix.AF_VSOCK, stream, 0), retErrno),
		same("AF_SMC stream denied", x86, unix.SYS_SOCKET, sock(afSMC, stream, 0), retErrno),
		same("AF_RDS seqpacket denied", x86, unix.SYS_SOCKET, sock(unix.AF_RDS, seqpacket, 0), retErrno),
		same("AF_PACKET raw denied", x86, unix.SYS_SOCKET, sock(unix.AF_PACKET, raw, 0), retErrno),
		same("AF_NETLINK audit denied", x86, unix.SYS_SOCKET, sock(unix.AF_NETLINK, raw, unix.NETLINK_AUDIT), retErrno),
		same("AF_NETLINK netfilter denied", x86, unix.SYS_SOCKET, sock(unix.AF_NETLINK, raw, unix.NETLINK_NETFILTER), retErrno),
		same("AF_NETLINK route seqpacket denied", x86, unix.SYS_SOCKET, sock(unix.AF_NETLINK, seqpacket, unix.NETLINK_ROUTE), retErrno),
		// nr-only denials.
		same("ptrace denied", x86, unix.SYS_PTRACE, [6]uint64{}, retErrno),
		same("io_uring_setup denied", x86, unix.SYS_IO_URING_SETUP, [6]uint64{}, retErrno),
		same("io_uring_enter denied", x86, unix.SYS_IO_URING_ENTER, [6]uint64{}, retErrno),
		same("io_uring_register denied", x86, unix.SYS_IO_URING_REGISTER, [6]uint64{}, retErrno),
		same("keyctl denied", x86, unix.SYS_KEYCTL, [6]uint64{}, retErrno),
		same("add_key denied", x86, unix.SYS_ADD_KEY, [6]uint64{}, retErrno),
		same("request_key denied", x86, unix.SYS_REQUEST_KEY, [6]uint64{}, retErrno),
		// Terminal input injection (review M12): the request is an unsigned
		// int in the kernel, so the low-word compare is the whole request.
		same("ioctl TIOCSTI denied", x86, unix.SYS_IOCTL, ioctlReq(linux.IoctlTIOCSTI), retErrno),
		same("ioctl TIOCLINUX denied", x86, unix.SYS_IOCTL, ioctlReq(linux.IoctlTIOCLINUX), retErrno),
		same("ioctl TIOCSTI with high request bits denied (kernel truncates to 32 bits)", x86, unix.SYS_IOCTL, ioctlReq(1<<32|linux.IoctlTIOCSTI), retErrno),
		same("ioctl TCGETS allowed", x86, unix.SYS_IOCTL, ioctlReq(unix.TCGETS), allow),
		same("ioctl TIOCGWINSZ allowed", x86, unix.SYS_IOCTL, ioctlReq(unix.TIOCGWINSZ), allow),
		same("ioctl FIONREAD (TIOCINQ) allowed", x86, unix.SYS_IOCTL, ioctlReq(unix.TIOCINQ), allow),
		// Positive controls (must ALLOW, else the filter is a blanket ban).
		same("AF_INET stream TCP allowed", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream, 0), allow),
		same("AF_INET stream IPPROTO_TCP allowed", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream, unix.IPPROTO_TCP), allow),
		same("AF_INET stream TCP with CLOEXEC allowed", x86, unix.SYS_SOCKET, sock(unix.AF_INET, stream|cloexec, 0), allow),
		same("AF_INET6 stream TCP allowed", x86, unix.SYS_SOCKET, sock(unix.AF_INET6, stream, 0), allow),
		same("AF_INET6 stream IPPROTO_TCP with CLOEXEC allowed", x86, unix.SYS_SOCKET, sock(unix.AF_INET6, stream|cloexec, unix.IPPROTO_TCP), allow),
		same("AF_NETLINK route raw allowed (getaddrinfo)", x86, unix.SYS_SOCKET, sock(unix.AF_NETLINK, raw|cloexec, unix.NETLINK_ROUTE), allow),
		same("AF_NETLINK route dgram allowed", x86, unix.SYS_SOCKET, sock(unix.AF_NETLINK, dgram, unix.NETLINK_ROUTE), allow),
		same("socketpair AF_UNIX allowed (distinct syscall)", x86, unix.SYS_SOCKETPAIR, sock(unix.AF_UNIX, stream|cloexec, 0), allow),
		same("unrelated syscall allowed", x86, unix.SYS_WRITE, [6]uint64{}, allow),
		same("openat allowed", x86, unix.SYS_OPENAT, [6]uint64{}, allow),
		same("connect allowed (scoped by Landlock / nftables, not seccomp)", x86, unix.SYS_CONNECT, [6]uint64{}, allow),
	}
	if runtime.GOARCH == "amd64" {
		// x32 shares AUDIT_ARCH_X86_64; only its syscall-number bit tells it apart.
		tests = append(tests,
			same("x32 socket killed", x86, unix.SYS_SOCKET|linux.SeccompX32SyscallBit, sock(unix.AF_INET, dgram, 0), kill),
			same("x32 write killed", x86, unix.SYS_WRITE|linux.SeccompX32SyscallBit, [6]uint64{}, kill),
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := seccompData(tt.arch, tt.nr, tt.args)
			if got := runBPF(t, confinedProg, data); got != tt.wantConfined {
				t.Errorf("confined filter(%s) = %#x, want %#x", tt.name, got, tt.wantConfined)
			}
			if got := runBPF(t, openProg, data); got != tt.wantOpen {
				t.Errorf("UDP-admitting filter(%s) = %#x, want %#x", tt.name, got, tt.wantOpen)
			}
			wantUnix, wantUnixOpen := tt.wantConfined, tt.wantOpen
			if tt.wantUnix != 0 {
				wantUnix, wantUnixOpen = tt.wantUnix, tt.wantUnix
			}
			if got := runBPF(t, unixProg, data); got != wantUnix {
				t.Errorf("AF_UNIX-admitting filter(%s) = %#x, want %#x", tt.name, got, wantUnix)
			}
			if got := runBPF(t, unixOpenProg, data); got != wantUnixOpen {
				t.Errorf("AF_UNIX+UDP-admitting filter(%s) = %#x, want %#x", tt.name, got, wantUnixOpen)
			}
		})
	}
}

// TestBuildSeccompFilterLayout pins the program length the bracketed
// instruction indices in seccomp.go document ([0]-[61] strict, [0]-[67] with
// the UDP tail, on amd64; two fewer on arm64 without the x32 guard), so an
// inserted instruction that is not re-indexed in the listing fails here. The
// AF_UNIX escape hatch selects one return action and never changes the
// length, so the listing holds for both values of AllowUnix.
func TestBuildSeccompFilterLayout(t *testing.T) {
	t.Parallel()
	requireSeccompArch(t)
	strict, open := 62, 68
	if runtime.GOARCH != "amd64" {
		strict, open = strict-2, open-2
	}
	for _, allowUnix := range []bool{false, true} {
		if got := len(linux.BuildSeccompFilter(linux.SeccompPolicy{AllowUnix: allowUnix})); got != strict {
			t.Errorf("strict filter (AllowUnix=%t) length = %d, want %d (re-index the seccomp.go listing)", allowUnix, got, strict)
		}
		if got := len(linux.BuildSeccompFilter(linux.SeccompPolicy{AllowUDP: true, AllowUnix: allowUnix})); got != open {
			t.Errorf("UDP-admitting filter (AllowUnix=%t) length = %d, want %d (re-index the seccomp.go listing)", allowUnix, got, open)
		}
	}
}

// --- Runtime proof through the REAL stage-2 backend ---------------------------
//
// The e2e proof re-runs THIS test binary as the stage-2 TARGET: the linux.Backend
// re-execs /proc/self/exe as the stage-2 helper, which installs Landlock +
// Seccomp and execve's /proc/self/exe (the target). In the target the Seccomp
// probe sentinel is set (via the policy's Env.Set) and the dispatch sentinel is
// NOT (it is scrubbed out of the target env), so seccompTargetDispatch runs the
// probes UNDER the filter inherited across the execve and prints markers the
// parent asserts on. This proves the socket() allowlist and the nr-only denials
// hold while TCP works — in a real post-execve target, composed with Landlock.

// seccompTargetEnv marks a process that should run the Seccomp probes and exit.
// It is injected into the TARGET env via the policy's Env.Set, so it is present
// only after the stage-2 execve — not in the stage-2 helper (which additionally
// carries linux.Stage2SentinelEnv, the distinguisher checked below).
const seccompTargetEnv = "LRSANDBOX_SECCOMP_PROBE"

// Marker keys the target prints (one KEY=VALUE line each).
const (
	seccompKeyUDP     = "UDP"     // socket(AF_INET, SOCK_DGRAM) -> want EACCES
	seccompKeyMPTCP   = "MPTCP"   // socket(AF_INET, SOCK_STREAM, 262) -> want EACCES
	seccompKeyTCP     = "TCP"     // socket(AF_INET, SOCK_STREAM) -> want OK (positive control)
	seccompKeyPtrace  = "PTRACE"  // ptrace(PTRACE_TRACEME) -> want EACCES
	seccompKeyIOUring = "IOURING" // io_uring_setup -> want EACCES
	// Socket allowlist probes (review C2/H1).
	seccompKeyUnix       = "UNIX"       // socket(AF_UNIX, SOCK_STREAM) -> want EACCES (D-Bus / agent sockets)
	seccompKeyUnixDgram  = "UNIXDGRAM"  // socket(AF_UNIX, SOCK_DGRAM) -> want EACCES (journald / syslog)
	seccompKeySocketpair = "SOCKETPAIR" // socketpair(AF_UNIX, SOCK_STREAM) -> want OK (in-process IPC)
	seccompKeyNetlink    = "NETLINK"    // socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) -> want OK (getaddrinfo)
	seccompKeyVsock      = "VSOCK"      // socket(AF_VSOCK, SOCK_STREAM) -> want EACCES
	seccompKeySCTP       = "SCTP"       // socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) -> want EACCES
	seccompKeyKeyctl     = "KEYCTL"     // keyctl(KEYCTL_GET_KEYRING_ID, session) -> want EACCES
	// seccompKeyDNS is the result of a real UDP DNS query from the target to
	// the address in seccompDNSServerEnv (review H2): OK when the policy's
	// network is Open, EACCES (the UDP socket refused) when it is Confined.
	seccompKeyDNS    = "DNS"
	seccompValOK     = "OK"
	seccompValEACCES = "EACCES"
)

// seccompDNSServerEnv carries the loopback UDP DNS responder's address into the
// probe target (via the policy's Env.Set). Rung 2 has no net namespace, so the
// parent's 127.0.0.1 listener is reachable from the target.
const seccompDNSServerEnv = "LRSANDBOX_SECCOMP_DNS"

// seccompDNSName is the one name the target looks up; the loopback responder
// answers any A question with 127.0.0.1.
const seccompDNSName = "lrsandbox.test."

// seccompTargetDispatch runs at package init in the re-exec'd TARGET only: the
// probe sentinel is set AND the stage-2 dispatch sentinel is NOT (the latter is
// present in the stage-2 helper but scrubbed out of the target env). It runs the
// socket/ptrace/io_uring probes under the inherited filter, prints the markers,
// and exits — it never returns to the test framework. In the parent or in a
// stage-2 helper it is a no-op.
func seccompTargetDispatch() {
	if os.Getenv(seccompTargetEnv) != "1" {
		return // not a probe target
	}
	if os.Getenv(linux.Stage2SentinelEnv) == linux.Stage2SentinelValue {
		return // this is the stage-2 helper (pre-execve); let Init()/linux.RunStage2 run
	}
	// Post-execve target: run the probes under the inherited Seccomp filter.
	fmt.Printf("%s=%s\n", seccompKeyUDP, classifySeccompSocket(unix.AF_INET, unix.SOCK_DGRAM, 0))
	fmt.Printf("%s=%s\n", seccompKeyMPTCP, classifySeccompSocket(unix.AF_INET, unix.SOCK_STREAM, linux.IPProtoMPTCP))
	fmt.Printf("%s=%s\n", seccompKeyTCP, classifySeccompSocket(unix.AF_INET, unix.SOCK_STREAM, 0))
	fmt.Printf("%s=%s\n", seccompKeyPtrace, classifySeccompPtrace())
	fmt.Printf("%s=%s\n", seccompKeyIOUring, classifySeccompIOUring())
	fmt.Printf("%s=%s\n", seccompKeyUnix, classifySeccompSocket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0))
	fmt.Printf("%s=%s\n", seccompKeyUnixDgram, classifySeccompSocket(unix.AF_UNIX, unix.SOCK_DGRAM, 0))
	fmt.Printf("%s=%s\n", seccompKeySocketpair, classifySeccompSocketpair())
	fmt.Printf("%s=%s\n", seccompKeyNetlink, classifySeccompSocket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE))
	fmt.Printf("%s=%s\n", seccompKeyVsock, classifySeccompSocket(unix.AF_VSOCK, unix.SOCK_STREAM, 0))
	fmt.Printf("%s=%s\n", seccompKeySCTP, classifySeccompSocket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_SCTP))
	fmt.Printf("%s=%s\n", seccompKeyKeyctl, classifySeccompKeyctl())
	if server := os.Getenv(seccompDNSServerEnv); server != "" {
		fmt.Printf("%s=%s\n", seccompKeyDNS, classifySeccompDNS(server))
	}
	os.Exit(0)
}

// init dispatches the Seccomp probe target. It runs before TestMain (which calls
// Init()); guarding on the two sentinels keeps it inert in every process except
// the intended post-execve probe target.
func init() { seccompTargetDispatch() }

// classifySeccompSocket attempts socket(domain, typ, proto) and reports OK (fd
// closed) or EACCES; any other error is surfaced verbatim for diagnosis. A
// SECCOMP_RET_ERRNO|EACCES denial (not a kernel EINVAL/EPROTONOSUPPORT) is what
// proves the FILTER caught the call — critical for the MPTCP probe, which on a
// kernel lacking MPTCP would otherwise fail with a different errno.
func classifySeccompSocket(domain, typ, proto int) string {
	fd, err := unix.Socket(domain, typ, proto)
	if err == nil {
		_ = unix.Close(fd)
		return seccompValOK
	}
	if errors.Is(err, syscall.EACCES) {
		return seccompValEACCES
	}
	return "ERR:" + err.Error()
}

// classifySeccompPtrace attempts ptrace(PTRACE_TRACEME) and reports EACCES when
// the filter denies it, OK otherwise. Using the raw syscall keeps the probe
// dependency-free and observes exactly the Seccomp return.
func classifySeccompPtrace() string {
	_, _, errno := unix.Syscall(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0)
	if errno == 0 {
		return seccompValOK
	}
	if errno == syscall.EACCES {
		return seccompValEACCES
	}
	return "ERR:" + errno.Error()
}

// classifySeccompIOUring attempts io_uring_setup(0, &params) and reports EACCES
// when the filter denies it. A zero-entry setup would normally fail EINVAL, so
// EACCES specifically proves the Seccomp filter intercepted it.
func classifySeccompIOUring() string {
	var params [120]byte // sizeof(struct io_uring_params) is 120; contents irrelevant when denied
	_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
	if errno == 0 {
		return seccompValOK
	}
	if errno == syscall.EACCES {
		return seccompValEACCES
	}
	return "ERR:" + errno.Error()
}

// classifySeccompSocketpair attempts socketpair(AF_UNIX, SOCK_STREAM): the
// in-process IPC primitive Go, Node and Chromium use, which the socket()
// allowlist must leave untouched (socketpair is a different syscall).
func classifySeccompSocketpair() string {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		return seccompValOK
	}
	if errors.Is(err, syscall.EACCES) {
		return seccompValEACCES
	}
	return "ERR:" + err.Error()
}

// classifySeccompKeyctl attempts keyctl(KEYCTL_GET_KEYRING_ID, session, 0),
// which reads the user's session keyring id; the filter refuses it EACCES.
func classifySeccompKeyctl() string {
	sessionKeyring := int32(unix.KEY_SPEC_SESSION_KEYRING)
	_, _, errno := unix.Syscall(unix.SYS_KEYCTL, uintptr(unix.KEYCTL_GET_KEYRING_ID), uintptr(sessionKeyring), 0)
	if errno == 0 {
		return seccompValOK
	}
	if errno == syscall.EACCES {
		return seccompValEACCES
	}
	return "ERR:" + errno.Error()
}

// classifySeccompDNS resolves seccompDNSName with Go's pure resolver over UDP
// against server, the parent's loopback responder: the same UDP-first query
// glibc's getaddrinfo issues. It reports OK on an answer and EACCES when the
// UDP socket itself was refused (Go wraps the errno in a *net.OpError).
func classifySeccompDNS(server string) string {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, seccompDNSName)
	if err == nil {
		if len(addrs) > 0 {
			return seccompValOK
		}
		return "ERR:no addresses"
	}
	// *net.DNSError does not always unwrap to the dial's errno, so the refused
	// UDP socket is also recognised by its message ("socket: permission
	// denied").
	if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), syscall.EACCES.Error()) {
		return seccompValEACCES
	}
	return fmt.Sprintf("ERR:%v", err)
}

// startLoopbackDNSResponder serves 127.0.0.1 UDP, answering any A question
// with 127.0.0.1 — enough for one Go resolver lookup. t.Cleanup stops it.
func startLoopbackDNSResponder(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply := loopbackDNSReply(buf[:n]); reply != nil {
				_, _ = conn.WriteTo(reply, peer)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// loopbackDNSReply answers a single-question query: the query's header and
// question with QR|RD|RA set, plus one 127.0.0.1 answer for an A question (an
// empty NOERROR answer otherwise, which the Go resolver accepts for its
// parallel AAAA query).
func loopbackDNSReply(query []byte) []byte {
	const headerLen = 12
	if len(query) < headerLen {
		return nil
	}
	end := headerLen
	for end < len(query) && query[end] != 0 {
		end += 1 + int(query[end])
	}
	end += 1 + 4 // root label + QTYPE + QCLASS
	if end > len(query) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(query[end-4:])
	reply := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(reply[2:], 0x8180) // QR, RD, RA, NOERROR
	binary.BigEndian.PutUint16(reply[6:], 0)      // ANCOUNT
	binary.BigEndian.PutUint16(reply[8:], 0)      // NSCOUNT
	binary.BigEndian.PutUint16(reply[10:], 0)     // ARCOUNT
	if qtype == 1 {
		binary.BigEndian.PutUint16(reply[6:], 1)
		reply = append(reply,
			0xc0, 0x0c, // NAME: pointer to the question
			0x00, 0x01, 0x00, 0x01, // TYPE A, CLASS IN
			0x00, 0x00, 0x00, 0x3c, // TTL 60
			0x00, 0x04, 127, 0, 0, 1) // RDLENGTH 4, 127.0.0.1
	}
	return reply
}

// parseSeccompMarkers turns the target's KEY=VALUE lines into a map.
func parseSeccompMarkers(out []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return m
}

// TestLinuxSeccompDeniesInTarget is the headline runtime proof: through the real
// linux.Backend stage-2 (Landlock + Seccomp), a post-execve target of a Confined
// network has UDP, MPTCP, SCTP, AF_UNIX, AF_VSOCK, ptrace, io_uring and keyctl
// denied with EACCES while plain TCP, NETLINK_ROUTE and socketpair still work. The
// positive TCP control is the anti-fail-open guard — a blanket socket() ban would
// (correctly) fail it. Parent-unaffected and existing FS composition are covered
// by the sibling tests below and the untouched landlock suite.
func TestLinuxSeccompDeniesInTarget(t *testing.T) {
	requireLandlockV4(t) // linux.Rung-2 backend also needs Landlock v4 to spawn
	requireSeccomp(t)

	ws := t.TempDir()
	// Inject the probe sentinel into the TARGET env via Env.Set, so the re-exec'd
	// target's init() runs the probes. TMPDIR is forced by the baseline regardless.
	e, err := newExecutorForEffectivePolicy(
		backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{seccompTargetEnv: "1"}})),
		withBackend(linux.NewBackend()),
	)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	// The target IS this test binary, re-exec'd; RunArgv execve's /proc/self/exe,
	// whose init() (seccompTargetDispatch) prints the markers under the filter.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/proc/self/exe"})
	if err != nil {
		t.Fatalf("RunArgv(/proc/self/exe): err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("probe target exit = %d, want 0 (out=%q)", code, out)
	}
	got := parseSeccompMarkers(out)

	checks := []struct {
		name string
		key  string
		want string
	}{
		{"UDP socket denied (no address scoping at linux.Rung 2)", seccompKeyUDP, seccompValEACCES},
		{"MPTCP socket denied (closes the port-allowlist bypass)", seccompKeyMPTCP, seccompValEACCES},
		{"ptrace denied", seccompKeyPtrace, seccompValEACCES},
		{"io_uring_setup denied", seccompKeyIOUring, seccompValEACCES},
		{"TCP socket allowed (deny is arg-scoped, not blanket)", seccompKeyTCP, seccompValOK},
		{"AF_UNIX stream socket denied (no D-Bus / agent socket reach)", seccompKeyUnix, seccompValEACCES},
		{"AF_UNIX dgram socket denied", seccompKeyUnixDgram, seccompValEACCES},
		{"socketpair allowed (in-process IPC)", seccompKeySocketpair, seccompValOK},
		{"netlink route socket allowed (getaddrinfo)", seccompKeyNetlink, seccompValOK},
		{"AF_VSOCK socket denied", seccompKeyVsock, seccompValEACCES},
		{"SCTP socket denied (outside the Landlock TCP rules)", seccompKeySCTP, seccompValEACCES},
		{"keyctl denied", seccompKeyKeyctl, seccompValEACCES},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got[c.key] != c.want {
				t.Errorf("target %s = %q, want %q\nfull target output:\n%s", c.key, got[c.key], c.want, out)
			}
		})
	}
}

// TestLinuxSeccompUDPFollowsNetworkPolicy is the review-H2 runtime proof:
// the same Rung-2 filter used to refuse every UDP socket even under
// `Network: Allow` (Net.Open), so glibc's UDP-first resolver — and every other
// UDP client — failed in an open sandbox. A real UDP DNS query to a loopback
// responder now succeeds when the network is Open and is refused EACCES when
// it is Confined; every other socket-allowlist decision is the same in both.
func TestLinuxSeccompUDPFollowsNetworkPolicy(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	server := startLoopbackDNSResponder(t)
	ws := t.TempDir()
	env := fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{seccompTargetEnv: "1", seccompDNSServerEnv: server}})
	tests := []struct {
		name    string
		policy  policy.Effective
		wantUDP string
	}{
		{
			name:    "open network allows UDP DNS",
			policy:  backendFixturePolicy(fixtureWorkspaceWrite, ws, env, fixtureWithNet(policy.NetPolicy{Open: true}), fixtureWithAckUnconfined()),
			wantUDP: seccompValOK,
		},
		{
			name:    "confined network refuses UDP DNS",
			policy:  backendFixturePolicy(fixtureWorkspaceWrite, ws, env),
			wantUDP: seccompValEACCES,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := newExecutorForEffectivePolicy(tt.policy, withBackend(linux.NewBackend()))
			if err != nil {
				t.Fatalf("NewExecutor: %v", err)
			}
			out, code, err := e.RunArgv(context.Background(), ws, []string{"/proc/self/exe"})
			if err != nil || code != 0 {
				t.Fatalf("probe target: code=%d err=%v out=%q", code, err, out)
			}
			got := parseSeccompMarkers(out)
			if got[seccompKeyUDP] != tt.wantUDP {
				t.Errorf("UDP socket = %q, want %q\n%s", got[seccompKeyUDP], tt.wantUDP, out)
			}
			if got[seccompKeyDNS] != tt.wantUDP {
				t.Errorf("UDP DNS lookup = %q, want %q\n%s", got[seccompKeyDNS], tt.wantUDP, out)
			}
			for _, key := range []string{seccompKeyUnix, seccompKeyVsock, seccompKeySCTP, seccompKeyMPTCP, seccompKeyKeyctl} {
				if got[key] != seccompValEACCES {
					t.Errorf("%s = %q, want %q regardless of network policy\n%s", key, got[key], seccompValEACCES, out)
				}
			}
			for _, key := range []string{seccompKeyTCP, seccompKeySocketpair, seccompKeyNetlink} {
				if got[key] != seccompValOK {
					t.Errorf("%s = %q, want %q regardless of network policy\n%s", key, got[key], seccompValOK, out)
				}
			}
		})
	}
}

// TestLinuxNetOpenGlibcResolves runs the real glibc resolver (getent hosts)
// in a Rung-2 target whose network is Open (review H2). It needs a host that
// can itself resolve an external name, so it skips — with the reason — where
// the parent cannot; the loopback proof above is the deterministic one.
func TestLinuxNetOpenGlibcResolves(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	getent, err := osexec.LookPath("getent")
	if err != nil {
		t.Skipf("getent unavailable: %v", err)
	}
	const name = "example.com"
	if out, err := osexec.Command(getent, "hosts", name).CombinedOutput(); err != nil {
		t.Skipf("the unsandboxed parent cannot resolve %s (%v: %q); no external DNS here", name, err, out)
	}
	ws := t.TempDir()
	e := newFSExecutor(t, backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithNet(policy.NetPolicy{Open: true}), fixtureWithAckUnconfined()))
	out, code, err := e.RunArgv(context.Background(), ws, []string{getent, "hosts", name})
	if err != nil {
		t.Fatalf("RunArgv(getent): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("getent hosts %s under Net.Open exit=%d, want 0 (out=%q)", name, code, out)
	}
}

// TestLinuxSeccompParentUnaffected proves the confinement is child-local: the
// test process (never Seccomp'd) can still open a UDP socket after the Confined
// target ran. A leak would fail this.
func TestLinuxSeccompParentUnaffected(t *testing.T) {
	requireSeccomp(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("parent UDP socket failed (confinement leaked into parent): %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Errorf("close parent fd: %v", err)
	}
}

// TestLinuxSeccompReportEntry asserts both rungs' CompileReport record the
// Seccomp hardening (informational; it does not add a guarantee bit — that is
// earned in 12c), naming the socket() allowlist and whether UDP is admitted
// for that compile (review C2/H1/H2). Compile only: it needs no kernel feature.
func TestLinuxSeccompReportEntry(t *testing.T) {
	ws := t.TempDir()
	tests := []struct {
		name    string
		backend *linux.Backend
		policy  policy.Effective
		wantUDP string
	}{
		{"rung 2 confined refuses UDP", linux.NewBackend(), backendFixturePolicy(fixtureWorkspaceWrite, ws), "UDP is refused"},
		{"rung 2 open admits UDP", linux.NewBackend(), backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithNet(policy.NetPolicy{Open: true}), fixtureWithAckUnconfined()), "UDP (protocol 0/IPPROTO_UDP) is admitted"},
		{"rung 1 admits UDP under nftables", linux.NewBackendRung1(), backendFixturePolicy(fixtureWorkspaceWrite, ws), "UDP (protocol 0/IPPROTO_UDP) is admitted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, report, _, _, err := tt.backend.Compile(tt.policy)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			entries := reportEntriesForFeature(report, "Seccomp-hardening")
			if len(entries) != 1 || entries[0].Status != linuxReportStatusEnforced {
				t.Fatalf("Seccomp-hardening entries = %+v, want one Enforced entry", entries)
			}
			for _, phrase := range []string{"allows socket() only for AF_INET/AF_INET6 SOCK_STREAM TCP and AF_NETLINK NETLINK_ROUTE", "AF_UNIX", "socketpair() stays allowed", "keyctl", tt.wantUDP} {
				if !strings.Contains(entries[0].Detail, phrase) {
					t.Errorf("Seccomp-hardening detail %q missing %q", entries[0].Detail, phrase)
				}
			}
		})
	}
}
