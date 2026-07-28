//go:build linux

package exec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

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

// TestBuildSeccompFilterStructure runs the shipped filter through the interpreter
// for the full anti-fail-open table: every denial (UDP, MPTCP, ptrace, io_uring),
// the arch/x32 kill guards, and the positive-control allows (TCP, AF_UNIX, and
// unrelated syscalls). SOCK_CLOEXEC-flagged types exercise the 0xff mask.
func TestBuildSeccompFilterStructure(t *testing.T) {
	t.Parallel()
	prog := linux.BuildSeccompFilter()

	const (
		x86      = uint32(unix.AUDIT_ARCH_X86_64)
		i386     = uint32(unix.AUDIT_ARCH_I386)
		retErrno = unix.SECCOMP_RET_ERRNO | (uint32(unix.EACCES) & unix.SECCOMP_RET_DATA)
	)
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	kill := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	dgram := uint64(unix.SOCK_DGRAM)
	stream := uint64(unix.SOCK_STREAM)
	cloexec := uint64(unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK)

	tests := []struct {
		name string
		arch uint32
		nr   uint32
		args [6]uint64
		want uint32
	}{
		// Kill guards (anti-fail-open, fail-closed).
		{"i386 arch killed", i386, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, stream, 0}, kill},
		{"x32 socket killed", x86, unix.SYS_SOCKET | linux.SeccompX32SyscallBit, [6]uint64{unix.AF_INET, dgram, 0}, kill},
		{"x32 write killed", x86, 1 | linux.SeccompX32SyscallBit, [6]uint64{}, kill},
		// UDP denials.
		{"AF_INET dgram denied", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, dgram, 0}, retErrno},
		{"AF_INET6 dgram denied", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET6, dgram, 0}, retErrno},
		{"AF_INET dgram with CLOEXEC flags denied (mask)", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, dgram | cloexec, 0}, retErrno},
		// MPTCP denials.
		{"AF_INET stream MPTCP denied", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, stream, uint64(linux.IPProtoMPTCP)}, retErrno},
		{"AF_INET6 stream MPTCP denied", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET6, stream, uint64(linux.IPProtoMPTCP)}, retErrno},
		{"AF_INET stream MPTCP with CLOEXEC denied", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, stream | cloexec, uint64(linux.IPProtoMPTCP)}, retErrno},
		// nr-only denials.
		{"ptrace denied", x86, unix.SYS_PTRACE, [6]uint64{}, retErrno},
		{"io_uring_setup denied", x86, unix.SYS_IO_URING_SETUP, [6]uint64{}, retErrno},
		{"io_uring_enter denied", x86, unix.SYS_IO_URING_ENTER, [6]uint64{}, retErrno},
		{"io_uring_register denied", x86, unix.SYS_IO_URING_REGISTER, [6]uint64{}, retErrno},
		// Positive controls (must ALLOW, else the filter is a blanket ban).
		{"AF_INET stream TCP allowed", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, stream, 0}, allow},
		{"AF_INET stream TCP with CLOEXEC allowed", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET, stream | cloexec, 0}, allow},
		{"AF_INET6 stream TCP allowed", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_INET6, stream, 0}, allow},
		{"AF_UNIX stream allowed", x86, unix.SYS_SOCKET, [6]uint64{unix.AF_UNIX, stream, 0}, allow},
		{"unrelated syscall allowed", x86, 1 /* write */, [6]uint64{}, allow},
		{"openat allowed", x86, unix.SYS_OPENAT, [6]uint64{}, allow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := runBPF(t, prog, seccompData(tt.arch, tt.nr, tt.args))
			if got != tt.want {
				t.Errorf("filter(%s) = %#x, want %#x", tt.name, got, tt.want)
			}
		})
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
// parent asserts on. This proves UDP + MPTCP + ptrace + io_uring are denied while
// TCP works — in a real post-execve target, composed with Landlock.

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
	seccompValOK      = "OK"
	seccompValEACCES  = "EACCES"
)

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
// linux.Backend stage-2 (Landlock + Seccomp), a post-execve target has UDP, MPTCP,
// ptrace, and io_uring denied with EACCES while plain TCP still works. The
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
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got[c.key] != c.want {
				t.Errorf("target %s = %q, want %q\nfull target output:\n%s", c.key, got[c.key], c.want, out)
			}
		})
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

// TestLinuxSeccompReportEntry asserts the rung-2 CompileReport records the
// Seccomp hardening (informational; it does not add a guarantee bit — that is
// earned in 12c).
func TestLinuxSeccompReportEntry(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ws := t.TempDir()
	e := newFSExecutor(t, backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if !reportHas(e.Report(), "Seccomp-hardening", linuxReportStatusEnforced) {
		t.Errorf("CompileReport missing Seccomp-hardening/Enforced entry; report=%+v", e.Report())
	}
}
