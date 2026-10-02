//go:build linux

package exec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"

	"golang.org/x/sys/unix"
)

// This file proves the Linux side of three review items end to end:
//
//   - C2's escape hatch: profile.UnixSocketPolicy admits AF_UNIX, and what the
//     target can then REACH matches what the compile report and guarantee bits
//     claim, per rung (compile-only tables, then real Rung-1 and Rung-2
//     targets connecting to host sockets the test serves).
//   - M12/L1: every target leads its own session, so it holds no controlling
//     terminal, and TIOCSTI/TIOCLINUX are refused by Seccomp; Landlock's
//     IOCTL_DEV right (ABI >= 5) refuses device ioctls on files it opens.
//   - M13: a HostWrite-Allow Rung-2 supervised target cannot write its own or
//     an ancestor's cgroup files.
//
// The runtime proofs re-run THIS test binary as the confined target (the
// seccomp_linux_test.go pattern): the probe sentinel arrives through the
// policy's Env.Set, so it is present only after the stage-2 execve, and
// unixProbeDispatch runs the probes there and exits.

// Probe sentinels and parameters, all injected through the target env.
const (
	unixProbeEnv         = "LRSANDBOX_UNIX_PROBE"          // "1": run the AF_UNIX probes
	unixProbeLocalDirEnv = "LRSANDBOX_UNIX_PROBE_LOCALDIR" // dir to create+connect a sandbox-local socket in
	unixProbeConnectEnv  = "LRSANDBOX_UNIX_PROBE_CONNECT"  // ':'-separated socket paths to connect to
	unixProbeAbstractEnv = "LRSANDBOX_UNIX_PROBE_ABSTRACT" // abstract name (no '@') to connect to
	ttyProbeEnv          = "LRSANDBOX_TTY_PROBE"           // "1": run the session/TIOCSTI probes
)

// Probe result values.
const (
	probeOK           = "OK"
	probeEACCES       = "EACCES"
	probeEPERM        = "EPERM"
	probeENOENT       = "ENOENT"
	probeENXIO        = "ENXIO"
	probeENOTTY       = "ENOTTY"
	probeECONNREFUSED = "ECONNREFUSED"
)

// unixProbeGreeting is what every host socket the test serves writes on
// accept; a target that reads it reached the real host server.
const unixProbeGreeting = "lrsandbox-hello"

func init() { unixProbeDispatch() }

// unixProbeDispatch runs in the post-execve TARGET only: a probe sentinel is
// set and the stage-2 dispatch sentinel is not (it is scrubbed from the
// target env). Everywhere else it is a no-op.
func unixProbeDispatch() {
	unixProbe := os.Getenv(unixProbeEnv) == "1"
	ttyProbe := os.Getenv(ttyProbeEnv) == "1"
	if !unixProbe && !ttyProbe {
		return
	}
	if os.Getenv(linux.Stage2SentinelEnv) == linux.Stage2SentinelValue {
		return // the stage-2 helper (pre-execve); let Init()/RunStage2 run
	}
	if unixProbe {
		fmt.Printf("SOCKET=%s\n", classifyUnixSocketCreate())
		if dir := os.Getenv(unixProbeLocalDirEnv); dir != "" {
			fmt.Printf("LOCAL=%s\n", probeLocalUnixSocket(dir))
		}
		if list := os.Getenv(unixProbeConnectEnv); list != "" {
			for _, path := range strings.Split(list, ":") {
				fmt.Printf("CONNECT %s=%s\n", path, probeUnixConnect(path))
			}
		}
		if name := os.Getenv(unixProbeAbstractEnv); name != "" {
			fmt.Printf("ABSTRACT=%s\n", probeUnixConnect("@"+name))
		}
	}
	if ttyProbe {
		runTTYProbes()
	}
	os.Exit(0)
}

// classifyErrno renders a probe error as one of the result values, or ERR:.
func classifyErrno(err error) string {
	for _, known := range []struct {
		errno syscall.Errno
		name  string
	}{
		{syscall.EACCES, probeEACCES}, {syscall.EPERM, probeEPERM}, {syscall.ENOENT, probeENOENT},
		{syscall.ENXIO, probeENXIO}, {syscall.ENOTTY, probeENOTTY}, {syscall.ECONNREFUSED, probeECONNREFUSED},
	} {
		if errors.Is(err, known.errno) {
			return known.name
		}
	}
	return "ERR:" + err.Error()
}

// classifyUnixSocketCreate attempts socket(AF_UNIX, SOCK_STREAM): EACCES under
// the default filter, OK under the escape hatch.
func classifyUnixSocketCreate() string {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return classifyErrno(err)
	}
	_ = unix.Close(fd)
	return probeOK
}

// probeLocalUnixSocket is the sandbox-local use the Local mode exists for
// (a forkserver, a test fixture): bind a pathname socket under dir, connect
// to it, and round-trip one byte.
func probeLocalUnixSocket(dir string) string {
	path := filepath.Join(dir, "local.sock")
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return classifyErrno(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_, _ = conn.Write([]byte("x"))
			_ = conn.Close()
		}
	}()
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return classifyErrno(err)
	}
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 'x' {
		return fmt.Sprintf("ERR:round trip %v", err)
	}
	return probeOK
}

// probeUnixConnect connects to a pathname or ("@"-prefixed) abstract socket
// with raw syscalls, so the errno is exactly the kernel's, and on success
// reads the host server's greeting: OK:<greeting> proves the real server was
// reached.
func probeUnixConnect(name string) string {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "SOCKET:" + classifyErrno(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		return classifyErrno(err)
	}
	buf := make([]byte, len(unixProbeGreeting))
	file := os.NewFile(uintptr(fd), "probe")
	n, err := io.ReadFull(file, buf)
	if err != nil {
		return fmt.Sprintf("ERR:read %d %v", n, err)
	}
	return probeOK + ":" + string(buf)
}

// runTTYProbes reports the target's session position and what its terminal
// ioctls do. SESSION=LEADER means getsid(0) == getpid() (stage 2's setsid);
// DEVTTY is the read-only open of /dev/tty, which fails ENXIO without a controlling
// terminal; TIOCSTI/TIOCLINUX run on stdin and must be refused EACCES by the
// filter (a non-tty stdin would otherwise answer ENOTTY); TCGETS on stdin is
// the positive control that ioctl is not blanket-denied; DEVNULL_TCGETS runs
// TCGETS on a /dev/null the TARGET opens, which Landlock's IOCTL_DEV (ABI >=
// 5) refuses EACCES and an older kernel answers ENOTTY.
func runTTYProbes() {
	sid, err := unix.Getsid(0)
	switch {
	case err != nil:
		fmt.Printf("SESSION=ERR:%v\n", err)
	case sid == unix.Getpid():
		fmt.Println("SESSION=LEADER")
	default:
		fmt.Printf("SESSION=FOLLOWER sid=%d pid=%d\n", sid, unix.Getpid())
	}
	// O_RDONLY: a host-read policy grants read on /dev, so the open reaches
	// the tty driver, whose answer (ENXIO: no controlling terminal) is the
	// thing under test; O_RDWR would stop at Landlock's write denial first.
	if fd, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0); err != nil {
		fmt.Printf("DEVTTY=%s\n", classifyErrno(err))
	} else {
		_ = unix.Close(fd)
		fmt.Println("DEVTTY=OK")
	}
	char := byte('x')
	fmt.Printf("TIOCSTI=%s\n", classifyIoctl(0, linux.IoctlTIOCSTI, uintptr(unsafe.Pointer(&char))))
	fmt.Printf("TIOCLINUX=%s\n", classifyIoctl(0, linux.IoctlTIOCLINUX, uintptr(unsafe.Pointer(&char))))
	var termios unix.Termios
	fmt.Printf("TCGETS=%s\n", classifyIoctl(0, unix.TCGETS, uintptr(unsafe.Pointer(&termios))))
	if fd, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0); err != nil {
		fmt.Printf("DEVNULL_TCGETS=OPEN:%s\n", classifyErrno(err))
	} else {
		fmt.Printf("DEVNULL_TCGETS=%s\n", classifyIoctl(fd, unix.TCGETS, uintptr(unsafe.Pointer(&termios))))
		_ = unix.Close(fd)
	}
}

func classifyIoctl(fd int, request uint, arg uintptr) string {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), arg)
	if errno == 0 {
		return probeOK
	}
	return classifyErrno(errno)
}

// serveUnixGreeting listens on a pathname (or "@"-prefixed abstract) socket
// in THIS (unconfined) test process and writes unixProbeGreeting to every
// connection, so a target that reads it provably reached the host server.
func serveUnixGreeting(t *testing.T, name string) {
	t.Helper()
	listener, err := net.Listen("unix", name)
	if err != nil {
		t.Fatalf("listen %s: %v", name, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte(unixProbeGreeting))
			_ = conn.Close()
		}
	}()
}

// shortTempDir is a short-pathed temp dir: sun_path holds 108 bytes, and
// t.TempDir's test-named paths can exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "lrsu")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	return resolved
}

// localSocketDir creates the pre-existing workspace subdirectory a probe binds
// its sandbox-local socket in. A writable root with read-only carveouts
// (.git/.looprig) is granted by enumerating its children at spawn, so a NEW
// entry directly at the root is refused by design (snapshot semantics,
// §7.5); a socket the target creates inside an existing writable child is
// the ordinary case the Local mode serves.
func localSocketDir(t *testing.T, ws string) string {
	t.Helper()
	dir := filepath.Join(ws, "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	return dir
}

// rung1ProbeWorkspace prepares a Rung-1 workspace for a scoped-runtime policy:
// the .git/.looprig carveouts fixtureWithWritable protects (an absent one
// beneath a writable bind fails the spawn closed), and a copy of this test
// binary, because a scoped view neither shows nor lets Landlock execute the
// original under the Go build cache.
func rung1ProbeWorkspace(t *testing.T) (string, string) {
	t.Helper()
	ws := shortTempDir(t)
	for _, dir := range []string{".git", ".looprig"} {
		if err := os.Mkdir(filepath.Join(ws, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read test binary: %v", err)
	}
	probe := filepath.Join(ws, "probe.test")
	if err := os.WriteFile(probe, data, 0o755); err != nil {
		t.Fatalf("copy test binary: %v", err)
	}
	return ws, probe
}

// withUnixSockets sets the effective policy's escape hatch.
func withUnixSockets(u profile.UnixSocketPolicy) backendFixtureOption {
	return func(p *policy.Effective) { p.UnixSockets = u }
}

// parseProbeMarkers turns KEY=VALUE lines into a map (a key may contain
// spaces: "CONNECT <path>").
func parseProbeMarkers(out []byte) map[string]string {
	markers := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		if key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "="); ok {
			markers[key] = value
		}
	}
	return markers
}

// --- compile-time contract ----------------------------------------------------

// TestLinuxUnixSocketCompileOutcomes pins, per rung and mode, the
// unix-sockets report rows and the guarantee/level outcome the backend claims
// (review C2). Compile only: it needs no kernel feature, but the Landlock ABI
// the compile probes decides whether abstract names are scoped, so the
// expectations that depend on it branch on the same probe.
func TestLinuxUnixSocketCompileOutcomes(t *testing.T) {
	t.Parallel()
	ws := shortTempDir(t)
	hostDir := shortTempDir(t)
	agent := filepath.Join(hostDir, "agent.sock")
	serveUnixGreeting(t, agent)
	missing := filepath.Join(hostDir, "absent.sock")
	const bus = "/run/user/1000/bus"
	abi := linux.ProbeLandlockABI()
	scoped := abi >= 6

	scopedWrite := func(opts ...backendFixtureOption) policy.Effective {
		return backendFixturePolicy(fixtureScopedRuntime, ws, append([]backendFixtureOption{fixtureWithWritable(ws)}, opts...)...)
	}
	type outcome struct {
		status       string   // unix-sockets status; "" = no entry at all
		detail       []string // phrases the unix-sockets detail must carry
		dangerous    []string // paths that must carry a unix-sockets.dangerous row
		processBound bool     // GuaranteeProcessBoundary set
		level        uint8
	}
	tests := []struct {
		name    string
		backend *linux.Backend
		policy  policy.Effective
		want    outcome
	}{
		{
			name:    "rung 1 default policy reports nothing new",
			backend: linux.NewBackendRung1(),
			policy:  scopedWrite(),
			want:    outcome{processBound: true, level: LevelFull},
		},
		{
			name:    "rung 1 local in a scoped view with a netns is Enforced",
			backend: linux.NewBackendRung1(),
			policy:  scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})),
			want: outcome{status: "Enforced", processBound: true, level: LevelFull,
				detail: []string{"local: pathname sockets limited to the mount view, abstract names isolated by the network namespace, socketpair"}},
		},
		{
			name:    "rung 1 local under a host-read root bind is narrowed",
			backend: linux.NewBackendRung1(),
			policy:  backendFixturePolicy(fixtureWorkspaceWrite, ws, withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})),
			want: outcome{status: "narrowed", processBound: false, level: LevelDegraded,
				detail: []string{`host sockets visible through the "/" bind`}},
		},
		{
			name:    "rung 1 local binding /run is narrowed",
			backend: linux.NewBackendRung1(),
			policy: scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal}),
				func(p *policy.Effective) {
					p.FS = append(p.FS, policy.FSEntry{Path: "/run", Access: policy.ReadAccess})
				}),
			want: outcome{status: "narrowed", processBound: false, level: LevelDegraded,
				detail: []string{`host sockets visible through the "/run" bind`}},
		},
		{
			name:    "rung 1 paths to a plain host socket keep the process boundary",
			backend: linux.NewBackendRung1(),
			policy:  scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Paths: []string{agent}})),
			want: outcome{status: "Enforced", processBound: true, level: LevelFull,
				detail: []string{"paths only: pathname sockets limited to the mount view", "paths: " + agent, "bound read-only into the mount view as the exact socket file"}},
		},
		{
			name:    "rung 1 a missing named path is narrowed but widens nothing",
			backend: linux.NewBackendRung1(),
			policy:  scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Paths: []string{missing}})),
			want: outcome{status: "narrowed", processBound: true, level: LevelFull,
				detail: []string{"not a socket at compile time", missing}},
		},
		{
			name:    "rung 1 a dangerous named path withholds the process boundary",
			backend: linux.NewBackendRung1(),
			policy:  scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Paths: []string{bus}})),
			want: outcome{status: "narrowed", processBound: false, level: LevelDegraded,
				dangerous: []string{bus}},
		},
		{
			name:    "rung 2 local is narrowed",
			backend: linux.NewBackend(),
			policy:  backendFixturePolicy(fixtureWorkspaceWrite, ws, withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})),
			want: outcome{status: "narrowed", processBound: false, level: LevelDegraded,
				detail: []string{"every same-user pathname socket is reachable", "D-Bus session bus (/run/user/$UID/bus)", "systemd user manager (/run/user/$UID/systemd/private)"}},
		},
		{
			name:    "rung 2 paths is narrowed and flags the session bus",
			backend: linux.NewBackend(),
			policy:  backendFixturePolicy(fixtureWorkspaceWrite, ws, withUnixSockets(profile.UnixSocketPolicy{Paths: []string{agent, bus}})),
			want: outcome{status: "narrowed", processBound: false, level: LevelDegraded,
				detail: []string{"every same-user pathname socket is reachable"}, dangerous: []string{bus}},
		},
	}
	// Net.Open removes Rung 1's netns: abstract names are then confined only
	// by Landlock scoping, which this kernel may or may not have.
	openLocal := outcome{status: "narrowed", processBound: false, level: LevelDegraded,
		detail: []string{"abstract namespace shared with the host"}}
	if scoped {
		openLocal = outcome{status: "Enforced", processBound: true, level: LevelFull,
			detail: []string{"local: pathname sockets limited to the mount view, abstract names confined to sockets created inside this sandbox by Landlock abstract-socket scoping"}}
	}
	tests = append(tests, struct {
		name    string
		backend *linux.Backend
		policy  policy.Effective
		want    outcome
	}{
		name:    fmt.Sprintf("rung 1 local with an open network (Landlock ABI %d)", abi),
		backend: linux.NewBackendRung1(),
		policy:  scopedWrite(withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal}), fixtureWithNet(policy.NetPolicy{Open: true})),
		want:    openLocal,
	})
	rung2Abstract := "abstract names are NOT confined"
	if scoped {
		rung2Abstract = "abstract names confined to sockets created inside this sandbox by Landlock abstract-socket scoping"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, report, level, bits, err := tt.backend.Compile(tt.policy)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			entries := reportEntriesForFeature(report, "unix-sockets")
			if tt.want.status == "" {
				if len(entries) != 0 {
					t.Errorf("default policy reported unix-sockets: %+v", entries)
				}
			} else {
				if len(entries) != 1 || entries[0].Status != tt.want.status {
					t.Fatalf("unix-sockets entries = %+v, want one %q entry", entries, tt.want.status)
				}
				for _, phrase := range tt.want.detail {
					if !strings.Contains(entries[0].Detail, phrase) {
						t.Errorf("unix-sockets detail %q missing %q", entries[0].Detail, phrase)
					}
				}
				if tt.backend.Rung == linux.RungTwo && !strings.Contains(entries[0].Detail, rung2Abstract) {
					t.Errorf("rung-2 unix-sockets detail %q missing %q", entries[0].Detail, rung2Abstract)
				}
			}
			dangerous := reportEntriesForFeature(report, "unix-sockets.dangerous")
			if len(dangerous) != len(tt.want.dangerous) {
				t.Fatalf("unix-sockets.dangerous entries = %+v, want %d", dangerous, len(tt.want.dangerous))
			}
			for i, path := range tt.want.dangerous {
				if dangerous[i].Status != "narrowed" || !strings.HasPrefix(dangerous[i].Detail, path+": ") || !strings.Contains(dangerous[i].Detail, "D-Bus session bus") {
					t.Errorf("unix-sockets.dangerous[%d] = %+v, want a narrowed row naming %s and its reason", i, dangerous[i], path)
				}
			}
			if got := bits&GuaranteeProcessBoundary != 0; got != tt.want.processBound {
				t.Errorf("GuaranteeProcessBoundary = %t, want %t (bits %#x)", got, tt.want.processBound, bits)
			}
			if level != tt.want.level {
				t.Errorf("level = %d, want %d", level, tt.want.level)
			}
			seccomp := reportEntriesForFeature(report, "Seccomp-hardening")
			if len(seccomp) != 1 {
				t.Fatalf("Seccomp-hardening entries = %+v", seccomp)
			}
			wantSeccomp := "AF_UNIX pathname/abstract sockets (D-Bus, ssh-agent, docker.sock) are refused"
			if tt.want.status != "" {
				wantSeccomp = "AF_UNIX stream/datagram/seqpacket sockets are admitted by the profile's UnixSocketPolicy escape hatch"
			}
			for _, phrase := range []string{wantSeccomp, "TIOCSTI/TIOCLINUX", "its own session"} {
				if !strings.Contains(seccomp[0].Detail, phrase) {
					t.Errorf("Seccomp-hardening detail %q missing %q", seccomp[0].Detail, phrase)
				}
			}
		})
	}
}

// --- runtime proofs -------------------------------------------------------------

// TestLinuxUnixSocketRung1Endpoints runs real Rung-1 targets (review C2): the
// default policy still refuses socket(AF_UNIX); Local lets the target serve
// and reach its own socket in its workspace while a host socket outside the
// view is ENOENT and a host abstract name is unreachable through the netns;
// a Paths grant reaches exactly the named host socket — its sibling in the
// same host directory stays invisible — with HostRead Deny.
func TestLinuxUnixSocketRung1Endpoints(t *testing.T) {
	requireRung1Caps(t)
	requireSeccomp(t)

	hostDir := shortTempDir(t)
	granted := filepath.Join(hostDir, "agent.sock")
	sibling := filepath.Join(hostDir, "other.sock")
	serveUnixGreeting(t, granted)
	serveUnixGreeting(t, sibling)
	abstract := fmt.Sprintf("lrsandbox-%d-%d", os.Getpid(), time.Now().UnixNano())
	serveUnixGreeting(t, "@"+abstract)

	tests := []struct {
		name    string
		sockets profile.UnixSocketPolicy
		want    map[string]string // marker key -> exact value (or prefix for OK:)
	}{
		{
			name: "default policy refuses AF_UNIX",
			want: map[string]string{"SOCKET": probeEACCES},
		},
		{
			name:    "local reaches only sandbox-local endpoints",
			sockets: profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal},
			want: map[string]string{
				"SOCKET":             probeOK,
				"LOCAL":              probeOK,
				"CONNECT " + granted: probeENOENT,
				"CONNECT " + sibling: probeENOENT,
				"ABSTRACT":           probeECONNREFUSED,
			},
		},
		{
			name:    "paths reach exactly the named host socket",
			sockets: profile.UnixSocketPolicy{Paths: []string{granted}},
			want: map[string]string{
				"SOCKET":             probeOK,
				"CONNECT " + granted: probeOK + ":" + unixProbeGreeting,
				"CONNECT " + sibling: probeENOENT,
				"ABSTRACT":           probeECONNREFUSED,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws, probe := rung1ProbeWorkspace(t)
			env := fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{
				unixProbeEnv:         "1",
				unixProbeLocalDirEnv: localSocketDir(t, ws),
				unixProbeConnectEnv:  granted + ":" + sibling,
				unixProbeAbstractEnv: abstract,
			}})
			p := backendFixturePolicy(fixtureScopedRuntime, ws, fixtureWithWritable(ws), env, withUnixSockets(tt.sockets))
			e, err := newExecutorForEffectivePolicy(p, withBackend(linux.NewBackendRung1()))
			if err != nil {
				t.Fatalf("NewExecutor: %v", err)
			}
			if tt.sockets.Mode != profile.UnixSocketsDenied || len(tt.sockets.Paths) > 0 {
				if e.GuaranteeBits()&GuaranteeProcessBoundary == 0 || e.Level() != LevelFull {
					t.Fatalf("confined escape hatch lost the process boundary: level=%d bits=%#x", e.Level(), e.GuaranteeBits())
				}
			}
			out, code, err := e.RunArgv(context.Background(), ws, []string{probe})
			if err != nil || code != 0 {
				t.Fatalf("probe target: code=%d err=%v out=%q", code, err, out)
			}
			got := parseProbeMarkers(out)
			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("%s = %q, want %q\nfull target output:\n%s", key, got[key], want, out)
				}
			}
		})
	}
}

// TestLinuxUnixSocketRung2Reach runs a real Rung-2 target under the escape
// hatch and proves the report is honest (review C2): a host pathname socket
// IS reachable (Rung 2 has no view — reported narrowed, process boundary not
// claimed), the target's own socket works, and a host abstract name is
// refused EPERM by Landlock's abstract-socket scope when the kernel has ABI
// >= 6 (reachable otherwise, as the report then says).
func TestLinuxUnixSocketRung2Reach(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)

	hostDir := shortTempDir(t)
	hostSocket := filepath.Join(hostDir, "agent.sock")
	serveUnixGreeting(t, hostSocket)
	abstract := fmt.Sprintf("lrsandbox-r2-%d-%d", os.Getpid(), time.Now().UnixNano())
	serveUnixGreeting(t, "@"+abstract)
	ws := shortTempDir(t)
	env := fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{
		unixProbeEnv:         "1",
		unixProbeLocalDirEnv: localSocketDir(t, ws),
		unixProbeConnectEnv:  hostSocket,
		unixProbeAbstractEnv: abstract,
	}})
	e, err := newExecutorForEffectivePolicy(
		backendFixturePolicy(fixtureWorkspaceWrite, ws, env, withUnixSockets(profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})),
		withBackend(linux.NewBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if e.GuaranteeBits()&GuaranteeProcessBoundary != 0 || e.Level() != LevelDegraded {
		t.Fatalf("rung 2 escape hatch: level=%d bits=%#x, want Degraded without ProcessBoundary", e.Level(), e.GuaranteeBits())
	}
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/proc/self/exe"})
	if err != nil || code != 0 {
		t.Fatalf("probe target: code=%d err=%v out=%q", code, err, out)
	}
	got := parseProbeMarkers(out)
	wantAbstract := probeOK + ":" + unixProbeGreeting
	if linux.ProbeLandlockABI() >= 6 {
		wantAbstract = probeEPERM
	}
	for key, want := range map[string]string{
		"SOCKET":                probeOK,
		"LOCAL":                 probeOK,
		"CONNECT " + hostSocket: probeOK + ":" + unixProbeGreeting,
		"ABSTRACT":              wantAbstract,
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q\nfull target output:\n%s", key, got[key], want, out)
		}
	}
}

// TestLinuxTargetHasNoControllingTerminal is the review M12/L1 runtime proof
// on both rungs: the target leads its own session (so /dev/tty is ENXIO — no
// controlling terminal to inject into), TIOCSTI and TIOCLINUX are refused
// EACCES by the filter, an ordinary terminal ioctl still reaches the kernel,
// and a device ioctl on a /dev/null the target opens itself is refused by
// Landlock's IOCTL_DEV right where the kernel has ABI >= 5.
func TestLinuxTargetHasNoControllingTerminal(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	wantDevNull := probeENOTTY
	if linux.ProbeLandlockABI() >= 5 {
		wantDevNull = probeEACCES
	}
	run := func(t *testing.T, e *Executor, ws, target string) {
		t.Helper()
		out, code, err := e.RunArgv(context.Background(), ws, []string{target})
		if err != nil || code != 0 {
			t.Fatalf("probe target: code=%d err=%v out=%q", code, err, out)
		}
		got := parseProbeMarkers(out)
		for key, want := range map[string]string{
			"SESSION":        "LEADER",
			"DEVTTY":         probeENXIO,
			"TIOCSTI":        probeEACCES,
			"TIOCLINUX":      probeEACCES,
			"TCGETS":         probeENOTTY,
			"DEVNULL_TCGETS": wantDevNull,
		} {
			if got[key] != want {
				t.Errorf("%s = %q, want %q\nfull target output:\n%s", key, got[key], want, out)
			}
		}
	}
	env := fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{ttyProbeEnv: "1"}})
	t.Run("rung 2", func(t *testing.T) {
		ws := t.TempDir()
		e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws, env), withBackend(linux.NewBackend()))
		if err != nil {
			t.Fatalf("NewExecutor: %v", err)
		}
		run(t, e, ws, "/proc/self/exe")
	})
	t.Run("rung 1", func(t *testing.T) {
		requireRung1Caps(t)
		ws, probe := rung1ProbeWorkspace(t)
		e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureHostRead, ws, fixtureWithWritable(ws), env), withBackend(linux.NewBackendRung1()))
		if err != nil {
			t.Fatalf("NewExecutor: %v", err)
		}
		run(t, e, ws, probe)
	})
}

// --- review M13 -------------------------------------------------------------------

// withHostWrite turns the fixture's "/" read grant into the HostWrite-Allow
// shape: read, write and execute on the whole host root.
func withHostWrite() backendFixtureOption {
	return func(p *policy.Effective) {
		for i := range p.FS {
			if p.FS[i].Path == "/" && p.FS[i].Access != 0 {
				p.FS[i].Access = policy.AllAccess
			}
		}
	}
}

// TestLinuxCgroupCarveoutReported pins the M13 compile outcome: a
// HostWrite-Allow policy gets a cgroup-write-carveout row on both rungs and no
// write-boundary claim it did not make; a policy without host write gets
// neither.
func TestLinuxCgroupCarveoutReported(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/sys/fs/cgroup"); err != nil {
		t.Skipf("no cgroup hierarchy mounted: %v", err)
	}
	ws := t.TempDir()
	for _, backend := range []*linux.Backend{linux.NewBackend(), linux.NewBackendRung1()} {
		_, report, _, bits, err := backend.Compile(backendFixturePolicy(fixtureWorkspaceWrite, ws, withHostWrite(), fixtureWithoutSecretDenials()))
		if err != nil {
			t.Fatalf("rung %d compile: %v", backend.Rung, err)
		}
		carveouts := reportEntriesForFeature(report, "cgroup-write-carveout")
		if len(carveouts) != 1 || carveouts[0].Status != "Enforced" || !strings.Contains(carveouts[0].Detail, "/sys/fs/cgroup") || !strings.Contains(carveouts[0].Detail, "cgroup.procs") {
			t.Errorf("rung %d host-write cgroup-write-carveout = %+v, want one Enforced row naming /sys/fs/cgroup and cgroup.procs", backend.Rung, carveouts)
		}
		if bits&GuaranteeWriteBoundary != 0 {
			t.Errorf("rung %d: the cgroup carveout manufactured a write-boundary claim (bits %#x)", backend.Rung, bits)
		}
		_, report, _, _, err = backend.Compile(backendFixturePolicy(fixtureWorkspaceWrite, ws))
		if err != nil {
			t.Fatalf("rung %d compile: %v", backend.Rung, err)
		}
		if got := reportEntriesForFeature(report, "cgroup-write-carveout"); len(got) != 0 {
			t.Errorf("rung %d without host write reported a carveout: %+v", backend.Rung, got)
		}
	}
}

// TestLinuxSupervisedRung2CannotWriteItsCgroup is the M13 runtime proof: a
// SUPERVISED Rung-2 target whose policy grants write on "/" — so it can write
// the host (the positive control) — cannot write its own lifetime scope's
// pids.max, its own cgroup.procs, or the delegated ancestor's cgroup.procs
// (EACCES from Landlock), so it cannot leave the scope whose cgroup.kill +
// empty read is the LifetimeContainment=Enforced proof, nor lift its limits.
func TestLinuxSupervisedRung2CannotWriteItsCgroup(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ancestor := requireLifetimeCgroupForExecTest(t)
	ws := t.TempDir()
	hostFile := filepath.Join(shortTempDir(t), "host-write-control")
	// The test process's own cgroup is a populated leaf outside the target's
	// lifetime scope: a target that could write its pid there would leave the
	// scope whose cgroup.kill + empty read proves teardown (the M13 escape).
	harnessCgroup := harnessCgroupProcs(t)
	script := strings.Join([]string{
		`cg=$(sed -n 's/^0:://p' /proc/self/cgroup)`,
		`echo "CG=$cg"`,
		`try() { if out=$( { echo "$2" > "$3"; } 2>&1 ); then echo "$1=WRITTEN"; else case "$out" in *"Permission denied"*) echo "$1=EACCES";; *) echo "$1=ERR:$out";; esac; fi; }`,
		`try HOST_WRITE ok ` + shq(hostFile),
		`try OWN_PIDS_MAX 100000 "/sys/fs/cgroup$cg/pids.max"`,
		`try OWN_PROCS $$ "/sys/fs/cgroup$cg/cgroup.procs"`,
		`try ANCESTOR_PROCS $$ ` + shq(filepath.Join(ancestor, "cgroup.procs")),
		`try ROOT_PROCS $$ /sys/fs/cgroup/cgroup.procs`,
		`try ESCAPE_PROCS $$ ` + shq(harnessCgroup),
	}, "\n")
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws, withHostWrite()), withBackend(linux.NewBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	prepared, err := e.PrepareProcess(context.Background(), ProcessOptions{Directory: ws, Command: script, ExecutionID: "cgroup-carveout"})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := proc.LifetimeContainment(); got != LifetimeContainmentEnforced {
		t.Fatalf("LifetimeContainment = %v, want Enforced", got)
	}
	out, readErr := io.ReadAll(proc.Stdout())
	result, err := proc.Wait(context.Background())
	if readErr != nil || err != nil || result.ExitCode != 0 {
		t.Fatalf("supervised target: exit=%d wait=%v read=%v out=%q", result.ExitCode, err, readErr, out)
	}
	got := parseProbeMarkers(out)
	if !strings.HasPrefix(got["CG"], "/") || !strings.Contains(got["CG"], linux.CgroupScopePrefix) {
		t.Fatalf("target is not in a transient lifetime scope: CG=%q\n%s", got["CG"], out)
	}
	for key, want := range map[string]string{
		"HOST_WRITE":     "WRITTEN",
		"OWN_PIDS_MAX":   probeEACCES,
		"OWN_PROCS":      probeEACCES,
		"ANCESTOR_PROCS": probeEACCES,
		"ROOT_PROCS":     probeEACCES,
		"ESCAPE_PROCS":   probeEACCES,
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q\nfull target output:\n%s", key, got[key], want, out)
		}
	}
}

// harnessCgroupProcs is the cgroup.procs file of this test process's own
// cgroup v2 node.
func harnessCgroupProcs(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read /proc/self/cgroup: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rest, "cgroup.procs")
		}
	}
	t.Fatalf("no cgroup v2 entry in /proc/self/cgroup: %q", data)
	return ""
}
