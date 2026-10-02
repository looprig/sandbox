//go:build darwin

package exec

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox/pkg/profile"
)

// Real-Seatbelt proof of the AF_UNIX contract (profile.UnixSocketPolicy):
// REAL executors built through ExecutorSet from a REAL Profile (so
// policy.Compile, the executor-owned HOME/TMPDIR roots and the Seatbelt
// compile all run), a perl client inside sandbox-exec, and Go servers in the
// unsandboxed test process — one inside the workspace (a writable root) and
// one in a sibling directory that no root covers.
//
// Paths are kept short on purpose: sun_path is 104 bytes on darwin, and a
// t.TempDir() under /var/folders/... plus the /private prefix Seatbelt
// resolves it to comes close. Every directory is made under /tmp (which the
// kernel resolves to /private/tmp, exercising the canonical-spelling rules)
// and removed by t.Cleanup.

// unixPongServer listens on path and answers every connection with "pong".
func unixPongServer(t *testing.T, path string) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("pong\n"))
			_ = conn.Close()
		}
	}()
	// Positive control: the endpoint is live for an unsandboxed client, so a
	// sandboxed failure below is attributable to Seatbelt, not a dead socket.
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatalf("control dial %s: %v", path, err)
	}
	line, _ := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if line != "pong\n" {
		t.Fatalf("control dial %s read %q", path, line)
	}
}

// shortTempDir makes a short-named directory under /tmp.
func shortTempDir(t *testing.T, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// perlUnixConnect is a sandboxed AF_UNIX client: it prints "connected: pong"
// on success and exits 1 with the errno text otherwise.
func perlUnixConnect(path string) string {
	return `/usr/bin/perl -MSocket -e 'socket(S,PF_UNIX,SOCK_STREAM,0) or die "socket: $!\n"; connect(S,pack_sockaddr_un($ARGV[0])) or die "connect: $!\n"; my $l=<S>; print "connected: $l"' ` + portableShellQuote(path)
}

// perlUnixBind binds (and listens on) a fresh pathname socket.
func perlUnixBind(path string) string { return perlUnixBindWord(portableShellQuote(path)) }

// perlUnixBindWord is perlUnixBind with the path given as a raw shell word,
// so it may expand a variable such as "$TMPDIR".
func perlUnixBindWord(word string) string {
	return `/usr/bin/perl -MSocket -e 'socket(S,PF_UNIX,SOCK_STREAM,0) or die "socket: $!\n"; bind(S,pack_sockaddr_un($ARGV[0])) or die "bind: $!\n"; listen(S,1) or die "listen: $!\n"; print "bound\n"' ` + word
}

type unixSocketFixture struct {
	workspace string
	inside    string // a live socket inside the (writable) workspace
	outside   string // a live socket in a directory no root covers
}

func newUnixSocketFixture(t *testing.T) unixSocketFixture {
	t.Helper()
	ws := shortTempDir(t, "uw")
	out := shortTempDir(t, "uo")
	fixture := unixSocketFixture{workspace: ws, inside: filepath.Join(ws, "in.sock"), outside: filepath.Join(out, "out.sock")}
	unixPongServer(t, fixture.inside)
	unixPongServer(t, fixture.outside)
	return fixture
}

func unixSocketExecutor(t *testing.T, ws string, sockets profile.UnixSocketPolicy) *Executor {
	t.Helper()
	prof := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: ws, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Allow, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
		UnixSockets: sockets,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(shortTempDir(t, "us")), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("unix")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	return executor
}

func runUnixProbe(t *testing.T, e *Executor, ws, command string) (string, bool) {
	t.Helper()
	out, code, err := e.RunCommand(context.Background(), ws, command)
	if err != nil {
		t.Fatalf("probe %q: spawn error %v (out=%s)", command, err, out)
	}
	return string(out), code == 0
}

func expectConnect(t *testing.T, e *Executor, ws, path string, want bool) {
	t.Helper()
	out, ok := runUnixProbe(t, e, ws, perlUnixConnect(path))
	if ok != want || (want && !strings.Contains(out, "connected: pong")) {
		t.Errorf("connect %s: success=%v, want %v (out=%q)", path, ok, want, out)
	}
	if !want && !strings.Contains(out, "Operation not permitted") {
		t.Errorf("connect %s failed for a reason other than the sandbox: %q", path, out)
	}
}

// TestSeatbeltEnforceUnixSocketsDefaultDenied: the zero policy denies a
// connect to both live sockets — even the one inside the workspace — while
// socketpair() (anonymous IPC, which the contract leaves alone) still works.
func TestSeatbeltEnforceUnixSocketsDefaultDenied(t *testing.T) {
	requireSandboxExec(t)
	fixture := newUnixSocketFixture(t)
	e := unixSocketExecutor(t, fixture.workspace, profile.UnixSocketPolicy{})
	expectConnect(t, e, fixture.workspace, fixture.inside, false)
	expectConnect(t, e, fixture.workspace, fixture.outside, false)
	out, ok := runUnixProbe(t, e, fixture.workspace, `/usr/bin/perl -MSocket -e 'socketpair(A,B,AF_UNIX,SOCK_STREAM,PF_UNSPEC) or die "socketpair: $!\n"; print "pair ok\n"'`)
	if !ok || !strings.Contains(out, "pair ok") {
		t.Errorf("socketpair under the default policy: ok=%v out=%q, want it to work", ok, out)
	}
}

// TestSeatbeltEnforceUnixSocketsLocal: Local mode reaches the socket inside
// the writable workspace (through both its /tmp and /private/tmp
// spellings), can bind a new one there and in its own TMPDIR, and still
// cannot reach the socket outside every writable root.
func TestSeatbeltEnforceUnixSocketsLocal(t *testing.T) {
	requireSandboxExec(t)
	fixture := newUnixSocketFixture(t)
	e := unixSocketExecutor(t, fixture.workspace, profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})
	expectConnect(t, e, fixture.workspace, fixture.inside, true)
	expectConnect(t, e, fixture.workspace, filepath.Join("/private", fixture.inside), true)
	expectConnect(t, e, fixture.workspace, fixture.outside, false)

	out, ok := runUnixProbe(t, e, fixture.workspace, perlUnixBind(filepath.Join(fixture.workspace, "b.sock")))
	if !ok || !strings.Contains(out, "bound") {
		t.Errorf("bind inside the workspace under Local: ok=%v out=%q", ok, out)
	}
	out, ok = runUnixProbe(t, e, fixture.workspace, perlUnixBindWord(`"$TMPDIR/t.sock"`))
	if !ok || !strings.Contains(out, "bound") {
		t.Errorf("bind inside the executor TMPDIR under Local: ok=%v out=%q", ok, out)
	}
	out, ok = runUnixProbe(t, e, fixture.workspace, perlUnixBind(filepath.Join(filepath.Dir(fixture.outside), "b.sock")))
	if ok {
		t.Errorf("bind outside every writable root under Local succeeded: %q", out)
	}
}

// TestSeatbeltEnforceUnixSocketsPaths: naming the OUTSIDE socket admits
// exactly it — reached through its public /tmp spelling, which the backend
// canonicalized to /private/tmp — while the workspace socket (no Local mode)
// stays denied and binding stays denied everywhere.
func TestSeatbeltEnforceUnixSocketsPaths(t *testing.T) {
	requireSandboxExec(t)
	fixture := newUnixSocketFixture(t)
	other := filepath.Join(filepath.Dir(fixture.outside), "other.sock")
	unixPongServer(t, other)
	e := unixSocketExecutor(t, fixture.workspace, profile.UnixSocketPolicy{Paths: []string{fixture.outside}})
	expectConnect(t, e, fixture.workspace, fixture.outside, true)
	expectConnect(t, e, fixture.workspace, other, false)
	expectConnect(t, e, fixture.workspace, fixture.inside, false)
	if out, ok := runUnixProbe(t, e, fixture.workspace, perlUnixBind(filepath.Join(fixture.workspace, "b.sock"))); ok {
		t.Errorf("bind under Paths-only succeeded: %q", out)
	}
}

// TestSeatbeltEnforceUnixSocketsDeniedUnderNetworkAllow: a sandboxed profile
// with Network: Allow compiles to (allow network*), which used to admit every
// pathname socket on the host. The default AF_UNIX denial must survive it.
func TestSeatbeltEnforceUnixSocketsDeniedUnderNetworkAllow(t *testing.T) {
	requireSandboxExec(t)
	fixture := newUnixSocketFixture(t)
	prof := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: fixture.workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Allow, HostWrite: profile.Deny, Network: profile.Allow, Command: profile.Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(shortTempDir(t, "us")), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	e, err := set.For("open")
	if err != nil {
		t.Fatal(err)
	}
	expectConnect(t, e, fixture.workspace, fixture.outside, false)
	expectConnect(t, e, fixture.workspace, fixture.inside, false)
	// Positive control: the same executor still has network egress, i.e. the
	// unix-socket deny did not swallow (allow network*). A loopback TCP
	// listener stands in for the internet.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if out, ok := runUnixProbe(t, e, fixture.workspace, "/usr/bin/nc -z -w2 127.0.0.1 "+strconv.Itoa(port)); !ok {
		t.Errorf("TCP egress under Network: Allow failed: %q", out)
	}
}
