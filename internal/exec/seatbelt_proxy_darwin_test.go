//go:build darwin

package exec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

// Review M11: proxy routing, TargetNetwork and HostRead: Deny had only ever
// been exercised against captureBackend and golden strings, never through
// the real Seatbelt backend. These tests drive REAL executors (ExecutorSet,
// policy.Compile, the darwin backend, /usr/bin/sandbox-exec) with a REAL
// egress route and REAL network.proxy-target.v1 grants.
//
// Topology, all on loopback inside the test process:
//
//	child (sandbox-exec) --> executor proxy 127.0.0.1:P   (the only port the profile admits)
//	                           --> upstream proxy 127.0.0.1:U   (the route; test-owned)
//	                                 --> origin 127.0.0.1:T      (the approved target)
//
// The direct route refuses loopback destinations by design (special-use
// address filtering), so the route is an UPSTREAM route to a tiny forward
// proxy that maps every host name to the origin. The origin's port is one
// the policy never admits directly, so the proxy is the only way to it, and
// the upstream's port is "another loopback port" that must be denied too.

const proxyTestOriginHost = "origin.lrsbx.test"

// startForwardUpstream is a minimal HTTP forward proxy for the route: CONNECT
// is spliced to origin, absolute-form requests are re-issued to origin. It
// records the request targets it was asked for.
func startForwardUpstream(t *testing.T, origin string) (addr string, seen func() []string) {
	t.Helper()
	var mu sync.Mutex
	var targets []string
	record := func(target string) {
		mu.Lock()
		targets = append(targets, target)
		mu.Unlock()
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			record("CONNECT " + r.Host)
			upstream, err := net.Dial("tcp", origin)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			client, buffered, err := w.(http.Hijacker).Hijack()
			if err != nil {
				_ = upstream.Close()
				return
			}
			_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = buffered.Flush()
			go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close() }()
			_, _ = io.Copy(client, upstream)
			_ = client.Close()
			return
		}
		record(r.Method + " " + r.URL.String())
		outbound := r.Clone(r.Context())
		outbound.RequestURI = ""
		outbound.URL.Host = origin
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

type seatbeltProxyFixture struct {
	workspace  string
	executor   *Executor
	originPort string
	origin     string // 127.0.0.1:T
	upstream   string // 127.0.0.1:U
	seen       func() []string
}

func newSeatbeltProxyFixture(t *testing.T) seatbeltProxyFixture {
	t.Helper()
	requireSandboxExec(t)
	if _, err := os.Stat("/usr/bin/curl"); err != nil {
		t.Skip("/usr/bin/curl is required for the proxy probes")
	}
	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "origin-ok:"+r.URL.Path)
	}))
	t.Cleanup(originServer.Close)
	origin := originServer.Listener.Addr().String()
	_, originPort, _ := net.SplitHostPort(origin)
	upstream, seen := startForwardUpstream(t, origin)
	route, err := NewUpstreamEgressRoute("http://"+upstream, false)
	if err != nil {
		t.Fatal(err)
	}
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	// /usr/bin/curl links LibreSSL, which reads /private/etc/ssl/openssl.cnf
	// at startup and exits ("Auto configuration failed") when it cannot —
	// even for plain HTTP. The darwin runtime closure
	// (policy.MinimalRuntimeEntries) does not include it, so under HostRead:
	// Deny the test grants that one directory read-only, as a consumer
	// running curl would have to.
	prof := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Deny, HostWrite: profile.Deny, Network: profile.Gated, Command: profile.Allow,
		AdditionalRoots: []profile.RootAccess{{Path: "/private/etc/ssl", Read: profile.Allow, Write: profile.Deny}},
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("seatbelt-proxy")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	if !executor.Guarantees().TargetNetwork || !executor.Guarantees().NetworkBoundary {
		t.Fatalf("real Seatbelt executor with a route lacks Target/NetworkBoundary: %+v", executor.Guarantees())
	}
	// Positive controls: the unsandboxed test process reaches both loopback
	// endpoints, so a sandboxed failure below is enforcement, not a dead port.
	for _, address := range []string{origin, upstream} {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("control dial %s: %v", address, err)
		}
		_ = conn.Close()
	}
	return seatbeltProxyFixture{workspace: workspace, executor: executor, originPort: originPort, origin: origin, upstream: upstream, seen: seen}
}

// runGranted mints a proxy-target grant for target and runs command with it.
func (fixture seatbeltProxyFixture) runGranted(t *testing.T, executionID, target, command string) (string, int, error) {
	t.Helper()
	token, err := fixture.executor.IssueGrant(context.Background(), executionID, command, fixture.workspace,
		"network", "", GrantClassNetworkProxyTarget, target, time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant(%s): %v", target, err)
	}
	out, code, runErr := fixture.executor.RunCommandWithGrants(context.Background(), executionID, fixture.workspace, command, []string{token})
	return string(out), code, runErr
}

// TestSeatbeltProxyTargetReachesApprovedTargetOnly is the end-to-end
// TargetNetwork proof under real Seatbelt: the approved target is reached
// through the executor's proxy for plain HTTP and for CONNECT; within the
// same granted spawn a direct TCP connect to the target's own address, and a
// connect to another loopback port (the route's upstream), are denied by
// Seatbelt; and an unapproved target through the proxy is refused and
// surfaces as a TargetDeniedError.
func TestSeatbeltProxyTargetReachesApprovedTargetOnly(t *testing.T) {
	fixture := newSeatbeltProxyFixture(t)
	target := "tcp:" + proxyTestOriginHost + ":" + fixture.originPort
	url := "http://" + proxyTestOriginHost + ":" + fixture.originPort

	out, code, err := fixture.runGranted(t, "exec-http", target, "/usr/bin/curl -sS --max-time 10 "+url+"/plain")
	if err != nil || code != 0 || !strings.Contains(out, "origin-ok:/plain") {
		t.Fatalf("approved plain-HTTP request through the proxy: code %d err %v out %q", code, err, out)
	}
	out, code, err = fixture.runGranted(t, "exec-connect", target, "/usr/bin/curl -sS --max-time 10 --proxytunnel "+url+"/tunnel")
	if err != nil || code != 0 || !strings.Contains(out, "origin-ok:/tunnel") {
		t.Fatalf("approved CONNECT through the proxy: code %d err %v out %q", code, err, out)
	}
	seen := strings.Join(fixture.seen(), "\n")
	if !strings.Contains(seen, "CONNECT "+proxyTestOriginHost+":"+fixture.originPort) || !strings.Contains(seen, "GET "+url+"/plain") {
		t.Fatalf("the route's upstream never saw the approved requests: %q", seen)
	}

	// Positive control for the nc probes below: in the same kind of spawn nc
	// runs and connects to the one loopback port the profile admits (the
	// executor's proxy), so a failure below is Seatbelt, not a broken tool.
	proxyHost, proxyPort, _ := net.SplitHostPort(fixture.executor.proxy.Addr())
	if out, code, err := fixture.runGranted(t, "exec-nc-control", target, "/usr/bin/nc -z -w2 "+proxyHost+" "+proxyPort); err != nil || code != 0 {
		t.Fatalf("control: nc to the admitted proxy port failed: code %d err %v out %q", code, err, out)
	}
	for _, direct := range []struct{ name, address string }{
		{"the approved target's own address", fixture.origin},
		{"another loopback port (the route upstream)", fixture.upstream},
	} {
		host, port, _ := net.SplitHostPort(direct.address)
		out, code, err := fixture.runGranted(t, "exec-direct-"+port, target, "/usr/bin/nc -z -w2 "+host+" "+port)
		if err != nil {
			t.Fatalf("direct connect to %s: spawn error %v", direct.name, err)
		}
		if code == 0 {
			t.Errorf("direct TCP connect to %s (%s) succeeded inside a proxy-target spawn — the proxy is bypassable: %q", direct.name, direct.address, out)
		}
	}

	out, code, err = fixture.runGranted(t, "exec-other", target,
		"/usr/bin/curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://other.lrsbx.test:"+fixture.originPort+"/")
	if !strings.Contains(out, "403") {
		t.Errorf("unapproved target through the proxy: code %d out %q, want HTTP 403", code, out)
	}
	var denied *network.TargetDeniedError
	if !errors.As(err, &denied) {
		t.Errorf("unapproved target error = %v, want a TargetDeniedError", err)
	}
}

// TestSeatbeltProxyRequiresTheExecutionCredential: a confined process that
// reaches the proxy listener (the profile admits its port) but does not
// present this execution's credential is refused with 407 — the proxy port
// being reachable is not itself authority.
func TestSeatbeltProxyRequiresTheExecutionCredential(t *testing.T) {
	fixture := newSeatbeltProxyFixture(t)
	target := "tcp:" + proxyTestOriginHost + ":" + fixture.originPort
	proxyAddr := fixture.executor.proxy.Addr()
	command := "/usr/bin/curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --noproxy '' -x http://" + proxyAddr +
		" http://" + proxyTestOriginHost + ":" + fixture.originPort + "/no-credential"
	out, _, err := fixture.runGranted(t, "exec-407", target, command)
	if err != nil {
		t.Fatalf("credential-less request: %v (out %q)", err, out)
	}
	if strings.TrimSpace(out) != "407" {
		t.Fatalf("credential-less request through the proxy = %q, want 407", out)
	}
	// An ungranted spawn of the same executor cannot use the proxy at all:
	// it holds no credential (TestUngrantedSpawnCarriesNoProxyCredential) and
	// gets the same 407.
	plain, code, err := fixture.executor.RunCommand(context.Background(), fixture.workspace, command)
	if err != nil || strings.TrimSpace(string(plain)) != "407" {
		t.Fatalf("ungranted spawn through the proxy = code %d err %v out %q, want 407", code, err, plain)
	}
}

// TestSeatbeltHostReadDenyLive: with HostRead: Deny (the production default
// shape, which the live conformance fixture does not use) a file outside
// every root is unreadable while the workspace stays readable — the
// read-boundary negative under the real backend.
func TestSeatbeltHostReadDenyLive(t *testing.T) {
	fixture := newSeatbeltProxyFixture(t)
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "host-secret.txt")
	if err := os.WriteFile(outside, []byte("HOST-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(fixture.workspace, "visible.txt")
	if err := os.WriteFile(inside, []byte("WORKSPACE-VISIBLE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "HOST-SECRET" {
		t.Fatalf("control: the test process cannot read %s: %v", outside, err)
	}
	out, code, err := fixture.executor.RunCommand(context.Background(), fixture.workspace, "/bin/cat "+inside)
	if err != nil || code != 0 || !strings.Contains(string(out), "WORKSPACE-VISIBLE") {
		t.Fatalf("workspace read under HostRead: Deny: code %d err %v out %q", code, err, out)
	}
	out, code, err = fixture.executor.RunCommand(context.Background(), fixture.workspace, "/bin/cat "+outside)
	if err != nil {
		t.Fatalf("outside read: spawn error %v", err)
	}
	if code == 0 || strings.Contains(string(out), "HOST-SECRET") {
		t.Fatalf("HostRead: Deny leaked a host file: code %d out %q", code, out)
	}
	if !fixture.executor.Guarantees().ReadBoundary {
		t.Fatal("HostRead: Deny executor does not claim ReadBoundary")
	}
}
