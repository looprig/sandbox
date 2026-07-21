package sandbox

import (
	"context"
	"errors"
	"github.com/looprig/sandbox/pkg/network"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProxyTargetGrantCompilesListenerAndInjectsExecutionCredential(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, _ := NewDirectEgressRoute()
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeTargetNetwork | GuaranteeEnvScrub}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(backend), withClock(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("proxy")
	if err != nil {
		t.Fatal(err)
	}
	if executor.routeFingerprint != route.Fingerprint() || executor.proxy == nil {
		t.Fatal("executor did not own the configured proxy route")
	}
	target := "tcp:example.test:443"
	token := issueTestGrant(t, executor, now, "exec-proxy", "env", workspace,
		"network", "", "network.proxy-target.v1", target)
	out, code, err := executor.RunCommandWithGrants(context.Background(), "exec-proxy", workspace, "env", []string{token})
	if err != nil || code != 0 {
		t.Fatalf("proxy grant run = code %d err %v out %q", code, err, out)
	}
	environment := string(out)
	if !strings.Contains(environment, "HTTP_PROXY=http://exec-proxy:") || !strings.Contains(environment, "HTTPS_PROXY=http://exec-proxy:") || !strings.Contains(environment, "NO_PROXY=\n") {
		t.Fatalf("proxy environment missing scoped values or NO_PROXY clear:\n%s", environment)
	}
	pol := backend.lastPolicy()
	_, portText, _ := net.SplitHostPort(executor.proxy.Addr())
	port, _ := strconv.ParseUint(portText, 10, 16)
	if pol.Net.ProxyPort != uint16(port) || pol.Net.Open || pol.Net.Loopback || len(pol.Net.Ports) != 0 {
		t.Fatalf("proxy policy = %+v, want exact listener port only", pol.Net)
	}
}

func TestExecutorComposesAddressGuaranteeWithSelectedRoute(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	direct, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	directDialed := false
	direct = direct.WithDialer(
		func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("100.100.100.200")}, nil
		},
		func(context.Context, string, string) (net.Conn, error) {
			directDialed = true
			return nil, errors.New("special-use address reached dial")
		},
	)
	untrusted, err := NewUpstreamEgressRoute("http://proxy.example:8080", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		route         EgressRoute
		want          bool
		verifyRefusal bool
	}{
		{name: "direct trusted resolution", route: direct, want: true, verifyRefusal: true},
		{name: "upstream without address contract", route: untrusted, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeTargetNetwork | GuaranteeEnvScrub}
			set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(test.route),
				withExecutorSetConfig(withBackend(backend)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = set.Close() })
			executor, err := set.For("route")
			if err != nil {
				t.Fatal(err)
			}
			if got := executor.Guarantees().AddressNetwork; got != test.want {
				t.Fatalf("AddressNetwork = %v, want %v", got, test.want)
			}
			if test.verifyRefusal {
				_, err := executor.proxy.Route().DialTarget(context.Background(), mustTarget(t, "tcp:metadata.example:80"))
				if !errors.Is(err, network.ErrAddressDenied) {
					t.Fatalf("composed direct route error = %v, want network.ErrAddressDenied", err)
				}
				if directDialed {
					t.Fatal("composed AddressNetwork guarantee allowed a special-use address to reach dial")
				}
			}
		})
	}
}

func TestAuthenticatedProxyDenialPrecedesProcessResultAndCredentialIsRevoked(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, _ := NewDirectEgressRoute()
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeTargetNetwork | GuaranteeEnvScrub}), withClock(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, _ := set.For("proxy-denial")
	proxyFile := workspace + "/proxy-url"
	command := "printf '%s' \"$HTTP_PROXY\" > " + proxyFile + "; sleep 1; exit 7"
	token := issueTestGrant(t, executor, now, "exec-denial", command, workspace,
		"network", "", "network.proxy-target.v1", "tcp:allowed.test:80")

	type result struct {
		out  []byte
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		out, code, err := executor.RunCommandWithGrants(context.Background(), "exec-denial", workspace, command, []string{token})
		done <- result{out, code, err}
	}()
	var rawProxy []byte
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rawProxy, _ = os.ReadFile(proxyFile)
		if len(rawProxy) != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rawProxy) == 0 {
		t.Fatal("command never exposed its scoped proxy URL")
	}
	parsed, err := url.Parse(string(rawProxy))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(parsed)}}
	response, err := client.Get("http://denied.test/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	got := <-done
	if !errors.Is(got.err, ErrNetworkTargetDenied) || got.code != 7 {
		t.Fatalf("run result = code %d err %v, want code 7 + ErrNetworkTargetDenied", got.code, got.err)
	}
	response, err = client.Get("http://allowed.test/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("revoked credential status = %d, want 407", response.StatusCode)
	}
}

func TestNetworkAllowUsesExplicitRoute(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Allow, Command: Allow,
	})
	route, _ := NewDirectEgressRoute()
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeTargetNetwork | GuaranteeEnvScrub}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("network-allow")
	if err != nil {
		t.Fatal(err)
	}
	out, code, err := executor.RunCommand(context.Background(), workspace, "env")
	if err != nil || code != 0 {
		t.Fatalf("RunCommand = code %d err %v", code, err)
	}
	if !strings.Contains(string(out), "HTTP_PROXY=http://route-") || !strings.Contains(string(out), "NO_PROXY=\n") {
		t.Fatalf("explicit route not injected:\n%s", out)
	}
	pol := backend.lastPolicy()
	if pol.Net.Open || pol.Net.ProxyPort == 0 || pol.Net.Loopback || len(pol.Net.Ports) != 0 {
		t.Fatalf("explicit route policy = %+v, want listener-only", pol.Net)
	}
}
