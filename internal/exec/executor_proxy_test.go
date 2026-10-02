package exec

import (
	"bufio"
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
	command := portableEnvironmentCommand()
	token := issueTestGrant(t, executor, now, "exec-proxy", command, workspace,
		"network", "", "network.proxy-target.v1", target)
	out, code, err := executor.RunCommandWithGrants(context.Background(), "exec-proxy", workspace, command, []string{token})
	if err != nil || code != 0 {
		t.Fatalf("proxy grant run = code %d err %v out %q", code, err, out)
	}
	environment := parsedEnvironment(out)
	if !strings.HasPrefix(environment["HTTP_PROXY"], "http://exec-proxy:") || !strings.HasPrefix(environment["HTTPS_PROXY"], "http://exec-proxy:") || environment["NO_PROXY"] != "" {
		t.Fatalf("proxy environment missing scoped values or NO_PROXY clear:\n%v", environment)
	}
	pol := backend.lastPolicy()
	_, portText, _ := net.SplitHostPort(executor.proxy.Addr())
	port, _ := strconv.ParseUint(portText, 10, 16)
	if pol.Net.ProxyPort != uint16(port) || pol.Net.Open || pol.Net.Loopback || len(pol.Net.Ports) != 0 {
		t.Fatalf("proxy policy = %+v, want exact listener port only", pol.Net)
	}
}

// TestUngrantedSpawnCarriesNoProxyCredential pins review H6's secondary
// mitigation. On darwin a confined child can read the initial environment of
// any same-user, non-platform process (Seatbelt does not mediate
// KERN_PROCARGS2), so a proxy credential is exposed to sibling spawns for as
// long as the process holding it lives. The credential must therefore exist
// only where it is needed: a route-configured executor whose Network is
// Gated runs an ungranted command with NO proxy variable at all (not even a
// credential-less URL), and the credential a granted run did receive is
// per-execution and refused by the proxy once that run released it.
func TestUngrantedSpawnCarriesNoProxyCredential(t *testing.T) {
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
	executor, err := set.For("proxy-scope")
	if err != nil {
		t.Fatal(err)
	}
	command := portableEnvironmentCommand()

	out, code, err := executor.RunCommand(context.Background(), workspace, command)
	if err != nil || code != 0 {
		t.Fatalf("ungranted run = code %d err %v out %q", code, err, out)
	}
	for name, value := range parsedEnvironment(out) {
		if strings.Contains(strings.ToUpper(name), "PROXY") || strings.Contains(value, executor.proxy.Addr()) {
			t.Fatalf("ungranted spawn received proxy variable %s=%q", name, value)
		}
	}

	// Positive control: the granted run in the same executor does receive a
	// credential, and it stops working the moment that run has released it.
	token := issueTestGrant(t, executor, now, "exec-scoped", command, workspace,
		"network", "", "network.proxy-target.v1", "tcp:example.test:443")
	out, code, err = executor.RunCommandWithGrants(context.Background(), "exec-scoped", workspace, command, []string{token})
	if err != nil || code != 0 {
		t.Fatalf("granted run = code %d err %v out %q", code, err, out)
	}
	proxyURL, err := url.Parse(parsedEnvironment(out)["HTTP_PROXY"])
	if err != nil || proxyURL.User == nil {
		t.Fatalf("granted run carried no credentialed proxy URL: %q (%v)", parsedEnvironment(out)["HTTP_PROXY"], err)
	}
	request, err := http.NewRequest(http.MethodConnect, "http://"+executor.proxy.Addr(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.test:443"
	password, _ := proxyURL.User.Password()
	request.SetBasicAuth(proxyURL.User.Username(), password)
	request.Header.Set("Proxy-Authorization", request.Header.Get("Authorization"))
	request.Header.Del("Authorization")
	conn, err := net.DialTimeout("tcp", executor.proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("a released execution's credential got %s from the proxy, want 407", response.Status)
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
	command := portableProxyExposureCommand(proxyFile)
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
	parsed, err := url.Parse(strings.TrimSpace(string(rawProxy)))
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
	out, code, err := executor.RunCommand(context.Background(), workspace, portableEnvironmentCommand())
	if err != nil || code != 0 {
		t.Fatalf("RunCommand = code %d err %v", code, err)
	}
	environment := parsedEnvironment(out)
	if !strings.HasPrefix(environment["HTTP_PROXY"], "http://route-") || environment["NO_PROXY"] != "" {
		t.Fatalf("explicit route not injected:\n%s", out)
	}
	pol := backend.lastPolicy()
	if pol.Net.Open || pol.Net.ProxyPort == 0 || pol.Net.Loopback || len(pol.Net.Ports) != 0 {
		t.Fatalf("explicit route policy = %+v, want listener-only", pol.Net)
	}
}
