package sandbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// This test lives with the executor rather than with the proxy because what it
// asserts is an ExecutorSet.Close guarantee: closing the set must unblock a
// CONNECT that an upstream proxy accepted but never answered.

func TestExecutorSetCloseUnblocksSilentUpstreamCONNECT(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var activeSockets atomic.Int32
	upstreamReady := make(chan struct{})
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		activeSockets.Add(1)
		defer func() {
			activeSockets.Add(-1)
			_ = connection.Close()
		}()
		request, readErr := http.ReadRequest(bufio.NewReader(connection))
		if readErr == nil {
			_ = request.Body.Close()
		}
		close(upstreamReady)
		_, _ = io.Copy(io.Discard, connection)
	}()

	route, err := NewUpstreamEgressRoute("http://"+listener.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	route = route.WithDialer(nil, func(ctx context.Context, transport, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, transport, address)
	})
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeTargetNetwork | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("silent-upstream")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := executor.proxy.Authorize("silent-handshake", []NetworkTarget{mustTarget(t, "tcp:service.example:443")})
	if err != nil {
		t.Fatal(err)
	}
	child, err := net.Dial("tcp", executor.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("silent-handshake:" + credential))
	_, _ = fmt.Fprintf(child, "CONNECT service.example:443 HTTP/1.1\r\nHost: service.example:443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	<-upstreamReady
	if got := activeSockets.Load(); got != 1 {
		t.Fatalf("active upstream sockets = %d, want 1", got)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- set.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("ExecutorSet.Close: %v", err)
		}
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("ExecutorSet.Close did not unblock silent upstream CONNECT")
	}
	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Fatal("upstream handler/socket survived ExecutorSet.Close")
	}
	if got := activeSockets.Load(); got != 0 {
		t.Fatalf("active upstream sockets after Close = %d, want 0", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dial count = %d, want exactly 1 and no fallback", got)
	}
	_ = child.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.Copy(io.Discard, child); err != nil {
		t.Fatalf("child proxy socket did not reach EOF after ExecutorSet.Close: %v", err)
	}
}
