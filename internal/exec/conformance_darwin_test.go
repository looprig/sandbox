//go:build darwin

package exec

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/sandbox/pkg/profile"
	"github.com/looprig/sandbox/pkg/sandboxtest"
)

// Review M11: the live darwin conformance target ran sandboxtest.RunSuite
// only, so a guarantee bit the real Seatbelt executor CLAIMED was never
// checked behaviourally unless RunSuite happened to cover it. Windows already
// gates its claims through sandboxtest.CheckClaimedImplications; darwin now
// does too, against three real executors whose claims differ: the live
// conformance fixture (HostRead: Allow — no ReadBoundary), the production
// default shape (HostRead: Deny — ReadBoundary claimed), and a
// route-configured executor (TargetNetwork claimed). Every claimed bit must
// have a probe, and every probe carries an unsandboxed positive control.

// darwinReadProbe: a file outside every root is unreadable under the
// sandbox, while the test process reads it and the sandbox reads the
// workspace.
func darwinReadProbe(workspace string) sandboxtest.ImplicationProbe {
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		outside := filepath.Join(os.TempDir(), fmt.Sprintf("lrsbx-read-probe-%d", time.Now().UnixNano()))
		if err := os.WriteFile(outside, []byte("OUTSIDE-SECRET"), 0o600); err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		defer os.Remove(outside)
		inside := filepath.Join(workspace, "read-probe.txt")
		if err := os.WriteFile(inside, []byte("INSIDE-VISIBLE"), 0o600); err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		defer os.Remove(inside)
		raw, hostErr := os.ReadFile(outside)
		insideOut, insideCode, insideErr := sut.RunCommand(ctx, workspace, "/bin/cat "+inside)
		control := hostErr == nil && string(raw) == "OUTSIDE-SECRET" && insideErr == nil && insideCode == 0 && strings.Contains(string(insideOut), "INSIDE-VISIBLE")
		out, code, err := sut.RunCommand(ctx, workspace, "/bin/cat "+outside)
		if err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		return sandboxtest.ImplicationResult{
			PositiveControl: control,
			GuaranteeHeld:   code != 0 && !strings.Contains(string(out), "OUTSIDE-SECRET"),
			Detail:          fmt.Sprintf("outside read code %d out %q; workspace read code %d", code, out, insideCode),
		}, nil
	}
}

// darwinProcessProbe: the sandbox cannot signal a same-user process outside
// it (Seatbelt's (deny default) covers the signal operation), while the test
// process can.
func darwinProcessProbe(workspace string) sandboxtest.ImplicationProbe {
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		holder := exec.Command("/bin/sleep", "30")
		if err := holder.Start(); err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		defer func() { _ = holder.Process.Kill(); _, _ = holder.Process.Wait() }()
		pid := holder.Process.Pid
		control := syscall.Kill(pid, 0) == nil
		out, code, err := sut.RunCommand(ctx, workspace, fmt.Sprintf("/bin/kill -TERM %d", pid))
		if err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		alive := syscall.Kill(pid, 0) == nil
		return sandboxtest.ImplicationResult{
			PositiveControl: control,
			GuaranteeHeld:   code != 0 && alive,
			Detail:          fmt.Sprintf("sandboxed kill code %d out %q; target alive %v", code, out, alive),
		}, nil
	}
}

// darwinNetworkProbe: a live loopback listener the test process can reach
// is unreachable from the sandbox.
func darwinNetworkProbe(workspace string) sandboxtest.ImplicationProbe {
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		host, port, _ := net.SplitHostPort(listener.Addr().String())
		conn, dialErr := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
		if dialErr == nil {
			_ = conn.Close()
		}
		out, code, err := sut.RunCommand(ctx, workspace, "/usr/bin/nc -z -w2 "+host+" "+port)
		if err != nil {
			return sandboxtest.ImplicationResult{}, err
		}
		return sandboxtest.ImplicationResult{
			PositiveControl: dialErr == nil,
			GuaranteeHeld:   code != 0,
			Detail:          fmt.Sprintf("sandboxed connect code %d out %q", code, out),
		}, nil
	}
}

func darwinImplicationProbes(workspace string) sandboxtest.ImplicationProbes {
	return sandboxtest.ImplicationProbes{
		Read:    darwinReadProbe(workspace),
		Process: darwinProcessProbe(workspace),
		Network: darwinNetworkProbe(workspace),
	}
}

// TestSandboxtestDarwinLiveImplications gates the live conformance fixture's
// claims (no ReadBoundary: HostRead is Allow there) and the production
// default shape's (ReadBoundary claimed: HostRead is Deny).
func TestSandboxtestDarwinLiveImplications(t *testing.T) {
	requireSandboxExec(t)
	t.Run("live-fixture", func(t *testing.T) {
		workspace := t.TempDir()
		sandboxtest.CheckClaimedImplications(t, newLiveConformanceExecutor(t, workspace), darwinImplicationProbes(workspace))
	})
	t.Run("host-read-deny", func(t *testing.T) {
		workspace := t.TempDir()
		prof := mustProfile(t, profile.ProfileConfig{
			WorkspaceRoot: workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
			HostRead: profile.Deny, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
		})
		set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
		if err != nil {
			t.Fatalf("NewExecutorSet: %v", err)
		}
		t.Cleanup(func() { _ = set.Close() })
		executor, err := set.For("implications")
		if err != nil {
			t.Fatal(err)
		}
		if !executor.Guarantees().ReadBoundary {
			t.Fatal("HostRead: Deny executor does not claim ReadBoundary; the read probe would not run")
		}
		sandboxtest.CheckClaimedImplications(t, executor, darwinImplicationProbes(workspace))
	})
}

// TestSandboxtestDarwinRouteImplications gates a route-configured executor,
// which additionally claims TargetNetwork: the probe reaches an approved
// target only through the proxy (and only with a grant), while a direct
// connect to the same target's address is refused.
func TestSandboxtestDarwinRouteImplications(t *testing.T) {
	fixture := newSeatbeltProxyFixture(t)
	target := "tcp:" + proxyTestOriginHost + ":" + fixture.originPort
	probes := darwinImplicationProbes(fixture.workspace)
	probes.TargetNetwork = func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		conn, dialErr := net.DialTimeout("tcp", fixture.origin, 2*time.Second)
		if dialErr == nil {
			_ = conn.Close()
		}
		viaProxy, viaCode, viaErr := fixture.runGranted(t, "implication-via", target,
			"/usr/bin/curl -sS --max-time 10 http://"+proxyTestOriginHost+":"+fixture.originPort+"/implication")
		host, port, _ := net.SplitHostPort(fixture.origin)
		direct, directCode, directErr := fixture.runGranted(t, "implication-direct", target, "/usr/bin/nc -z -w2 "+host+" "+port)
		if directErr != nil {
			return sandboxtest.ImplicationResult{}, directErr
		}
		return sandboxtest.ImplicationResult{
			PositiveControl: dialErr == nil && viaErr == nil && viaCode == 0 && strings.Contains(viaProxy, "origin-ok:/implication"),
			GuaranteeHeld:   directCode != 0,
			Detail:          fmt.Sprintf("via proxy code %d out %q err %v; direct code %d out %q", viaCode, viaProxy, viaErr, directCode, direct),
		}, nil
	}
	sandboxtest.CheckClaimedImplications(t, fixture.executor, probes)
}
