//go:build darwin

package darwin

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// Review H7: the preamble's unfiltered (allow mach-lookup) let every confined
// process reach LaunchServices, so `open https://…` launched the unsandboxed
// default browser (defeating Network: Deny) and `open -a`/AppleEvents could
// start or drive any application. Review H6: Seatbelt cannot mediate
// KERN_PROCARGS2, so EnvScrub must be reported narrowed.

// TestCompileSBPLMachLookupIsAllowlisted pins the preamble: no unfiltered
// mach-lookup rule anywhere, and the allowlist is exactly the measured set.
func TestCompileSBPLMachLookupIsAllowlisted(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	sbpl, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	if strings.Contains(sbpl, "(allow mach-lookup)\n") {
		t.Fatalf("profile still carries an unfiltered mach-lookup:\n%s", sbpl)
	}
	want := `(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo") (global-name "com.apple.system.opendirectoryd.membership"))`
	if !strings.Contains(sbpl, want+"\n") {
		t.Fatalf("profile missing the measured allowlist %q:\n%s", want, sbpl)
	}
	for _, forbidden := range []string{
		"launchservicesd", "com.apple.lsd", "coreservicesd", "cfprefsd", "SecurityServer",
		"FSEvents", "distributed_notifications", "pasteboard", "windowserver",
	} {
		if strings.Contains(sbpl, forbidden) {
			t.Errorf("profile names excluded service %q", forbidden)
		}
	}
	sandboxExecParses(t, sbpl)
}

// TestCompileSBPLTrustdOnlyWithNetworkEgress: certificate evaluation is
// admitted exactly when the profile grants some egress, never to a
// network-denied (or DNS-only) profile, because trustd fetches URLs named
// by a certificate itself, outside the sandbox.
func TestCompileSBPLTrustdOnlyWithNetworkEgress(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	const trustd = `(global-name "com.apple.trustd.agent")`
	for _, test := range []struct {
		name string
		net  policy.NetPolicy
		want bool
	}{
		{"denied", policy.NetPolicy{}, false},
		{"dns only", policy.NetPolicy{DNS: true}, false},
		{"private only (compiled to blocked)", policy.NetPolicy{Private: true}, false},
		{"egress proxy", policy.NetPolicy{ProxyPort: 40000}, true},
		{"port", policy.NetPolicy{Ports: []uint16{443}}, true},
		{"loopback", policy.NetPolicy{Loopback: true}, true},
		{"open", policy.NetPolicy{Open: true}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sbpl, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws", fixtureWithNet(test.net)))
			if got := strings.Contains(sbpl, trustd); got != test.want {
				t.Fatalf("trustd admitted = %v, want %v", got, test.want)
			}
		})
	}
}

// launchServicesProbe runs `open zzz://…` (a scheme no application claims,
// so nothing is ever launched) under profile and returns its stderr.
func launchServicesProbe(t *testing.T, sbpl string) string {
	t.Helper()
	cmd := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, "--", "/usr/bin/open", "zzz-lrsbx-probe://x")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("open zzz-lrsbx-probe:// succeeded under the profile?! output=%s", stderr.String())
	}
	return stderr.String()
}

// TestSeatbeltBlocksLaunchServices is H7's live proof, differential: the
// same compiled profile with its mach-lookup allowlist swapped back to the
// former unfiltered rule gets a real LaunchServices answer
// (kLSApplicationNotFoundErr, -10814: the LS database was consulted and no
// handler claims the scheme), while the shipped profile cannot reach the LS
// daemons at all (kLSExecutableIncorrectFormat, -10661, from the client-side
// fallback). `open https://…` and `open -a` go through the same daemons, so
// with them unreachable nothing can be launched outside the sandbox.
func TestSeatbeltBlocksLaunchServices(t *testing.T) {
	requireSandboxExec(t)
	pol, err := policy.Compile(mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Allow, HostWrite: profile.Deny, Network: profile.Allow, Command: profile.Allow,
	}))
	if err != nil {
		t.Fatal(err)
	}
	shipped, _, _, _ := compileSBPL(pol)
	unfiltered := strings.Replace(shipped, darwinMachLookupRule, "(allow mach-lookup)\n", 1)
	if unfiltered == shipped {
		t.Fatal("could not build the unfiltered control profile")
	}

	control := launchServicesProbe(t, unfiltered)
	if !strings.Contains(control, "-10814") {
		t.Skipf("control: LaunchServices did not answer as expected on this host (%q); cannot attribute the shipped result", control)
	}
	got := launchServicesProbe(t, shipped)
	if strings.Contains(got, "-10814") {
		t.Fatalf("the shipped profile still reaches LaunchServices (real LS answer): %s", got)
	}
	if !strings.Contains(got, "-10661") {
		t.Logf("shipped profile output (LaunchServices unreachable): %s", got)
	}
}

// TestCompileSBPLReportsEnvScrubNarrowed: every profile that claims EnvScrub
// reports its cross-process limit; an inherited environment claims neither.
func TestCompileSBPLReportsEnvScrubNarrowed(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	_, report, _, bits := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	if bits&profile.GuaranteeEnvScrub == 0 || !hasReport(report, "env-scrub", "narrowed") {
		t.Fatalf("EnvScrub claimed without its narrowed report entry: bits %#b report %+v", bits, report.Entries)
	}
	_, inheritReport, _, _ := compileSBPL(policy.Effective{Workspace: "/ws", Env: policy.EnvPolicy{Inherit: true}})
	if hasReportFeature(inheritReport, "env-scrub") {
		t.Fatal("an inherited environment reported an env-scrub entry")
	}
}

// procargsProbe is the reviewer's H6 probe: a raw __sysctl (syscall 202)
// for {CTL_KERN, KERN_PROCARGS2, pid}, printing the NUL-separated argv and
// environment one per line.
const procargsProbe = `my $pid = shift; my $mib = pack("i3", 1, 49, $pid); my $size = pack("Q", 1<<20); my $buf = "\0" x (1<<20);
syscall(202, $mib, 3, $buf, $size, 0, 0) == 0 or die "sysctl: $!\n";
my $n = unpack("Q", $size); my $s = substr($buf, 4, $n - 4); $s =~ s/\0+/\n/g; print $s, "\n";`

// TestH6ProcargsHolder is not a test: re-executed by
// TestSeatbeltProcargsCrossProcessReadIsReported with LRSBX_H6_HOLDER=1, it
// is the same-user, non-platform-binary process whose environment carries
// the planted secret, and it just waits to be read.
func TestH6ProcargsHolder(t *testing.T) {
	if os.Getenv("LRSBX_H6_HOLDER") != "1" {
		t.Skip("helper process for TestSeatbeltProcargsCrossProcessReadIsReported")
	}
	time.Sleep(30 * time.Second)
}

// TestSeatbeltProcargsCrossProcessReadIsReported pins H6's measured limit
// against the module's real profile: a confined child recovers a planted
// secret from a same-user process's KERN_PROCARGS2 (so the report entry is
// required, and this test fails loudly — telling a maintainer to revisit the
// entry — if a future macOS starts mediating it), while the child's own argv
// stays readable (the positive control: the probe works at all).
func TestSeatbeltProcargsCrossProcessReadIsReported(t *testing.T) {
	requireSandboxExec(t)
	secret := fmt.Sprintf("lrsbx-h6-secret-%d", time.Now().UnixNano())
	holder := exec.Command(os.Args[0], "-test.run=^TestH6ProcargsHolder$")
	holder.Env = append(os.Environ(), "LRSBX_H6_HOLDER=1", "LRSBX_H6_PLANTED="+secret)
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Process.Kill(); _, _ = holder.Process.Wait() })

	pol, err := policy.Compile(mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Allow, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
	}))
	if err != nil {
		t.Fatal(err)
	}
	sbpl, report, _, _ := compileSBPL(pol)
	if !hasReport(report, "env-scrub", "narrowed") {
		t.Fatalf("profile claims EnvScrub without reporting the KERN_PROCARGS2 limit: %+v", report.Entries)
	}

	self, err := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, "--", "/usr/bin/perl", "-e",
		`my $mib = pack("i3", 1, 49, $$); my $size = pack("Q", 1<<16); my $buf = "\0" x (1<<16); syscall(202, $mib, 3, $buf, $size, 0, 0) == 0 or die "sysctl: $!\n"; print "self-ok\n" if index($buf, "/usr/bin/perl") >= 0`).CombinedOutput()
	if err != nil || !strings.Contains(string(self), "self-ok") {
		t.Fatalf("positive control: the confined probe could not read its own argv (err %v, out %q)", err, self)
	}

	var leaked bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !leaked {
		out, _ := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, "--", "/usr/bin/perl", "-e", procargsProbe, fmt.Sprint(holder.Process.Pid)).CombinedOutput()
		leaked = strings.Contains(string(out), secret)
		if !leaked {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !leaked {
		t.Fatalf("the confined probe could NOT read the holder's environment: this macOS now mediates KERN_PROCARGS2 — re-measure H6 and revisit the env-scrub/narrowed report entry")
	}
}
