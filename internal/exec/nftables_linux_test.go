//go:build linux

package exec

import (
	"context"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestCompileNftPlan asserts the pure policy.NetPolicy -> nftables plan compilation
// (SPEC §5.2, §5.4, §7.2 rung 1): open egress is unconfined (no ruleset, no
// Netns); every other policy is Confined with the metadata deny always present
// and each accept gated by its flag. Runs on THIS host — no netlink.
func TestCompileNftPlan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		net          policy.NetPolicy
		wantConfined bool
		wantPorts    []uint16
		wantLoopback bool
		wantPrivate  bool
		wantDNS      bool
		wantMetadata bool
	}{
		{name: "open egress: unconfined, no ruleset", net: policy.NetPolicy{Open: true}, wantConfined: false},
		{name: "zerotrust (all-false): Confined, everything dropped, metadata denied", net: policy.NetPolicy{}, wantConfined: true, wantMetadata: true},
		{
			name:         "trusted: ports+Loopback+Private+Dns, metadata denied",
			net:          policy.NetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true},
			wantConfined: true, wantPorts: []uint16{443}, wantLoopback: true, wantPrivate: true, wantDNS: true, wantMetadata: true,
		},
		{
			name:         "duplicate ports deduped",
			net:          policy.NetPolicy{Ports: []uint16{443, 443, 80}},
			wantConfined: true, wantPorts: []uint16{443, 80}, wantMetadata: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := linux.CompileNftPlan(tt.net)
			if plan.Confined != tt.wantConfined {
				t.Fatalf("Confined = %v, want %v", plan.Confined, tt.wantConfined)
			}
			if !tt.wantConfined {
				if len(plan.MetadataCIDRs) != 0 {
					t.Errorf("open policy carries metadata CIDRs: %v", plan.MetadataCIDRs)
				}
				return
			}
			if len(plan.TcpPorts) != len(tt.wantPorts) {
				t.Errorf("TcpPorts = %v, want %v", plan.TcpPorts, tt.wantPorts)
			}
			if plan.Loopback != tt.wantLoopback || plan.Private != tt.wantPrivate || plan.Dns != tt.wantDNS {
				t.Errorf("flags Loopback/Private/Dns = %v/%v/%v, want %v/%v/%v",
					plan.Loopback, plan.Private, plan.Dns, tt.wantLoopback, tt.wantPrivate, tt.wantDNS)
			}
			if tt.wantMetadata && len(plan.MetadataCIDRs) == 0 {
				t.Errorf("metadata deny CIDRs missing on a Confined policy")
			}
		})
	}
}

// TestParseCIDR covers CIDR + bare-IP parsing (SPEC §5.4 metadata uses a bare
// IPv6 host). Runs on THIS host.
func TestParseCIDR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		wantErr  bool
		wantV4   bool
		wantOnes int
	}{
		{name: "ipv4 /16", in: "169.254.0.0/16", wantV4: true, wantOnes: 16},
		{name: "ipv4 /8", in: "10.0.0.0/8", wantV4: true, wantOnes: 8},
		{name: "ipv6 ULA /7", in: "fc00::/7", wantV4: false, wantOnes: 7},
		{name: "bare ipv6 host -> /128", in: "fd00:ec2::254", wantV4: false, wantOnes: 128},
		{name: "bare ipv4 host -> /32", in: "192.0.2.1", wantV4: true, wantOnes: 32},
		{name: "garbage errors", in: "not-a-cidr", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ipnet, err := linux.ParseCIDR(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("linux.ParseCIDR(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if (ipnet.IP.To4() != nil) != tt.wantV4 {
				t.Errorf("family v4 = %v, want %v", ipnet.IP.To4() != nil, tt.wantV4)
			}
			ones, _ := ipnet.Mask.Size()
			if ones != tt.wantOnes {
				t.Errorf("mask ones = %d, want %d", ones, tt.wantOnes)
			}
		})
	}
}

// TestCidrVerdictRule asserts the address-match rule carries the requested
// verdict and fails closed on a bad CIDR. It builds bare table/chain literals —
// no netlink conn — so it runs on THIS host.
func TestCidrVerdictRule(t *testing.T) {
	t.Parallel()
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "filter"}
	chain := &nftables.Chain{Name: "output", Table: table}

	tests := []struct {
		name    string
		cidr    string
		kind    expr.VerdictKind
		wantErr bool
	}{
		{name: "ipv4 metadata drop", cidr: "169.254.0.0/16", kind: expr.VerdictDrop},
		{name: "ipv6 metadata drop (bare)", cidr: "fd00:ec2::254", kind: expr.VerdictDrop},
		{name: "ipv4 Private accept", cidr: "10.0.0.0/8", kind: expr.VerdictAccept},
		{name: "ipv6 ula accept", cidr: "fc00::/7", kind: expr.VerdictAccept},
		{name: "bad cidr fails closed", cidr: "xyz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule, err := linux.CIDRVerdictRule(table, chain, tt.cidr, tt.kind)
			if (err != nil) != tt.wantErr {
				t.Fatalf("linux.CIDRVerdictRule err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			last, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict)
			if !ok || last.Kind != tt.kind {
				t.Errorf("final expr = %+v, want verdict kind %v", rule.Exprs[len(rule.Exprs)-1], tt.kind)
			}
		})
	}
}

// TestDportAcceptRule asserts the destination-port match encodes the port in
// network byte order and carries an accept verdict. Runs on THIS host.
func TestDportAcceptRule(t *testing.T) {
	t.Parallel()
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: "filter"}
	chain := &nftables.Chain{Name: "output", Table: table}
	rule := linux.DportAcceptRule(table, chain, unix.IPPROTO_TCP, 443)

	// 443 == 0x01BB, big-endian.
	foundPort := false
	for _, e := range rule.Exprs {
		if c, ok := e.(*expr.Cmp); ok && len(c.Data) == 2 && c.Data[0] == 0x01 && c.Data[1] == 0xBB {
			foundPort = true
		}
	}
	if !foundPort {
		t.Errorf("dport 443 not encoded big-endian {0x01,0xBB}; exprs=%+v", rule.Exprs)
	}
	if last, ok := rule.Exprs[len(rule.Exprs)-1].(*expr.Verdict); !ok || last.Kind != expr.VerdictAccept {
		t.Errorf("final expr not accept verdict: %+v", rule.Exprs[len(rule.Exprs)-1])
	}
}

// TestIfname asserts the interface name is padded to the 16-byte IFNAMSIZ field.
func TestIfname(t *testing.T) {
	t.Parallel()
	b := linux.Ifname("lo")
	if len(b) != 16 {
		t.Fatalf("linux.Ifname len = %d, want 16", len(b))
	}
	if b[0] != 'l' || b[1] != 'o' {
		t.Errorf("linux.Ifname prefix = %q, want lo", b[:2])
	}
	for i := 2; i < 16; i++ {
		if b[i] != 0 {
			t.Errorf("linux.Ifname byte %d = %d, want 0 padding", i, b[i])
		}
	}
}

// TestBuildRung1Ruleset builds the full rung-1 ruleset (metadata deny + ct +
// Loopback + ports + Dns + Private) into a netlink conn WITHOUT flushing, proving
// every CIDR/port rule assembles without error. Constructing the conn opens an
// unprivileged netlink socket; if that is unavailable the test skips (the flush —
// which needs CAP_NET_ADMIN — is never reached here). Runs on THIS host when
// netlink is reachable.
func TestBuildRung1Ruleset(t *testing.T) {
	conn, err := nftables.New()
	if err != nil {
		t.Skipf("nftables netlink socket unavailable on this host (no flush attempted): %v", err)
	}
	spec := linux.NftSpec{
		Confined:      true,
		TCPPorts:      []uint16{443},
		Loopback:      true,
		Private:       true,
		DNS:           true,
		MetadataCIDRs: policy.MetadataDenyCIDRs(),
	}
	if err := linux.BuildRung1Ruleset(conn, spec); err != nil {
		t.Fatalf("linux.BuildRung1Ruleset: %v", err)
	}
	// Deliberately NOT flushed: Flush would require CAP_NET_ADMIN in a Netns.
}

// TestDaddrMatchExprsFamilyGuard asserts the address match guards on nfproto
// before indexing the header, and masks to the network — the correctness a
// v4/v6-mixed inet table needs. Runs on THIS host.
func TestDaddrMatchExprsFamilyGuard(t *testing.T) {
	t.Parallel()
	v4, err := linux.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("linux.ParseCIDR v4: %v", err)
	}
	exprs := linux.DaddrMatchExprs(v4)
	// First expr must be the nfproto meta load; a payload load must appear.
	if _, ok := exprs[0].(*expr.Meta); !ok {
		t.Errorf("first expr = %T, want *expr.Meta (nfproto guard)", exprs[0])
	}
	var sawPayload bool
	for _, e := range exprs {
		if _, ok := e.(*expr.Payload); ok {
			sawPayload = true
		}
	}
	if !sawPayload {
		t.Errorf("no payload load in daddr match; exprs=%+v", exprs)
	}
	// The final compare must equal the masked network (10.0.0.0).
	last, ok := exprs[len(exprs)-1].(*expr.Cmp)
	if !ok {
		t.Fatalf("final expr = %T, want *expr.Cmp", exprs[len(exprs)-1])
	}
	if want := net.IPv4(10, 0, 0, 0).To4(); last.Data[0] != want[0] {
		t.Errorf("network compare = %v, want first octet %d", last.Data, want[0])
	}
}

// TestRung1NftEnforcement is the CI-verified enforcement proof for the in-Netns
// nftables filter (SPEC §5.4). Anti-fail-open: it asserts the §5.4 cloud-metadata
// endpoint is DROPPED (not merely unrouted) while a Confined command still runs —
// the negative direction that a blanket blackhole could NOT prove on its own (the
// positive scoping is proven by the M4 spike). It SKIPS on the authoring host
// (Netns/CAP_NET_ADMIN blocked) with a recorded reason and runs only in CI (which
// also needs nf_conntrack + a shell with /dev/tcp).
func TestRung1NftEnforcement(t *testing.T) {
	requireRung1Caps(t)

	ws := t.TempDir()
	for _, carveout := range []string{".git", ".looprig"} {
		if err := os.Mkdir(filepath.Join(ws, carveout), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", carveout, err)
		}
	}
	// This fixture grants Loopback+Private+443+Dns, so the rung-1 nftables ruleset is
	// installed with the metadata hard-deny ahead of the Private accept.
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureBroadNetwork, ws), withBackend(linux.NewBackendRung1()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	// A Confined command must still run (the nft install did not fail closed) AND
	// the metadata IP must be unreachable. bash /dev/tcp with a short timeout dials
	// 169.254.169.254:80; the connect must NOT succeed (SYN dropped at OUTPUT).
	script := `echo RAN; ` +
		`if timeout 2 bash -c 'exec 3<>/dev/tcp/169.254.169.254/80' 2>/dev/null; then echo META_REACHED; else echo META_BLOCKED; fi`
	out, code, err := e.RunCommand(context.Background(), ws, script)
	if err != nil || code != 0 {
		t.Fatalf("RunCommand: err=%v code=%d out=%q", err, code, out)
	}
	s := string(out)
	if !strings.Contains(s, "RAN") {
		t.Errorf("Confined command did not run (nft may have failed closed); out=%q", s)
	}
	if strings.Contains(s, "META_REACHED") || !strings.Contains(s, "META_BLOCKED") {
		t.Errorf("cloud-metadata endpoint was reachable under the linux.Rung-1 nft filter (§5.4 violated); out=%q", s)
	}
}
