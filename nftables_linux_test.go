//go:build linux

package sandbox

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// TestCompileNftPlan asserts the pure effectiveNetPolicy -> nftables plan compilation
// (SPEC §5.2, §5.4, §7.2 rung 1): open egress is unconfined (no ruleset, no
// netns); every other policy is confined with the metadata deny always present
// and each accept gated by its flag. Runs on THIS host — no netlink.
func TestCompileNftPlan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		net          effectiveNetPolicy
		wantConfined bool
		wantPorts    []uint16
		wantLoopback bool
		wantPrivate  bool
		wantDNS      bool
		wantMetadata bool
	}{
		{name: "open egress: unconfined, no ruleset", net: effectiveNetPolicy{Open: true}, wantConfined: false},
		{name: "zerotrust (all-false): confined, everything dropped, metadata denied", net: effectiveNetPolicy{}, wantConfined: true, wantMetadata: true},
		{
			name:         "trusted: ports+loopback+private+dns, metadata denied",
			net:          effectiveNetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true},
			wantConfined: true, wantPorts: []uint16{443}, wantLoopback: true, wantPrivate: true, wantDNS: true, wantMetadata: true,
		},
		{
			name:         "duplicate ports deduped",
			net:          effectiveNetPolicy{Ports: []uint16{443, 443, 80}},
			wantConfined: true, wantPorts: []uint16{443, 80}, wantMetadata: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := compileNftPlan(tt.net)
			if plan.confined != tt.wantConfined {
				t.Fatalf("confined = %v, want %v", plan.confined, tt.wantConfined)
			}
			if !tt.wantConfined {
				if len(plan.metadataCIDRs) != 0 {
					t.Errorf("open policy carries metadata CIDRs: %v", plan.metadataCIDRs)
				}
				return
			}
			if len(plan.tcpPorts) != len(tt.wantPorts) {
				t.Errorf("tcpPorts = %v, want %v", plan.tcpPorts, tt.wantPorts)
			}
			if plan.loopback != tt.wantLoopback || plan.private != tt.wantPrivate || plan.dns != tt.wantDNS {
				t.Errorf("flags loopback/private/dns = %v/%v/%v, want %v/%v/%v",
					plan.loopback, plan.private, plan.dns, tt.wantLoopback, tt.wantPrivate, tt.wantDNS)
			}
			if tt.wantMetadata && len(plan.metadataCIDRs) == 0 {
				t.Errorf("metadata deny CIDRs missing on a confined policy")
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
			ipnet, err := parseCIDR(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseCIDR(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
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
		{name: "ipv4 private accept", cidr: "10.0.0.0/8", kind: expr.VerdictAccept},
		{name: "ipv6 ula accept", cidr: "fc00::/7", kind: expr.VerdictAccept},
		{name: "bad cidr fails closed", cidr: "xyz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule, err := cidrVerdictRule(table, chain, tt.cidr, tt.kind)
			if (err != nil) != tt.wantErr {
				t.Fatalf("cidrVerdictRule err = %v, wantErr %v", err, tt.wantErr)
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
	rule := dportAcceptRule(table, chain, unix.IPPROTO_TCP, 443)

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
	b := ifname("lo")
	if len(b) != 16 {
		t.Fatalf("ifname len = %d, want 16", len(b))
	}
	if b[0] != 'l' || b[1] != 'o' {
		t.Errorf("ifname prefix = %q, want lo", b[:2])
	}
	for i := 2; i < 16; i++ {
		if b[i] != 0 {
			t.Errorf("ifname byte %d = %d, want 0 padding", i, b[i])
		}
	}
}

// TestBuildRung1Ruleset builds the full rung-1 ruleset (metadata deny + ct +
// loopback + ports + dns + private) into a netlink conn WITHOUT flushing, proving
// every CIDR/port rule assembles without error. Constructing the conn opens an
// unprivileged netlink socket; if that is unavailable the test skips (the flush —
// which needs CAP_NET_ADMIN — is never reached here). Runs on THIS host when
// netlink is reachable.
func TestBuildRung1Ruleset(t *testing.T) {
	conn, err := nftables.New()
	if err != nil {
		t.Skipf("nftables netlink socket unavailable on this host (no flush attempted): %v", err)
	}
	spec := NftSpec{
		Confined:      true,
		TCPPorts:      []uint16{443},
		Loopback:      true,
		Private:       true,
		DNS:           true,
		MetadataCIDRs: metadataDenyCIDRs(),
	}
	if err := buildRung1Ruleset(conn, spec); err != nil {
		t.Fatalf("buildRung1Ruleset: %v", err)
	}
	// Deliberately NOT flushed: Flush would require CAP_NET_ADMIN in a netns.
}

// TestDaddrMatchExprsFamilyGuard asserts the address match guards on nfproto
// before indexing the header, and masks to the network — the correctness a
// v4/v6-mixed inet table needs. Runs on THIS host.
func TestDaddrMatchExprsFamilyGuard(t *testing.T) {
	t.Parallel()
	v4, err := parseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parseCIDR v4: %v", err)
	}
	exprs := daddrMatchExprs(v4)
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

// TestRung1NftEnforcement is the CI-verified enforcement proof for the in-netns
// nftables filter (SPEC §5.4). Anti-fail-open: it asserts the §5.4 cloud-metadata
// endpoint is DROPPED (not merely unrouted) while a confined command still runs —
// the negative direction that a blanket blackhole could NOT prove on its own (the
// positive scoping is proven by the M4 spike). It SKIPS on the authoring host
// (netns/CAP_NET_ADMIN blocked) with a recorded reason and runs only in CI (which
// also needs nf_conntrack + a shell with /dev/tcp).
func TestRung1NftEnforcement(t *testing.T) {
	requireRung1Caps(t)

	ws := t.TempDir()
	// This fixture grants loopback+private+443+dns, so the rung-1 nftables ruleset is
	// installed with the metadata hard-deny ahead of the Private accept.
	e, err := newExecutorForEffectivePolicy(testPolicy(testBroadNetwork, ws), withBackend(newLinuxBackendRung1()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	// A confined command must still run (the nft install did not fail closed) AND
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
		t.Errorf("confined command did not run (nft may have failed closed); out=%q", s)
	}
	if strings.Contains(s, "META_REACHED") || !strings.Contains(s, "META_BLOCKED") {
		t.Errorf("cloud-metadata endpoint was reachable under the rung-1 nft filter (§5.4 violated); out=%q", s)
	}
}
