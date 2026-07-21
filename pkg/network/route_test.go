package network

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEgressRouteValidationFingerprintAndGuarantees(t *testing.T) {
	direct, err := NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	if direct.Fingerprint() == "" || !direct.TargetGuarantee() || !direct.AddressGuarantee() {
		t.Fatalf("direct route = fingerprint %q target %v address %v", direct.Fingerprint(), direct.TargetGuarantee(), direct.AddressGuarantee())
	}

	const secret = "route-password"
	upstream, err := NewUpstreamRoute("https://proxy-user:"+secret+"@proxy.example:8443", false)
	if err != nil {
		t.Fatal(err)
	}
	if upstream.Fingerprint() == "" || upstream.Fingerprint() == direct.Fingerprint() {
		t.Fatal("route fingerprints are empty or collide")
	}
	if strings.Contains(upstream.Fingerprint(), secret) || strings.Contains(upstream.String(), secret) {
		t.Fatal("route fingerprint or display leaked credentials")
	}
	if !upstream.TargetGuarantee() || upstream.AddressGuarantee() {
		t.Fatalf("upstream guarantees = target %v address %v", upstream.TargetGuarantee(), upstream.AddressGuarantee())
	}
	trusted, err := NewUpstreamRoute("http://proxy.example:8080", true)
	if err != nil || !trusted.AddressGuarantee() {
		t.Fatalf("trusted upstream = %#v, %v", trusted, err)
	}

	for _, raw := range []string{"", "socks5://proxy.example:1080", "http://proxy.example/path", "http://proxy.example:0"} {
		if _, err := NewUpstreamRoute(raw, false); err == nil {
			t.Errorf("invalid upstream %q accepted", raw)
		}
	}
}

func TestRouteResolverCanOnlySelectConfiguredRoutes(t *testing.T) {
	direct, _ := NewDirectRoute()
	upstream, _ := NewUpstreamRoute("http://proxy.example:8080", false)
	resolver, err := NewRouteResolver([]Route{direct, upstream}, func(context.Context, Target) string {
		return upstream.Fingerprint()
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseTarget("tcp:example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Resolve(context.Background(), target)
	if err != nil || got.Fingerprint() != upstream.Fingerprint() {
		t.Fatalf("Resolve = %q, %v", got.Fingerprint(), err)
	}

	bad, err := NewRouteResolver([]Route{direct}, func(context.Context, Target) string { return "not-configured" })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Resolve(context.Background(), target); !errors.Is(err, ErrRouteDenied) {
		t.Fatalf("unconfigured selection error = %v, want ErrRouteDenied", err)
	}
}
