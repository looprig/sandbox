package network

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ErrAddressDenied reports that a target resolved to an address outside the
// public destination space a route is permitted to reach.
var ErrAddressDenied = errors.New("sandbox: resolved network address denied")

// DialTarget resolves target through the route's resolver and connects to the
// first address that answers. Every resolved address must be a public
// destination: if any one of them is not, the whole dial fails with
// ErrAddressDenied rather than silently trying the remaining addresses, so a
// DNS answer that mixes public and private records cannot reach the private one.
func (route Route) DialTarget(ctx context.Context, target Target) (net.Conn, error) {
	addresses, err := route.lookup(ctx, target.host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("sandbox: target resolution failed")
	}
	for _, address := range addresses {
		if !publicDestination(address) {
			return nil, ErrAddressDenied
		}
	}
	var lastErr error
	for _, address := range addresses {
		connection, err := route.dial(ctx, "tcp", net.JoinHostPort(address.String(), fmt.Sprint(target.port)))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("sandbox: target connection failed: %w", lastErr)
}

// DialUpstream connects to the route's upstream proxy, wrapping the connection
// in TLS when the endpoint is https.
func (route Route) DialUpstream(ctx context.Context) (net.Conn, error) {
	connection, err := route.dial(ctx, "tcp", route.upstream.Host)
	if err != nil {
		return nil, errors.New("sandbox: upstream proxy unavailable")
	}
	if route.upstream.Scheme == "https" {
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: route.upstream.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, errors.New("sandbox: upstream proxy TLS failed")
		}
		return tlsConnection, nil
	}
	return connection, nil
}

var deniedDestinationPrefixes = []netip.Prefix{
	// IPv4 special-purpose, local, metadata, documentation, and reserved space.
	netip.MustParsePrefix("0.0.0.0/8"),          // this network
	netip.MustParsePrefix("10.0.0.0/8"),         // private-use
	netip.MustParsePrefix("100.64.0.0/10"),      // shared address space / CGNAT
	netip.MustParsePrefix("100.100.100.200/32"), // known cloud metadata endpoint
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local and common metadata
	netip.MustParsePrefix("172.16.0.0/12"),      // private-use
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("192.31.196.0/24"),    // AS112-v4
	netip.MustParsePrefix("192.52.193.0/24"),    // AMT
	netip.MustParsePrefix("192.88.99.0/24"),     // deprecated 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),     // private-use
	netip.MustParsePrefix("192.175.48.0/24"),    // AS112 direct delegation
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved and limited broadcast

	// IPv6 special-purpose, transition, local, documentation, and multicast.
	netip.MustParsePrefix("::/96"),             // unspecified/IPv4-compatible
	netip.MustParsePrefix("::1/128"),           // loopback
	netip.MustParsePrefix("::ffff:0:0:0/96"),   // IPv4-translated
	netip.MustParsePrefix("64:ff9b::/96"),      // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),    // NAT64 local-use prefix
	netip.MustParsePrefix("100::/64"),          // discard-only
	netip.MustParsePrefix("2001::/23"),         // IETF protocol assignments
	netip.MustParsePrefix("2001:db8::/32"),     // documentation
	netip.MustParsePrefix("2002::/16"),         // 6to4
	netip.MustParsePrefix("2620:4f:8000::/48"), // AS112 direct delegation
	netip.MustParsePrefix("3fff::/20"),         // documentation
	netip.MustParsePrefix("5f00::/16"),         // segment-routing SIDs
	netip.MustParsePrefix("fc00::/7"),          // unique-local
	netip.MustParsePrefix("fe80::/10"),         // link-local
	netip.MustParsePrefix("fec0::/10"),         // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),          // multicast
}

// publicDestination reports whether ip lies outside every denied prefix.
func publicDestination(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, denied := range deniedDestinationPrefixes {
		if denied.Contains(address) {
			return false
		}
	}
	return true
}
