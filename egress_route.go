package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrEgressRouteDenied = errors.New("sandbox: egress route denied")

type egressRouteKind uint8

const (
	routeDirect egressRouteKind = iota + 1
	routeUpstream
)

// NetworkTarget is a normalized transport, hostname, and port tuple.
type NetworkTarget struct {
	transport string
	host      string
	port      uint16
}

// ParseNetworkTarget accepts the v1 tcp:<host>:<port> grant target.
func ParseNetworkTarget(raw string) (NetworkTarget, error) {
	const prefix = "tcp:"
	if !strings.HasPrefix(raw, prefix) {
		return NetworkTarget{}, errors.New("sandbox: network target transport must be tcp")
	}
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(raw, prefix))
	if err != nil {
		return NetworkTarget{}, fmt.Errorf("sandbox: network target: %w", err)
	}
	host, err = normalizeTargetHost(host)
	if err != nil {
		return NetworkTarget{}, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return NetworkTarget{}, errors.New("sandbox: network target port is invalid")
	}
	return NetworkTarget{transport: "tcp", host: host, port: uint16(port)}, nil
}

func normalizeTargetHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || strings.ContainsAny(host, "\x00/%@ ") {
		return "", errors.New("sandbox: network target hostname is invalid")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if len(host) > 253 {
		return "", errors.New("sandbox: network target hostname is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("sandbox: network target hostname is invalid")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
				return "", errors.New("sandbox: network target hostname must be ASCII")
			}
		}
	}
	return host, nil
}

func (target NetworkTarget) String() string {
	if target.transport == "" || target.host == "" || target.port == 0 {
		return ""
	}
	return target.transport + ":" + net.JoinHostPort(target.host, strconv.Itoa(int(target.port)))
}

func (target NetworkTarget) Transport() string { return target.transport }
func (target NetworkTarget) Hostname() string  { return target.host }
func (target NetworkTarget) Port() uint16      { return target.port }

func (target NetworkTarget) address() string {
	return net.JoinHostPort(target.host, strconv.Itoa(int(target.port)))
}

// EgressRoute is a validated, immutable route description. Secret upstream
// credentials are kept only in the private URL and excluded from identity.
type EgressRoute struct {
	kind             egressRouteKind
	upstream         *url.URL
	fingerprint      string
	targetGuarantee  bool
	addressGuarantee bool
	lookup           func(context.Context, string) ([]net.IP, error)
	dial             func(context.Context, string, string) (net.Conn, error)
}

// NewDirectEgressRoute creates an explicit direct route with local DNS and
// address-class validation.
func NewDirectEgressRoute() (EgressRoute, error) {
	route := EgressRoute{
		kind: routeDirect, targetGuarantee: true, addressGuarantee: true,
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		},
		dial: (&net.Dialer{}).DialContext,
	}
	route.fingerprint = fingerprintRoute("direct", "", true)
	return route, nil
}

// NewUpstreamEgressRoute creates an explicit HTTP or HTTPS organization proxy
// route. trustedAddressGuarantee is asserted only when the upstream contract
// guarantees resolved-address filtering.
func NewUpstreamEgressRoute(rawURL string, trustedAddressGuarantee bool) (EgressRoute, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return EgressRoute{}, errors.New("sandbox: upstream proxy must use http or https")
	}
	if parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return EgressRoute{}, errors.New("sandbox: upstream proxy URL must contain only authority")
	}
	host, err := normalizeTargetHost(parsed.Hostname())
	if err != nil {
		return EgressRoute{}, errors.New("sandbox: upstream proxy host is invalid")
	}
	portText := parsed.Port()
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return EgressRoute{}, errors.New("sandbox: upstream proxy port is invalid")
	}
	parsed.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	route := EgressRoute{
		kind: routeUpstream, upstream: parsed, targetGuarantee: true,
		addressGuarantee: trustedAddressGuarantee,
		dial:             (&net.Dialer{}).DialContext,
	}
	route.fingerprint = fingerprintRoute(parsed.Scheme, parsed.Host, trustedAddressGuarantee)
	return route, nil
}

func fingerprintRoute(kind, endpoint string, addressGuarantee bool) string {
	payload, _ := json.Marshal(struct {
		Version          uint16
		Kind             string
		Endpoint         string
		AddressGuarantee bool
	}{1, kind, endpoint, addressGuarantee})
	digest := sha256.Sum256(payload)
	return "route-v1:" + hex.EncodeToString(digest[:])
}

func (route EgressRoute) validate() error {
	if route.fingerprint == "" || !route.targetGuarantee || route.dial == nil {
		return errors.New("sandbox: invalid egress route")
	}
	if route.kind == routeDirect && route.lookup == nil {
		return errors.New("sandbox: direct route has no resolver")
	}
	if route.kind == routeUpstream && route.upstream == nil {
		return errors.New("sandbox: upstream route has no endpoint")
	}
	return nil
}

func (route EgressRoute) Fingerprint() string {
	if route.validate() != nil {
		return ""
	}
	return route.fingerprint
}

func (route EgressRoute) TargetGuarantee() bool {
	return route.validate() == nil && route.targetGuarantee
}
func (route EgressRoute) AddressGuarantee() bool {
	return route.validate() == nil && route.addressGuarantee
}

func (route EgressRoute) String() string {
	if route.validate() != nil {
		return "invalid"
	}
	if route.kind == routeDirect {
		return "direct"
	}
	return route.upstream.Scheme + "://" + route.upstream.Host
}

// EgressRouteResolver confines a consumer selector to prevalidated routes.
type EgressRouteResolver struct {
	routes      map[string]EgressRoute
	selectRoute func(context.Context, NetworkTarget) string
}

func NewEgressRouteResolver(routes []EgressRoute, selector func(context.Context, NetworkTarget) string) (*EgressRouteResolver, error) {
	if len(routes) == 0 || selector == nil {
		return nil, errors.New("sandbox: route resolver requires routes and selector")
	}
	configured := make(map[string]EgressRoute, len(routes))
	for _, route := range routes {
		if err := route.validate(); err != nil {
			return nil, err
		}
		if _, duplicate := configured[route.fingerprint]; duplicate {
			return nil, errors.New("sandbox: duplicate egress route")
		}
		configured[route.fingerprint] = route
	}
	return &EgressRouteResolver{routes: configured, selectRoute: selector}, nil
}

func (resolver *EgressRouteResolver) Resolve(ctx context.Context, target NetworkTarget) (EgressRoute, error) {
	if resolver == nil || resolver.selectRoute == nil || target.String() == "" {
		return EgressRoute{}, ErrEgressRouteDenied
	}
	identity := resolver.selectRoute(ctx, target)
	if err := ctx.Err(); err != nil {
		return EgressRoute{}, err
	}
	route, ok := resolver.routes[identity]
	if !ok {
		return EgressRoute{}, ErrEgressRouteDenied
	}
	return route, nil
}
