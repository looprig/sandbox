package network

import (
	"context"
	"errors"
	"net"
	"net/url"
)

// ErrClosed reports that a proxy refused an authorization because the executor
// that owns it is shutting down. It is the same sentinel the executor layer
// exposes as ErrExecutorClosed: one value, so errors.Is answers the same way
// whichever side of the boundary raised it.
var ErrClosed = errors.New("sandbox: executor closed")

// UnparseableTarget is the placeholder recorded against an execution when a
// proxied request carried a target that could not be parsed at all. It is
// deliberately a value no real target can equal, so a denial is still audited
// without inventing a plausible-looking host.
var UnparseableTarget = Target{transport: "tcp", host: "invalid", port: 1}

// IsDirect reports whether the route dials targets itself rather than handing
// them to an upstream proxy.
func (route Route) IsDirect() bool { return route.kind == routeDirect }

// Upstream returns the upstream proxy endpoint, or nil for a direct route.
// The returned URL is the route's own; callers must not mutate it.
func (route Route) Upstream() *url.URL { return route.upstream }

// LookupFunc resolves a host to the addresses a route may connect to.
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// DialFunc opens a connection to an already-resolved address.
type DialFunc func(ctx context.Context, transport, address string) (net.Conn, error)

// WithDialer returns a copy of route that resolves and dials through the
// supplied collaborators; a nil argument leaves that collaborator unchanged.
//
// This narrows nothing and widens nothing: DialTarget still rejects any
// resolved address outside the public destination space, so a substituted
// resolver cannot be used to reach loopback, link-local, or metadata addresses.
// The route's fingerprint is deliberately unchanged, because a fingerprint
// identifies the route's authority — its kind, endpoint, and guarantees — and
// not the machinery it uses to reach the network.
func (route Route) WithDialer(lookup LookupFunc, dial DialFunc) Route {
	if lookup != nil {
		route.lookup = lookup
	}
	if dial != nil {
		route.dial = dial
	}
	return route
}

// Route returns the egress route this proxy was constructed with.
func (proxy *Proxy) Route() Route {
	if proxy == nil {
		return Route{}
	}
	return proxy.route
}

// NewTargetDeniedError builds the typed error an executor returns when a spawn
// ran to completion but the proxy denied one of its network targets. The denial
// itself stays unexported so it can only be read through Error(), which keeps
// the denied host out of any caller that merely formats the wrapped sentinel.
func NewTargetDeniedError(exitCode int, processErr, denial error) *TargetDeniedError {
	return &TargetDeniedError{ExitCode: exitCode, ProcessError: processErr, denial: denial}
}
