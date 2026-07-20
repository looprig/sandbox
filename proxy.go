package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrNetworkTargetDenied = errors.New("sandbox: network target denied")

var errNetworkAddressDenied = errors.New("sandbox: resolved network address denied")

// NetworkTargetDeniedError preserves the completed process result while making
// an authenticated proxy denial the primary typed error.
type NetworkTargetDeniedError struct {
	ExitCode     int
	ProcessError error
	denial       error
}

func (err *NetworkTargetDeniedError) Error() string {
	if err == nil {
		return ErrNetworkTargetDenied.Error()
	}
	return fmt.Sprintf("%v (process exit %d)", err.denial, err.ExitCode)
}

func (err *NetworkTargetDeniedError) Unwrap() error { return ErrNetworkTargetDenied }

const (
	proxyHeaderTimeout           = 10 * time.Second
	proxyCONNECTHandshakeTimeout = 10 * time.Second
	proxyIdleTimeout             = 30 * time.Second
	proxyMaxHeader               = 64 << 10
)

type proxyAuthorization struct {
	credentialHash [32]byte
	targets        map[string]struct{}
	allowAll       bool
	denial         error
	ctx            context.Context
	cancel         context.CancelFunc
}

type egressProxy struct {
	route      EgressRoute
	listener   net.Listener
	server     *http.Server
	mu         sync.Mutex
	executions map[string]*proxyAuthorization
	tunnels    map[*proxyTunnel]struct{}
	closing    bool
	closeOnce  sync.Once
	closeErr   error

	// connectHandshakeTimeout is an unexported deterministic timeout seam.
	// Production proxies use proxyCONNECTHandshakeTimeout.
	connectHandshakeTimeout time.Duration

	// beforeTunnelRegister is an unexported deterministic race seam used only by
	// tests; production proxies leave it nil.
	beforeTunnelRegister func()
}

type proxyTunnel struct {
	child    net.Conn
	upstream net.Conn
}

func newEgressProxy(route EgressRoute) (*egressProxy, error) {
	if err := route.validate(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("sandbox: listen for egress proxy: %w", err)
	}
	proxy := &egressProxy{
		route: route, listener: listener, executions: make(map[string]*proxyAuthorization),
		tunnels: make(map[*proxyTunnel]struct{}), connectHandshakeTimeout: proxyCONNECTHandshakeTimeout,
	}
	proxy.server = &http.Server{
		Handler: proxy, ReadHeaderTimeout: proxyHeaderTimeout,
		IdleTimeout: proxyIdleTimeout, MaxHeaderBytes: proxyMaxHeader,
	}
	go func() { _ = proxy.server.Serve(listener) }()
	return proxy, nil
}

func (proxy *egressProxy) Addr() string {
	if proxy == nil || proxy.listener == nil {
		return ""
	}
	return proxy.listener.Addr().String()
}

func (proxy *egressProxy) Authorize(executionID string, targets []NetworkTarget) (string, error) {
	if proxy == nil || !validGrantText(executionID) || len(targets) == 0 {
		return "", errors.New("sandbox: invalid proxy authorization")
	}
	return proxy.authorize(executionID, targets, false)
}

func (proxy *egressProxy) authorizeAll(executionID string) (string, error) {
	return proxy.authorize(executionID, nil, true)
}

func (proxy *egressProxy) authorize(executionID string, targets []NetworkTarget, allowAll bool) (string, error) {
	if proxy == nil || !validGrantText(executionID) || (!allowAll && len(targets) == 0) {
		return "", errors.New("sandbox: invalid proxy authorization")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("sandbox: proxy credential: %w", err)
	}
	credential := base64.RawURLEncoding.EncodeToString(secret)
	authorization := &proxyAuthorization{credentialHash: sha256.Sum256([]byte(credential)), targets: make(map[string]struct{}, len(targets)), allowAll: allowAll}
	for _, target := range targets {
		if target.String() == "" {
			return "", errors.New("sandbox: invalid proxy target")
		}
		authorization.targets[target.String()] = struct{}{}
	}
	authorization.ctx, authorization.cancel = context.WithCancel(context.Background())
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.closing || proxy.executions == nil {
		authorization.cancel()
		return "", ErrExecutorClosed
	}
	if _, exists := proxy.executions[executionID]; exists {
		return "", errors.New("sandbox: execution already authorized")
	}
	proxy.executions[executionID] = authorization
	return credential, nil
}

func (proxy *egressProxy) URL(executionID, credential string) string {
	if proxy == nil || !validGrantText(executionID) || credential == "" {
		return ""
	}
	return (&url.URL{Scheme: "http", Host: proxy.Addr(), User: url.UserPassword(executionID, credential)}).String()
}

func (proxy *egressProxy) Release(executionID string) {
	if proxy == nil {
		return
	}
	proxy.mu.Lock()
	authorization := proxy.executions[executionID]
	delete(proxy.executions, executionID)
	proxy.mu.Unlock()
	if authorization != nil {
		authorization.cancel()
	}
}

func (proxy *egressProxy) Denial(executionID string) error {
	if proxy == nil {
		return nil
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if authorization := proxy.executions[executionID]; authorization != nil {
		return authorization.denial
	}
	return nil
}

func (proxy *egressProxy) authenticate(request *http.Request) (string, *proxyAuthorization, bool) {
	header := request.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", nil, false
	}
	executionID, credential, ok := strings.Cut(string(decoded), ":")
	if !ok || executionID == "" || credential == "" {
		return "", nil, false
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	authorization := proxy.executions[executionID]
	gotHash := sha256.Sum256([]byte(credential))
	if authorization == nil || subtle.ConstantTimeCompare(authorization.credentialHash[:], gotHash[:]) != 1 {
		return "", nil, false
	}
	return executionID, authorization, true
}

func (proxy *egressProxy) recordDenial(executionID string, target NetworkTarget) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if authorization := proxy.executions[executionID]; authorization != nil && authorization.denial == nil {
		authorization.denial = fmt.Errorf("%w: %s", ErrNetworkTargetDenied, target.String())
	}
}

func (proxy *egressProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	executionID, authorization, authenticated := proxy.authenticate(request)
	if !authenticated {
		writer.Header().Set("Proxy-Authenticate", `Basic realm="sandbox"`)
		http.Error(writer, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	requestContext, cancel := context.WithCancel(request.Context())
	stop := context.AfterFunc(authorization.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	request = request.WithContext(requestContext)
	target, err := targetForRequest(request)
	if err != nil {
		proxy.recordDenial(executionID, NetworkTarget{transport: "tcp", host: "invalid", port: 1})
		http.Error(writer, "network target denied", http.StatusForbidden)
		return
	}
	if _, allowed := authorization.targets[target.String()]; !allowed && !authorization.allowAll {
		proxy.recordDenial(executionID, target)
		http.Error(writer, "network target denied", http.StatusForbidden)
		return
	}
	request.Header.Del("Proxy-Authorization")
	if request.Method == http.MethodConnect {
		proxy.serveConnect(writer, request, executionID, target)
		return
	}
	proxy.serveHTTP(writer, request, executionID, target)
}

func targetForRequest(request *http.Request) (NetworkTarget, error) {
	address := request.Host
	if request.Method != http.MethodConnect {
		if request.URL == nil || !request.URL.IsAbs() || request.URL.Scheme != "http" {
			return NetworkTarget{}, errors.New("sandbox: proxy requires an absolute HTTP URL")
		}
		address = request.URL.Host
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		if request.Method != http.MethodConnect && !strings.Contains(address, ":") {
			host, port = address, "80"
		} else {
			return NetworkTarget{}, err
		}
	}
	return ParseNetworkTarget("tcp:" + net.JoinHostPort(host, port))
}

func (proxy *egressProxy) serveHTTP(writer http.ResponseWriter, request *http.Request, executionID string, target NetworkTarget) {
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.Header = request.Header.Clone()
	removeHopHeaders(outbound.Header)
	transport := &http.Transport{DisableKeepAlives: false, IdleConnTimeout: proxyIdleTimeout}
	if proxy.route.kind == routeDirect {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return proxy.route.dialTarget(ctx, target)
		}
	} else {
		transport.Proxy = http.ProxyURL(proxy.route.upstream)
		transport.DialContext = proxy.route.dial
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		if errors.Is(err, errNetworkAddressDenied) {
			proxy.recordDenial(executionID, target)
		}
		http.Error(writer, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

func (proxy *egressProxy) serveConnect(writer http.ResponseWriter, request *http.Request, executionID string, target NetworkTarget) {
	upstream, err := proxy.dialTunnel(request.Context(), target)
	if err != nil {
		if errors.Is(err, errNetworkAddressDenied) {
			proxy.recordDenial(executionID, target)
		}
		http.Error(writer, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "tunneling unsupported", http.StatusInternalServerError)
		return
	}
	child, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = child.Close()
		_ = upstream.Close()
		return
	}
	pair := &proxyTunnel{child: &idleTimeoutConn{Conn: child, timeout: proxyIdleTimeout}, upstream: &idleTimeoutConn{Conn: upstream, timeout: proxyIdleTimeout}}
	stopRelease := context.AfterFunc(request.Context(), func() {
		_ = pair.child.Close()
		_ = pair.upstream.Close()
	})
	defer stopRelease()
	if proxy.beforeTunnelRegister != nil {
		proxy.beforeTunnelRegister()
	}
	proxy.mu.Lock()
	if proxy.closing {
		proxy.mu.Unlock()
		_ = pair.child.Close()
		_ = pair.upstream.Close()
		return
	}
	proxy.tunnels[pair] = struct{}{}
	proxy.mu.Unlock()
	tunnel(pair.child, pair.upstream)
	proxy.mu.Lock()
	delete(proxy.tunnels, pair)
	proxy.mu.Unlock()
}

func (proxy *egressProxy) dialTunnel(ctx context.Context, target NetworkTarget) (net.Conn, error) {
	if proxy.route.kind == routeDirect {
		return proxy.route.dialTarget(ctx, target)
	}
	upstream, err := proxy.route.dialUpstream(ctx)
	if err != nil {
		return nil, err
	}
	owned := newContextOwnedConn(ctx, upstream)
	succeeded := false
	defer func() {
		if !succeeded {
			_ = owned.Close()
		}
	}()
	timeout := proxy.connectHandshakeTimeout
	if timeout <= 0 {
		timeout = proxyCONNECTHandshakeTimeout
	}
	if err := owned.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target.address()}, Host: target.address(), Header: make(http.Header)}
	if proxy.route.upstream.User != nil {
		username := proxy.route.upstream.User.Username()
		password, _ := proxy.route.upstream.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	if err := request.Write(owned); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(owned), request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, errors.New("sandbox: upstream proxy rejected CONNECT")
	}
	if err := owned.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	succeeded = true
	return owned, nil
}

// contextOwnedConn keeps cancellation ownership attached to a successful
// upstream connection until tunnel teardown. Closing it stops the callback on
// normal exit; cancellation closes the underlying connection to unblock any
// handshake or tunnel I/O.
type contextOwnedConn struct {
	net.Conn
	stop context.CancelFunc
	once sync.Once
	err  error
}

func newContextOwnedConn(ctx context.Context, connection net.Conn) *contextOwnedConn {
	owned := &contextOwnedConn{Conn: connection}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	owned.stop = func() { stop() }
	return owned
}

func (connection *contextOwnedConn) Close() error {
	connection.once.Do(func() {
		connection.stop()
		connection.err = connection.Conn.Close()
	})
	return connection.err
}

type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *idleTimeoutConn) Read(buffer []byte) (int, error) {
	_ = connection.SetReadDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Read(buffer)
}

func (connection *idleTimeoutConn) Write(buffer []byte) (int, error) {
	_ = connection.SetWriteDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Write(buffer)
}

func (route EgressRoute) dialTarget(ctx context.Context, target NetworkTarget) (net.Conn, error) {
	addresses, err := route.lookup(ctx, target.host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("sandbox: target resolution failed")
	}
	for _, address := range addresses {
		if !publicDestination(address) {
			return nil, errNetworkAddressDenied
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

// deniedDestinationPrefixes is deliberately explicit and conservative. A
// direct route claims address-class enforcement, so an ambiguous IANA
// special-purpose destination is denied rather than treated as public. Keep
// this table auditable alongside TestPublicDestinationRejectsSpecialUsePrefixes.
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

func (route EgressRoute) dialUpstream(ctx context.Context) (net.Conn, error) {
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

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func tunnel(left, right net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyHalf(right, left)
	go copyHalf(left, right)
	wait.Wait()
	_ = left.Close()
	_ = right.Close()
}

func (proxy *egressProxy) Close() error {
	if proxy == nil {
		return nil
	}
	proxy.closeOnce.Do(func() {
		proxy.mu.Lock()
		proxy.closing = true
		for _, authorization := range proxy.executions {
			authorization.cancel()
		}
		for pair := range proxy.tunnels {
			_ = pair.child.Close()
			_ = pair.upstream.Close()
		}
		proxy.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), proxyHeaderTimeout)
		defer cancel()
		proxy.closeErr = proxy.server.Shutdown(ctx)
		if proxy.closeErr == nil {
			proxy.closeErr = proxy.listener.Close()
			if errors.Is(proxy.closeErr, net.ErrClosed) {
				proxy.closeErr = nil
			}
		}
		proxy.mu.Lock()
		proxy.executions = nil
		proxy.mu.Unlock()
	})
	return proxy.closeErr
}
