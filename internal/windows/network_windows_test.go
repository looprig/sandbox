//go:build windows

package windows

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	sandboxnetwork "github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

func TestTask20ReservedListenerHandoffKeepsEveryOtherPortDenyOnly(t *testing.T) {
	binder := &networkContractBinder{}
	locker := &fakeInstallationLocker{}
	reservation, err := reserveProxyPorts(
		"installation",
		[]uint16{39003, 39001, 39002},
		binder,
		locker,
		fakePortOwner{},
	)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := reservation.ClaimProxy(39002)
	if err != nil {
		t.Fatal(err)
	}
	route, err := sandboxnetwork.NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := sandboxnetwork.NewProxyWithListener(route, listener)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proxy.Addr(), "127.0.0.1:39002"; got != want {
		t.Fatalf("proxy endpoint = %q, want reserved endpoint %q", got, want)
	}
	if got, want := binder.bound, []uint16{39001, 39002, 39003}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bind order = %v, want all configured ports reserved first as %v", got, want)
	}
	if binder.bindings[39002].activations != 1 {
		t.Fatalf("proxy endpoint activations = %d, want one-way activation", binder.bindings[39002].activations)
	}
	for _, port := range []uint16{39001, 39003} {
		if !reservation.IsGuard(port) || binder.bindings[port].activations != 0 {
			t.Fatalf("unused port %d did not remain a deny-only guard", port)
		}
	}

	// Proxy owns the claimed listener after successful construction. The
	// reservation still owns the installation lock and every guard; both close
	// paths are deliberately idempotent because executor and host cleanup race.
	if err := proxy.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := reservation.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	if !locker.released {
		t.Fatal("port reservation did not release the installation lock")
	}
}

func TestTask20ElevatedBackendReservesVerifiedPortsAndSelectsDeterministicEndpoint(t *testing.T) {
	binder := &networkContractBinder{}
	locker := &fakeInstallationLocker{}
	snapshot := readyElevatedSnapshot()
	snapshot.OwnerSID = "S-1-5-21-1-2-3-1001"
	snapshot.ProxyPorts = []uint16{39003, 39001, 39002}
	var reservedSnapshot elevatedSetupSnapshot
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return snapshot, nil
		},
		reserve: func(got elevatedSetupSnapshot) (*proxyPortReservation, error) {
			reservedSnapshot = got
			return reserveProxyPorts(got.InstallationID, got.ProxyPorts, binder, locker, fakePortOwner{})
		},
	}}
	route, err := sandboxnetwork.NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	proxy, release, err := backend.ReserveEgressProxy(route)
	if err != nil {
		t.Fatal(err)
	}
	if reservedSnapshot.InstallationID != snapshot.InstallationID ||
		reservedSnapshot.OwnerSID != snapshot.OwnerSID ||
		!reflect.DeepEqual(reservedSnapshot.ProxyPorts, snapshot.ProxyPorts) {
		t.Fatalf("reservation snapshot = %+v, want verified identity and ports %+v", reservedSnapshot, snapshot)
	}
	if got, want := proxy.Addr(), "127.0.0.1:39001"; got != want {
		t.Fatalf("proxy endpoint = %q, want deterministic lowest configured endpoint %q", got, want)
	}
	if got, want := binder.bound, []uint16{39001, 39002, 39003}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bound ports = %v, want %v", got, want)
	}
	if err := proxy.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("reservation cleanup was not idempotent: %v", err)
	}
	if !locker.released {
		t.Fatal("reservation cleanup did not release the protected installation lock")
	}
}

func TestTask20ElevatedBackendRefusesStaleSetupBeforePortAuthority(t *testing.T) {
	snapshot := readyElevatedSnapshot()
	snapshot.FirewallReady = false
	reserves := 0
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return snapshot, nil
		},
		reserve: func(elevatedSetupSnapshot) (*proxyPortReservation, error) {
			reserves++
			return nil, errors.New("must not be called")
		},
	}}
	route, err := sandboxnetwork.NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := backend.ReserveEgressProxy(route); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("stale setup error = %v, want ErrSetupStale", err)
	}
	if reserves != 0 {
		t.Fatal("stale setup consumed port reservation authority")
	}
}

func TestTask20AutoForwardsReservedProxyCapabilityWithoutEphemeralFallback(t *testing.T) {
	snapshot := readyElevatedSnapshot()
	snapshot.OwnerSID = "S-1-5-21-1-2-3-1001"
	snapshot.ProxyPorts = []uint16{39002}
	binder := &networkContractBinder{}
	elevated := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return snapshot, nil },
		reserve: func(got elevatedSetupSnapshot) (*proxyPortReservation, error) {
			return reserveProxyPorts(got.InstallationID, got.ProxyPorts, binder, &fakeInstallationLocker{}, fakePortOwner{})
		},
	}}
	backend := &autoBackend{elevated: elevated}
	route, err := sandboxnetwork.NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	proxy, release, err := backend.ReserveEgressProxy(route)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer proxy.Close()
	if got := proxy.Addr(); got != "127.0.0.1:39002" {
		t.Fatalf("auto proxy endpoint = %q, want verified reserved endpoint", got)
	}
	if !reflect.DeepEqual(binder.bound, []uint16{39002}) {
		t.Fatalf("auto bound ports = %v, want manifest port only", binder.bound)
	}
}

func TestTask20ElevatedGuaranteesDescribeOfflineAndTargetPosture(t *testing.T) {
	const base = profile.GuaranteeProcessBoundary |
		profile.GuaranteeWriteBoundary |
		profile.GuaranteeReadBoundary |
		profile.GuaranteeResourceLimits |
		profile.GuaranteeEnvScrub

	tests := []struct {
		name string
		net  policy.NetPolicy
		want uint64
	}{
		{
			name: "offline deny all",
			want: base | profile.GuaranteeNetworkBoundary,
		},
		{
			name: "offline authenticated target proxy",
			net:  policy.NetPolicy{ProxyPort: 39002},
			want: base | profile.GuaranteeNetworkBoundary | profile.GuaranteeTargetNetwork,
		},
		{
			name: "online",
			net:  policy.NetPolicy{Open: true},
			want: base,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := elevatedGuaranteeBits(policy.Effective{
				Net: test.net,
				Env: policy.EnvPolicy{Inherit: false},
			})
			if got != test.want {
				t.Fatalf("guarantee bits = %#x, want %#x", got, test.want)
			}
			if got&profile.GuaranteeAddressNetwork != 0 {
				t.Fatal("Windows backend claimed route-dependent AddressNetwork")
			}
		})
	}
}

func TestTask20ProxyTargetCompilesOnlyWithVerifiedOfflinePosture(t *testing.T) {
	lease := &fakeElevatedLease{}
	snapshot := readyElevatedSnapshot()
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return snapshot, nil
		},
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
			return lease, nil
		},
	}}
	required := uint64(profile.GuaranteeNetworkBoundary | profile.GuaranteeTargetNetwork)
	p := policy.Effective{
		Net:                policy.NetPolicy{ProxyPort: 39002},
		RequiredGuarantees: required,
	}
	spec, _, _, bits, err := backend.Compile(p)
	if err != nil {
		t.Fatalf("verified offline proxy target did not compile: %v", err)
	}
	if bits&required != required {
		t.Fatalf("proxy-target bits = %#x, want %#x", bits, required)
	}
	if err := spec.Release(); err != nil {
		t.Fatal(err)
	}

	snapshot.FirewallReady = false
	acquires := 0
	backend.deps.acquire = func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
		acquires++
		return &fakeElevatedLease{}, nil
	}
	if _, _, _, _, err := backend.Compile(p); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("unverified offline posture error = %v, want ErrSetupStale", err)
	}
	if acquires != 0 {
		t.Fatal("unverified offline posture consumed broker or grant authority")
	}

	snapshot = readyElevatedSnapshot()
	p.Net.Open = true
	if _, _, _, bits, err := backend.Compile(p); err == nil ||
		bits&(profile.GuaranteeNetworkBoundary|profile.GuaranteeTargetNetwork) != 0 {
		t.Fatalf("online proxy-target result = bits %#x err %v, want no network claims and rejection", bits, err)
	}
}

func TestTask20ProxyAuthorizationsAreExecutionScopedAndReleasedIndependently(t *testing.T) {
	route, err := sandboxnetwork.NewDirectRoute()
	if err != nil {
		t.Fatal(err)
	}
	listener := &networkContractBinding{port: 39002}
	if err := listener.ActivateProxy(); err != nil {
		t.Fatal(err)
	}
	proxy, err := sandboxnetwork.NewProxyWithListener(route, listener)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	targetA, err := sandboxnetwork.ParseTarget("tcp:alpha.example:443")
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := sandboxnetwork.ParseTarget("tcp:beta.example:443")
	if err != nil {
		t.Fatal(err)
	}
	credentialA, err := proxy.Authorize("execution-a", []sandboxnetwork.Target{targetA})
	if err != nil {
		t.Fatal(err)
	}
	credentialB, err := proxy.Authorize("execution-b", []sandboxnetwork.Target{targetB})
	if err != nil {
		t.Fatal(err)
	}
	if credentialA == credentialB {
		t.Fatal("concurrent executions received the same proxy credential")
	}
	if proxy.URL("execution-a", credentialA) == proxy.URL("execution-b", credentialB) {
		t.Fatal("concurrent executions received the same authenticated proxy authority")
	}
	proxy.Release("execution-a")
	if _, err := proxy.Authorize("execution-a", []sandboxnetwork.Target{targetA}); err != nil {
		t.Fatalf("released execution identity remained active: %v", err)
	}
	if _, err := proxy.Authorize("execution-b", []sandboxnetwork.Target{targetB}); err == nil {
		t.Fatal("releasing one execution also released another execution")
	}
}

func TestTask20BroadAndHostWideGrantsRemainUnsupported(t *testing.T) {
	backend := &elevatedBackend{}
	for _, class := range []string{
		"network.broad.v1",
		"filesystem.host.read.v1",
		"filesystem.host.write.v1",
	} {
		if backend.SupportsGrantClass(class) {
			t.Errorf("authority-widening grant class %q passed side-effect-free preflight", class)
		}
	}
	if !backend.SupportsGrantClass("network.proxy-target.v1") {
		t.Fatal("narrow authenticated proxy-target grant was rejected")
	}
}

// networkContractBinding is a hermetic listener seam. It proves ownership,
// activation and release ordering without opening a workstation socket or
// relying on the live firewall.
type networkContractBinding struct {
	port        uint16
	activations int
	closed      bool
}

func (b *networkContractBinding) Port() uint16 { return b.port }
func (b *networkContractBinding) ActivateProxy() error {
	if b.closed || b.activations != 0 {
		return errors.New("invalid listener activation")
	}
	b.activations++
	return nil
}
func (b *networkContractBinding) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (b *networkContractBinding) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(b.port)}
}
func (b *networkContractBinding) Close() error {
	b.closed = true
	return nil
}

type networkContractBinder struct {
	bound    []uint16
	bindings map[uint16]*networkContractBinding
}

func (b *networkContractBinder) Bind(port uint16) (proxyPortBinding, error) {
	if b.bindings == nil {
		b.bindings = make(map[uint16]*networkContractBinding)
	}
	binding := &networkContractBinding{port: port}
	b.bound = append(b.bound, port)
	b.bindings[port] = binding
	return binding, nil
}
