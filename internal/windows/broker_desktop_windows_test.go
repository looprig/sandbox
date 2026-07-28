//go:build windows

package windows

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	win "golang.org/x/sys/windows"
)

type fakeBrokerPrivateDesktopCreator struct {
	mu            sync.Mutex
	specs         []privateDesktopSpec
	err           error
	closeErr      error
	closeCalls    atomic.Int32
	active        atomic.Int32
	maxActive     atomic.Int32
	createGate    <-chan struct{}
	createEntered chan<- struct{}
}

func (creator *fakeBrokerPrivateDesktopCreator) Create(spec privateDesktopSpec) (*privateDesktop, error) {
	active := creator.active.Add(1)
	defer creator.active.Add(-1)
	for {
		maximum := creator.maxActive.Load()
		if active <= maximum || creator.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	if creator.createEntered != nil {
		creator.createEntered <- struct{}{}
	}
	if creator.createGate != nil {
		<-creator.createGate
	}
	creator.mu.Lock()
	creator.specs = append(creator.specs, spec)
	creator.mu.Unlock()
	if creator.err != nil {
		return nil, creator.err
	}
	return &privateDesktop{
		Name:          spec.WindowStation + `\` + spec.Desktop,
		windowStation: 1,
		desktop:       2,
		api:           fakeBrokerDesktopCloser{creator: creator},
	}, nil
}

type fakeBrokerDesktopCloser struct {
	creator *fakeBrokerPrivateDesktopCreator
}

func (fakeBrokerDesktopCloser) CreateWindowStation(string, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	panic("unexpected CreateWindowStation")
}
func (fakeBrokerDesktopCloser) CreateDesktop(string, desktopHandle, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	panic("unexpected CreateDesktop")
}
func (fakeBrokerDesktopCloser) VerifyProtectedACL(desktopHandle, *win.SECURITY_DESCRIPTOR) error {
	panic("unexpected VerifyProtectedACL")
}
func (closer fakeBrokerDesktopCloser) CloseWindowStation(desktopHandle) error {
	closer.creator.closeCalls.Add(1)
	return closer.creator.closeErr
}
func (closer fakeBrokerDesktopCloser) CloseDesktop(desktopHandle) error {
	closer.creator.closeCalls.Add(1)
	return nil
}

func TestBrokerDesktopRequiresLocalSystemBeforeAuthorityUse(t *testing.T) {
	creator := &fakeBrokerPrivateDesktopCreator{}
	entropy := &countingReader{reader: bytes.NewReader(make([]byte, brokerDesktopEntropyBytes))}
	manager, err := newLocalSystemBrokerDesktopManager(
		func() error { return errors.New("not LocalSystem") },
		entropy,
		creator,
		testBrokerAccountSID,
		testBrokerOnlineAccountSID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(testBrokerDesktopContext(t, brokerAccountOffline)); err == nil {
		t.Fatal("desktop creation succeeded outside LocalSystem")
	}
	if entropy.reads != 0 || len(creator.specs) != 0 {
		t.Fatalf("authority used before LocalSystem rejection: reads=%d creates=%d", entropy.reads, len(creator.specs))
	}
}

func TestBrokerDesktopDescriptorHasOnlyRequiredTrustees(t *testing.T) {
	installation := testBrokerInstallationSID(t)
	descriptor, err := brokerDesktopSecurityDescriptor(testBrokerAccountSID, installation)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := win.SecurityDescriptorFromString(
		"O:SYD:P(A;;GA;;;SY)(A;;GA;;;" + testBrokerAccountSID + ")(A;;GA;;;" + installation.String() + ")",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyExactDesktopSecurity(descriptor, expected); err != nil {
		t.Fatalf("descriptor is not exact: %v", err)
	}
	for name, forbidden := range map[string]string{
		"Administrators":    "O:SYD:P(A;;GA;;;SY)(A;;GA;;;" + testBrokerAccountSID + ")(A;;GA;;;" + installation.String() + ")(A;;GA;;;BA)",
		"interactive owner": "O:SYD:P(A;;GA;;;SY)(A;;GA;;;" + testBrokerAccountSID + ")(A;;GA;;;" + installation.String() + ")(A;;GA;;;S-1-5-21-1-2-3-1002)",
	} {
		t.Run(name, func(t *testing.T) {
			widened, err := win.SecurityDescriptorFromString(forbidden)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyExactDesktopSecurity(descriptor, widened); err == nil {
				t.Fatal("descriptor matched a widened trustee set")
			}
		})
	}
}

func TestBrokerDesktopSelectsOnlyConfiguredAccountSID(t *testing.T) {
	creator := &fakeBrokerPrivateDesktopCreator{}
	manager, err := newLocalSystemBrokerDesktopManager(
		func() error { return nil },
		bytes.NewReader(make([]byte, 2*brokerDesktopEntropyBytes)),
		creator,
		testBrokerAccountSID,
		testBrokerOnlineAccountSID,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range []brokerAccountKind{brokerAccountOffline, brokerAccountOnline} {
		object, err := manager.Create(testBrokerDesktopContext(t, account))
		if err != nil {
			t.Fatal(err)
		}
		if err := object.Close(); err != nil {
			t.Fatal(err)
		}
	}
	creator.mu.Lock()
	specs := append([]privateDesktopSpec(nil), creator.specs...)
	creator.mu.Unlock()
	if len(specs) != 2 {
		t.Fatalf("created desktop count = %d, want 2", len(specs))
	}
	installation := testBrokerInstallationSID(t)
	for index, accountSID := range []string{testBrokerAccountSID, testBrokerOnlineAccountSID} {
		expected, err := brokerDesktopSecurityDescriptor(accountSID, installation)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyExactDesktopSecurity(specs[index].SecurityDescriptor, expected); err != nil {
			t.Fatalf("account %d descriptor: %v", index, err)
		}
	}
}

func TestBrokerDesktopUsesUnguessableNamesAndRetainsHandles(t *testing.T) {
	creator := &fakeBrokerPrivateDesktopCreator{closeErr: errors.New("close station")}
	entropy := bytes.Repeat([]byte{0xa5}, brokerDesktopEntropyBytes)
	manager, err := newLocalSystemBrokerDesktopManager(func() error { return nil }, bytes.NewReader(entropy), creator, testBrokerAccountSID, testBrokerOnlineAccountSID)
	if err != nil {
		t.Fatal(err)
	}
	object, err := manager.Create(testBrokerDesktopContext(t, brokerAccountOffline))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.Repeat("a5", brokerDesktopEntropyBytes)
	want := "looprig-broker-" + suffix + `\desktop-` + suffix
	if object.Name != want {
		t.Fatalf("desktop name = %q, want %q", object.Name, want)
	}
	if creator.closeCalls.Load() != 0 {
		t.Fatal("desktop handles closed before broker object release")
	}
	first := object.Close()
	second := object.Close()
	if first == nil || second == nil || first.Error() != second.Error() || creator.closeCalls.Load() != 2 {
		t.Fatalf("idempotent close = (%v, %v), native close calls = %d", first, second, creator.closeCalls.Load())
	}
}

func TestBrokerDesktopRejectsInvalidBrokerContextBeforeEntropyOrCreation(t *testing.T) {
	valid := testBrokerDesktopContext(t, brokerAccountOffline)
	for name, mutate := range map[string]func(*brokerDesktopContext){
		"lease":        func(context *brokerDesktopContext) { context.LeaseID = ACLLeaseID{} },
		"nonce":        func(context *brokerDesktopContext) { context.Binding.Nonce = [brokerNonceSize]byte{} },
		"pid":          func(context *brokerDesktopContext) { context.Binding.PID = 0 },
		"creation":     func(context *brokerDesktopContext) { context.Binding.CreationTime = 0 },
		"process":      func(context *brokerDesktopContext) { context.Binding.Process = nil },
		"installation": func(context *brokerDesktopContext) { context.Installation = SID{} },
		"restricting":  func(context *brokerDesktopContext) { context.Restricting = SID{} },
		"account":      func(context *brokerDesktopContext) { context.Account = brokerAccountUnspecified },
	} {
		t.Run(name, func(t *testing.T) {
			context := valid
			mutate(&context)
			creator := &fakeBrokerPrivateDesktopCreator{}
			entropy := &countingReader{reader: bytes.NewReader(make([]byte, brokerDesktopEntropyBytes))}
			manager, err := newLocalSystemBrokerDesktopManager(
				func() error { return nil }, entropy, creator,
				testBrokerAccountSID, testBrokerOnlineAccountSID,
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Create(context); err == nil {
				t.Fatal("invalid broker desktop context accepted")
			}
			if entropy.reads != 0 || len(creator.specs) != 0 {
				t.Fatalf("authority used for invalid context: reads=%d creates=%d", entropy.reads, len(creator.specs))
			}
		})
	}
}

func TestBrokerDesktopRejectsInvalidTrusteesAndEntropyFailureBeforeCreation(t *testing.T) {
	installation := testBrokerInstallationSID(t)
	for name, account := range map[string]string{
		"malformed":      "not-a-sid",
		"LocalSystem":    "S-1-5-18",
		"Administrators": "S-1-5-32-544",
	} {
		t.Run(name, func(t *testing.T) {
			creator := &fakeBrokerPrivateDesktopCreator{}
			if _, err := newLocalSystemBrokerDesktopManager(func() error { return nil }, bytes.NewReader(make([]byte, brokerDesktopEntropyBytes)), creator, account, testBrokerOnlineAccountSID); err == nil {
				t.Fatal("invalid account trustee accepted")
			}
			if len(creator.specs) != 0 {
				t.Fatal("native creation attempted for invalid trustee")
			}
		})
	}
	creator := &fakeBrokerPrivateDesktopCreator{}
	manager, _ := newLocalSystemBrokerDesktopManager(func() error { return nil }, io.LimitReader(bytes.NewReader([]byte{1}), 1), creator, testBrokerAccountSID, testBrokerOnlineAccountSID)
	context := testBrokerDesktopContext(t, brokerAccountOffline)
	context.Installation = installation
	if _, err := manager.Create(context); err == nil {
		t.Fatal("short entropy source accepted")
	}
	if len(creator.specs) != 0 {
		t.Fatal("native creation attempted after entropy failure")
	}
}

func TestBrokerDesktopCreationIsProcessGloballySerialized(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 2)
	creator := &fakeBrokerPrivateDesktopCreator{createGate: gate, createEntered: entered}
	manager, err := newLocalSystemBrokerDesktopManager(
		func() error { return nil },
		bytes.NewReader(make([]byte, 2*brokerDesktopEntropyBytes)),
		creator,
		testBrokerAccountSID,
		testBrokerOnlineAccountSID,
	)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	context := testBrokerDesktopContext(t, brokerAccountOffline)
	for range 2 {
		go func() {
			object, err := manager.Create(context)
			if object.close != nil {
				_ = object.Close()
			}
			results <- err
		}()
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first desktop creation did not enter")
	}
	select {
	case <-entered:
		t.Fatal("desktop creations overlapped")
	case <-time.After(50 * time.Millisecond):
	}
	gate <- struct{}{}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second desktop creation did not enter after release")
	}
	gate <- struct{}{}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if creator.maxActive.Load() != 1 {
		t.Fatalf("maximum concurrent desktop creations = %d", creator.maxActive.Load())
	}
}

func TestBrokerDesktopCreatorFailureIsReturnedWithoutObject(t *testing.T) {
	injected := errors.New("injected create failure")
	creator := &fakeBrokerPrivateDesktopCreator{err: injected}
	manager, _ := newLocalSystemBrokerDesktopManager(
		func() error { return nil },
		bytes.NewReader(make([]byte, brokerDesktopEntropyBytes)),
		creator,
		testBrokerAccountSID,
		testBrokerOnlineAccountSID,
	)
	object, err := manager.Create(testBrokerDesktopContext(t, brokerAccountOffline))
	if object.close != nil || !errors.Is(err, injected) {
		t.Fatalf("Create = (%v, %v), want nil/injected", object, err)
	}
}

type countingReader struct {
	reader io.Reader
	reads  int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.reads++
	return reader.reader.Read(buffer)
}

const (
	testBrokerAccountSID       = "S-1-5-21-1-2-3-1001"
	testBrokerOnlineAccountSID = "S-1-5-21-1-2-3-1002"
)

func testBrokerInstallationSID(t *testing.T) SID {
	t.Helper()
	sid, err := InstallationSID("broker-desktop-test")
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func testBrokerRestrictingSID(t *testing.T) SID {
	t.Helper()
	return deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "broker-desktop-test")
}

func testBrokerDesktopContext(t *testing.T, account brokerAccountKind) brokerDesktopContext {
	t.Helper()
	var lease ACLLeaseID
	lease[0] = 1
	var nonce [brokerNonceSize]byte
	nonce[0] = 1
	return brokerDesktopContext{
		LeaseID: lease,
		Binding: brokerLeaseBinding{
			Nonce: nonce, PID: 7, CreationTime: 9, Process: &brokerTestProcess{id: 7},
		},
		Installation: testBrokerInstallationSID(t),
		Restricting:  testBrokerRestrictingSID(t),
		Account:      account,
	}
}
