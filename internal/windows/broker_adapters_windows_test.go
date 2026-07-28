//go:build windows

package windows

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	win "golang.org/x/sys/windows"
)

type recordingPipeImpersonator struct {
	impersonateThread uint32
	revertThread      uint32
	revertErr         error
}

func (impersonator *recordingPipeImpersonator) Impersonate(win.Handle) error {
	impersonator.impersonateThread = win.GetCurrentThreadId()
	return nil
}

func (impersonator *recordingPipeImpersonator) Revert() error {
	impersonator.revertThread = win.GetCurrentThreadId()
	return impersonator.revertErr
}

func TestBrokerPipeImpersonationPinsAuthorizationAndRevertToOneThread(t *testing.T) {
	impersonator := &recordingPipeImpersonator{}
	var operationThread uint32
	if err := runUnderBrokerClientImpersonation(impersonator, 1, func() error {
		operationThread = win.GetCurrentThreadId()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if impersonator.impersonateThread == 0 || impersonator.impersonateThread != operationThread ||
		operationThread != impersonator.revertThread {
		t.Fatalf("thread-affine authorization migrated: impersonate=%d operation=%d revert=%d",
			impersonator.impersonateThread, operationThread, impersonator.revertThread)
	}

	poisoned := &recordingPipeImpersonator{revertErr: errors.New("injected revert failure")}
	if err := runUnderBrokerClientImpersonation(poisoned, 1, func() error { return nil }); err == nil || poisoned.impersonateThread != poisoned.revertThread {
		t.Fatalf("revert failure was not returned on its locked thread: %v", err)
	}
}

type fakeBrokerJournalFile struct {
	data       []byte
	operations []string
	closed     bool
}

func (file *fakeBrokerJournalFile) ReadAll() ([]byte, error) {
	return append([]byte(nil), file.data...), nil
}
func (file *fakeBrokerJournalFile) Append(data []byte) error {
	file.operations = append(file.operations, "append")
	file.data = append(file.data, data...)
	return nil
}
func (file *fakeBrokerJournalFile) Sync() error {
	file.operations = append(file.operations, "sync")
	return nil
}
func (file *fakeBrokerJournalFile) Truncate(size int64) error {
	file.operations = append(file.operations, "truncate")
	file.data = file.data[:size]
	return nil
}
func (file *fakeBrokerJournalFile) Close() error { file.closed = true; return nil }

func TestProtectedBrokerLeaseJournalDropsOnlyTornTail(t *testing.T) {
	file := &fakeBrokerJournalFile{data: []byte("complete\ntorn")}
	store, err := newProtectedBrokerLeaseJournalStore(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadAll()
	if err != nil || string(data) != "complete\n" {
		t.Fatalf("recovered = %q, %v", data, err)
	}
	if got := file.operations; len(got) != 2 || got[0] != "truncate" || got[1] != "sync" {
		t.Fatalf("recovery operations = %v", got)
	}
	if err := store.Append([]byte("next\n")); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	if string(file.data) != "complete\nnext\n" {
		t.Fatalf("data = %q", file.data)
	}
}

func TestProtectedBrokerLeaseJournalRetainsCompleteCorruptionForFailClosedDecode(t *testing.T) {
	file := &fakeBrokerJournalFile{data: []byte("not-json\n")}
	store, err := newProtectedBrokerLeaseJournalStore(file)
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := newBrokerLeaseJournal(store)
	if _, err := journal.recover(); err == nil {
		t.Fatal("complete corrupt record was hidden")
	}
}

type brokerLoopStream struct{ net.Conn }

type panicBrokerStream struct {
	closed chan struct{}
	once   sync.Once
}

func (*panicBrokerStream) Read([]byte) (int, error)  { panic("malformed stream") }
func (*panicBrokerStream) Write([]byte) (int, error) { return 0, errors.New("unexpected write") }
func (stream *panicBrokerStream) Close() error {
	stream.once.Do(func() { close(stream.closed) })
	return nil
}

type fakeBrokerServiceAcceptor struct {
	connections chan brokerServiceConnection
	closed      chan struct{}
	once        sync.Once
}

type fakeBrokerPipeInstanceOps struct {
	anchorCalls  int
	trafficCalls int
	trafficErr   error
	closed       []win.Handle
}

func (ops *fakeBrokerPipeInstanceOps) CreateAnchor(string) (win.Handle, win.Handle, error) {
	ops.anchorCalls++
	return win.Handle(101), win.Handle(102), nil
}
func (ops *fakeBrokerPipeInstanceOps) CreateTraffic(string, string) (win.Handle, error) {
	ops.trafficCalls++
	if ops.trafficErr != nil {
		return 0, ops.trafficErr
	}
	return win.Handle(200 + ops.trafficCalls), nil
}
func (*fakeBrokerPipeInstanceOps) Connect(win.Handle) error { return nil }
func (ops *fakeBrokerPipeInstanceOps) Close(handle win.Handle) error {
	ops.closed = append(ops.closed, handle)
	return nil
}

func TestBrokerPipeAnchorLivesAcrossTrafficInstancesUntilShutdown(t *testing.T) {
	ops := &fakeBrokerPipeInstanceOps{}
	acceptor := &win32BrokerServiceAcceptor{pipeName: `\\.\pipe\anchor-test`, ownerSID: testOwnerSID, pipes: ops}
	first, err := acceptor.createTrafficPipe()
	if err != nil || first == 0 {
		t.Fatalf("first traffic = %v, %v", first, err)
	}
	// Simulate ownership transfer of the connected traffic handle. The anchor
	// remains held while another traffic instance is created.
	acceptor.mu.Lock()
	acceptor.current = 0
	acceptor.mu.Unlock()
	second, err := acceptor.createTrafficPipe()
	if err != nil || second == 0 || second == first {
		t.Fatalf("second traffic = %v, %v", second, err)
	}
	if ops.anchorCalls != 1 || ops.trafficCalls != 2 || acceptor.anchorServer != 101 || acceptor.anchorClient != 102 {
		t.Fatalf("anchor state calls=%d/%d handles=%v/%v", ops.anchorCalls, ops.trafficCalls, acceptor.anchorServer, acceptor.anchorClient)
	}
	if err := acceptor.Close(); err != nil {
		t.Fatal(err)
	}
	wantClosed := []win.Handle{second, 102, 101}
	if !slices.Equal(ops.closed, wantClosed) {
		t.Fatalf("shutdown close order = %v, want %v", ops.closed, wantClosed)
	}
}

func TestBrokerPipeAnchorSurvivesTrafficCreationFailure(t *testing.T) {
	ops := &fakeBrokerPipeInstanceOps{trafficErr: errors.New("traffic unavailable")}
	acceptor := &win32BrokerServiceAcceptor{pipeName: `\\.\pipe\anchor-test`, ownerSID: testOwnerSID, pipes: ops}
	if _, err := acceptor.createTrafficPipe(); err == nil {
		t.Fatal("traffic creation failure accepted")
	}
	if acceptor.anchorServer != 101 || acceptor.anchorClient != 102 || len(ops.closed) != 0 {
		t.Fatalf("anchor was rolled back with traffic: server=%v client=%v closed=%v", acceptor.anchorServer, acceptor.anchorClient, ops.closed)
	}
	if err := acceptor.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ops.closed, []win.Handle{102, 101}) {
		t.Fatalf("anchor failure close order = %v", ops.closed)
	}
}

func newFakeBrokerServiceAcceptor() *fakeBrokerServiceAcceptor {
	return &fakeBrokerServiceAcceptor{connections: make(chan brokerServiceConnection, 4), closed: make(chan struct{})}
}
func (acceptor *fakeBrokerServiceAcceptor) Accept(ctx context.Context) (brokerServiceConnection, error) {
	select {
	case connection := <-acceptor.connections:
		return connection, nil
	case <-acceptor.closed:
		return brokerServiceConnection{}, context.Canceled
	case <-ctx.Done():
		return brokerServiceConnection{}, ctx.Err()
	}
}
func (acceptor *fakeBrokerServiceAcceptor) Close() error {
	acceptor.once.Do(func() { close(acceptor.closed) })
	return nil
}

func TestBrokerServiceLoopRoundTripsAndCleansDisconnect(t *testing.T) {
	broker, connection, _, _, _, _ := newBrokerTestRig(t)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- (windowsBrokerServiceLoop{broker: broker}).serveConnection(brokerServiceConnection{stream: brokerLoopStream{server}, connection: connection})
	}()
	if nonce, err := readBrokerGreeting(client); err != nil || nonce != connection.binding.Nonce {
		t.Fatalf("greeting = %x, %v", nonce, err)
	}
	request := brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: connection.binding.Nonce}
	encoded, err := encodeBrokerFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(encoded); err != nil {
		t.Fatal(err)
	}
	response, err := decodeBrokerFrame(client)
	if err != nil || response.Result != brokerResultOK || response.Kind != brokerMessageStatus {
		t.Fatalf("response = %#v, %v", response, err)
	}
	_ = client.Close()
	if err := <-done; !errors.Is(err, errBrokerFrameMalformed) {
		t.Fatalf("serve result = %v", err)
	}
}

func TestBrokerServiceLoopServesClientsConcurrentlyAndWaitsForShutdown(t *testing.T) {
	broker, firstConnection, _, _, _, _ := newBrokerTestRig(t)
	secondConnection := *firstConnection
	secondConnection.binding.Nonce[0]++
	secondConnection.binding.PID++
	secondConnection.binding.Process = &brokerTestProcess{id: 2}
	acceptor := newFakeBrokerServiceAcceptor()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (windowsBrokerServiceLoop{broker: broker, acceptor: acceptor}).Serve(ctx) }()

	serverOne, clientOne := net.Pipe()
	serverTwo, clientTwo := net.Pipe()
	acceptor.connections <- brokerServiceConnection{stream: brokerLoopStream{serverOne}, connection: firstConnection}
	acceptor.connections <- brokerServiceConnection{stream: brokerLoopStream{serverTwo}, connection: &secondConnection}
	requestStatus := func(client net.Conn, connection *brokerTestConnection) brokerFrame {
		t.Helper()
		if nonce, err := readBrokerGreeting(client); err != nil || nonce != connection.binding.Nonce {
			t.Fatalf("greeting = %x, %v", nonce, err)
		}
		encoded, err := encodeBrokerFrame(brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: connection.binding.Nonce})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeBrokerFrame(client, encoded); err != nil {
			t.Fatal(err)
		}
		response, err := decodeBrokerFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := requestStatus(clientOne, firstConnection); response.Result != brokerResultOK {
		t.Fatalf("first response = %#v", response)
	}
	// The first connection remains open. A synchronous service loop would hang
	// here and the test deadline would fire.
	if response := requestStatus(clientTwo, &secondConnection); response.Result != brokerResultOK {
		t.Fatalf("second response = %#v", response)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service shutdown did not wait for and finish connection workers")
	}
	_ = clientOne.Close()
	_ = clientTwo.Close()
}

func TestBrokerServiceLoopCancellationUnblocksEmptyAccept(t *testing.T) {
	broker, _, _, _, _, _ := newBrokerTestRig(t)
	acceptor := newFakeBrokerServiceAcceptor()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (windowsBrokerServiceLoop{broker: broker, acceptor: acceptor}).Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocking accept was not canceled")
	}
}

func TestBrokerServiceLoopContainsPanickingConnectionAndClosesIt(t *testing.T) {
	broker, connection, _, _, _, _ := newBrokerTestRig(t)
	acceptor := newFakeBrokerServiceAcceptor()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (windowsBrokerServiceLoop{broker: broker, acceptor: acceptor}).Serve(ctx) }()
	panicking := &panicBrokerStream{closed: make(chan struct{})}
	acceptor.connections <- brokerServiceConnection{stream: panicking, connection: connection}
	select {
	case <-panicking.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("panicking connection did not run deferred close")
	}

	server, client := net.Pipe()
	second := *connection
	second.binding.Nonce[0]++
	second.binding.PID++
	second.binding.Process = &brokerTestProcess{id: 3}
	acceptor.connections <- brokerServiceConnection{stream: brokerLoopStream{server}, connection: &second}
	if nonce, err := readBrokerGreeting(client); err != nil || nonce != second.binding.Nonce {
		t.Fatalf("greeting = %x, %v", nonce, err)
	}
	encoded, _ := encodeBrokerFrame(brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: second.binding.Nonce})
	if err := writeBrokerFrame(client, encoded); err != nil {
		t.Fatal(err)
	}
	if response, err := decodeBrokerFrame(client); err != nil || response.Result != brokerResultOK {
		t.Fatalf("post-panic response = %#v, %v", response, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not stop after contained panic")
	}
	_ = client.Close()
}

type fakeFrameStream struct {
	read  *bytes.Reader
	wrote bytes.Buffer
}

func (stream *fakeFrameStream) Read(data []byte) (int, error)  { return stream.read.Read(data) }
func (stream *fakeFrameStream) Write(data []byte) (int, error) { return stream.wrote.Write(data) }
func (*fakeFrameStream) Close() error                          { return nil }

func TestPipeBrokerTransportRejectsMismatchedResponseThroughClient(t *testing.T) {
	var nonce [brokerNonceSize]byte
	nonce[0] = 1
	wrong := nonce
	wrong[0]++
	response, _ := encodeBrokerFrame(brokerFrame{Kind: brokerMessageStatus, Direction: brokerResponse, Nonce: wrong, Generation: 1})
	stream := &fakeFrameStream{read: bytes.NewReader(response)}
	client, _ := newBrokerClient(&pipeBrokerFrameTransport{stream: stream}, nonce)
	if _, err := client.Status(); err == nil {
		t.Fatal("mismatched pipe response accepted")
	}
}

type fakeBrokerCredentialSource struct {
	account  string
	password []byte
	loads    int
}

func (source *fakeBrokerCredentialSource) LoadCredential(brokerAccountKind) (string, []byte, error) {
	source.loads++
	return source.account, source.password, nil
}

type fakeBrokerLogonNative struct {
	account    string
	password   []byte
	logonErr   error
	logonToken win.Token
	closed     []win.Token
}

func (native *fakeBrokerLogonNative) LogonService(account string, password []byte) (win.Token, error) {
	native.account = account
	native.password = append([]byte(nil), password...)
	return native.logonToken, native.logonErr
}
func (*fakeBrokerLogonNative) DuplicateToProcess(win.Token, win.Handle) (win.Handle, error) {
	return 88, nil
}
func (native *fakeBrokerLogonNative) CloseToken(token win.Token) error {
	native.closed = append(native.closed, token)
	return nil
}

type fakeBrokerTokenRestrictor struct{ trustees []SID }

func (restrictor *fakeBrokerTokenRestrictor) Restrict(_ win.Token, trustees []SID) (win.Token, error) {
	restrictor.trustees = append([]SID(nil), trustees...)
	return win.Token(17), nil
}

type fakeNativeBrokerProcess struct{ brokerTestProcess }

func (*fakeNativeBrokerProcess) NativeProcessHandle() win.Handle { return win.Handle(44) }

func TestBrokerTokenIssuerZerosServiceCredentialOnLogonFailure(t *testing.T) {
	password := []byte("service-secret")
	credentials := &fakeBrokerCredentialSource{account: `HOST\sandbox`, password: password}
	native := &fakeBrokerLogonNative{logonErr: errors.New("logon denied")}
	installation, _ := InstallationSID("install")
	restricting := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "nonce")
	issuer := win32BrokerTokenIssuer{credentials: credentials, native: native}
	if _, err := issuer.IssueRestricted(brokerAccountOffline, installation, restricting); err == nil {
		t.Fatal("logon failure accepted")
	}
	if credentials.loads != 1 || native.account != credentials.account || string(native.password) != "service-secret" {
		t.Fatalf("credential seam was not used exactly once: %#v %#v", credentials, native)
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatalf("service credential was not zeroed: %q", password)
	}
}

func TestBrokerTokenIssuerRestrictsBeforeDuplicateAndClosesBothLocalTokens(t *testing.T) {
	password := []byte("service-secret")
	credentials := &fakeBrokerCredentialSource{account: `HOST\sandbox`, password: password}
	native := &fakeBrokerLogonNative{logonToken: win.Token(9)}
	restrictor := &fakeBrokerTokenRestrictor{}
	installation, _ := InstallationSID("install")
	restricting := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "nonce")
	issuer := win32BrokerTokenIssuer{credentials: credentials, native: native, restrictor: restrictor}
	issued, err := issuer.IssueRestricted(brokerAccountOnline, installation, restricting)
	if err != nil {
		t.Fatal(err)
	}
	binding := brokerLeaseBinding{Nonce: [brokerNonceSize]byte{1}, PID: 2, CreationTime: 3, Process: &fakeNativeBrokerProcess{}}
	handle, err := issued.DuplicateTo(binding)
	if err != nil || handle != 88 {
		t.Fatalf("duplicate = %d, %v", handle, err)
	}
	if err := issued.Close(); err != nil {
		t.Fatal(err)
	}
	if len(restrictor.trustees) != 3 || !restrictor.trustees[0].isRestrictedCode() ||
		restrictor.trustees[1] != installation || restrictor.trustees[2] != restricting {
		t.Fatalf("restricting trustees = %#v", restrictor.trustees)
	}
	if len(native.closed) != 2 || native.closed[1] != win.Token(17) {
		t.Fatalf("closed local tokens = %#v", native.closed)
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("credential was not zeroed")
	}
}
