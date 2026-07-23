//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	win "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const maxBrokerLeaseJournalBytes = 64 << 20
const maxConcurrentBrokerConnections = 64

type brokerJournalFile interface {
	ReadAll() ([]byte, error)
	Append([]byte) error
	Sync() error
	Truncate(int64) error
	Close() error
}

type osBrokerJournalFile struct{ file *os.File }

func (file *osBrokerJournalFile) ReadAll() ([]byte, error) {
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file.file, maxBrokerLeaseJournalBytes+1))
}
func (file *osBrokerJournalFile) Append(data []byte) error {
	if _, err := file.file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	_, err := file.file.Write(data)
	return err
}
func (file *osBrokerJournalFile) Sync() error               { return file.file.Sync() }
func (file *osBrokerJournalFile) Truncate(size int64) error { return file.file.Truncate(size) }
func (file *osBrokerJournalFile) Close() error              { return file.file.Close() }

type protectedBrokerLeaseJournalStore struct {
	mu   sync.Mutex
	file brokerJournalFile
	data []byte
}

func newProtectedBrokerLeaseJournalStore(file brokerJournalFile) (*protectedBrokerLeaseJournalStore, error) {
	if file == nil {
		return nil, errors.New("windows sandbox: protected lease journal file is required")
	}
	data, err := file.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(data) > maxBrokerLeaseJournalBytes {
		return nil, errors.New("windows sandbox: lease journal exceeds size limit")
	}
	// A torn final append has no newline and was never a complete event. Drop
	// only that suffix and flush the truncation. Corrupt complete events remain
	// visible so semantic recovery fails closed.
	if len(data) != 0 && data[len(data)-1] != '\n' {
		last := bytes.LastIndexByte(data, '\n') + 1
		if err := file.Truncate(int64(last)); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
		data = data[:last]
	}
	return &protectedBrokerLeaseJournalStore{file: file, data: append([]byte(nil), data...)}, nil
}

func openProtectedBrokerLeaseJournalStore(path string) (*protectedBrokerLeaseJournalStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("windows sandbox: absolute lease journal path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*protectedBrokerLeaseJournalStore, error) {
		return nil, errors.Join(cause, file.Close())
	}
	if err := protectCredentialFile(path); err != nil {
		return fail(fmt.Errorf("protect broker lease journal: %w", err))
	}
	protection, err := inspectCredentialFileProtection(path)
	if err != nil || !protection.valid() {
		return fail(errors.Join(errors.New("windows sandbox: lease journal ACL is not protected"), err))
	}
	store, err := newProtectedBrokerLeaseJournalStore(&osBrokerJournalFile{file: file})
	if err != nil {
		return fail(err)
	}
	return store, nil
}

func (store *protectedBrokerLeaseJournalStore) Append(data []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.file == nil || len(data) == 0 || data[len(data)-1] != '\n' || len(store.data)+len(data) > maxBrokerLeaseJournalBytes {
		return errors.New("windows sandbox: invalid lease journal append")
	}
	if err := store.file.Append(data); err != nil {
		return err
	}
	store.data = append(store.data, data...)
	return nil
}
func (store *protectedBrokerLeaseJournalStore) Flush() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.file == nil {
		return errors.New("windows sandbox: closed lease journal")
	}
	return store.file.Sync()
}
func (store *protectedBrokerLeaseJournalStore) ReadAll() ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]byte(nil), store.data...), nil
}
func (store *protectedBrokerLeaseJournalStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.file == nil {
		return nil
	}
	err := store.file.Close()
	store.file = nil
	return err
}

type brokerPipeImpersonator interface {
	Impersonate(win.Handle) error
	Revert() error
}

type win32BrokerPipeImpersonator struct{}

var procImpersonateNamedPipeClient = win.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

func (win32BrokerPipeImpersonator) Impersonate(pipe win.Handle) error {
	ok, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	if ok == 0 {
		return syscallErr(callErr)
	}
	return nil
}
func (win32BrokerPipeImpersonator) Revert() error { return win.RevertToSelf() }

type authorizedBrokerPipeConnection struct {
	*authenticatedBrokerConnection
	impersonator brokerPipeImpersonator
}

func (connection *authorizedBrokerPipeConnection) AuthorizeObject(reference brokerObjectReference) (brokerAuthorizedObject, error) {
	if connection == nil || connection.authenticatedBrokerConnection == nil || connection.impersonator == nil || validateBrokerObject(reference) != nil {
		return brokerAuthorizedObject{}, errBrokerClientUnauthorized
	}
	if err := connection.ValidateIdentity(); err != nil {
		return brokerAuthorizedObject{}, err
	}
	process, ok := connection.process.(*windowsBrokerClientProcess)
	if !ok {
		return brokerAuthorizedObject{}, errBrokerClientUnauthorized
	}
	authorityHandle, err := process.DuplicateClientHandle(win.Handle(reference.Handle))
	if err != nil {
		return brokerAuthorizedObject{}, fmt.Errorf("duplicate broker client object handle: %w", err)
	}
	closeAuthority := true
	defer func() {
		if closeAuthority {
			_ = win.CloseHandle(authorityHandle)
		}
	}()
	if err := connection.impersonator.Impersonate(connection.pipe); err != nil {
		return brokerAuthorizedObject{}, fmt.Errorf("impersonate broker client: %w", err)
	}
	object, openErr := openBoundWin32ACLObject(authorityHandle, reference.Path, reference.Kind == brokerObjectDirectory, false)
	revertErr := connection.impersonator.Revert()
	if openErr != nil || revertErr != nil {
		if object != nil {
			_ = object.close()
		}
		return brokerAuthorizedObject{}, errors.Join(openErr, revertErr)
	}
	snapshot, err := object.snapshot()
	closeErr := object.close()
	if err != nil || closeErr != nil {
		return brokerAuthorizedObject{}, errors.Join(err, closeErr)
	}
	closeAuthority = false
	var once sync.Once
	return brokerAuthorizedObject{Reference: reference, Identity: snapshot.identity, AuthorityHandle: uint64(authorityHandle), Release: func() error {
		var closeErr error
		once.Do(func() { closeErr = win.CloseHandle(authorityHandle) })
		return closeErr
	}}, nil
}

type brokerFrameStream interface {
	io.Reader
	io.Writer
	Close() error
}

type pipeBrokerFrameTransport struct {
	mu     sync.Mutex
	stream brokerFrameStream
}

func (transport *pipeBrokerFrameTransport) RoundTrip(request brokerFrame) (brokerFrame, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.stream == nil {
		return brokerFrame{}, errors.New("windows sandbox: broker pipe is closed")
	}
	encoded, err := encodeBrokerFrame(request)
	if err != nil {
		return brokerFrame{}, err
	}
	if err := writeBrokerFrame(transport.stream, encoded); err != nil {
		return brokerFrame{}, err
	}
	return decodeBrokerFrame(transport.stream)
}
func (transport *pipeBrokerFrameTransport) Close() error {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.stream == nil {
		return nil
	}
	err := transport.stream.Close()
	transport.stream = nil
	return err
}

type brokerServiceConnection struct {
	stream     brokerFrameStream
	connection brokerServiceClient
}

type brokerServiceClient interface {
	brokerConnection
	Close() error
}

type brokerServiceAcceptor interface {
	Accept(context.Context) (brokerServiceConnection, error)
	Close() error
}

type win32BrokerServiceAcceptor struct {
	mu            sync.Mutex
	pipeName      string
	ownerSID      string
	authenticator *brokerPipeAuthenticator
	impersonator  brokerPipeImpersonator
	pipes         brokerPipeInstanceOps
	anchorServer  win.Handle
	anchorClient  win.Handle
	current       win.Handle
	closed        bool
}

type brokerPipeInstanceOps interface {
	CreateAnchor(string) (server, client win.Handle, err error)
	CreateTraffic(string, string) (win.Handle, error)
	Connect(win.Handle) error
	Close(win.Handle) error
}

type win32BrokerPipeInstanceOps struct{}

func (win32BrokerPipeInstanceOps) CreateAnchor(name string) (win.Handle, win.Handle, error) {
	server, err := createSystemOnlyBrokerAnchor(name)
	if err != nil {
		return 0, 0, err
	}
	name16, err := win.UTF16PtrFromString(name)
	if err != nil {
		_ = win.CloseHandle(server)
		return 0, 0, err
	}
	// The anchor DACL permits only LocalSystem, so an installation user cannot
	// win the create-to-self-connect interval. Retaining both connected ends
	// makes the anchor unavailable for traffic while preserving first-instance
	// namespace ownership until shutdown.
	client, err := win.CreateFile(name16, win.GENERIC_READ|win.GENERIC_WRITE, 0, nil, win.OPEN_EXISTING, 0, 0)
	if err != nil {
		_ = win.CloseHandle(server)
		return 0, 0, err
	}
	if err := win.ConnectNamedPipe(server, nil); err != nil && !errors.Is(err, win.ERROR_PIPE_CONNECTED) {
		_ = win.CloseHandle(client)
		_ = win.CloseHandle(server)
		return 0, 0, err
	}
	return server, client, nil
}
func (win32BrokerPipeInstanceOps) CreateTraffic(name, ownerSID string) (win.Handle, error) {
	return createBrokerPipeInstance(name, ownerSID, false)
}
func (win32BrokerPipeInstanceOps) Connect(pipe win.Handle) error {
	err := win.ConnectNamedPipe(pipe, nil)
	if errors.Is(err, win.ERROR_PIPE_CONNECTED) {
		return nil
	}
	return err
}
func (win32BrokerPipeInstanceOps) Close(handle win.Handle) error { return win.CloseHandle(handle) }

func createSystemOnlyBrokerAnchor(name string) (win.Handle, error) {
	if !strings.HasPrefix(strings.ToLower(name), `\\.\pipe\`) || len(name) <= len(`\\.\pipe\`) {
		return win.InvalidHandle, errors.New("windows sandbox: invalid broker anchor pipe name")
	}
	descriptor, err := win.SecurityDescriptorFromString("D:P(A;;GA;;;SY)")
	if err != nil {
		return win.InvalidHandle, err
	}
	name16, err := win.UTF16PtrFromString(name)
	if err != nil {
		return win.InvalidHandle, err
	}
	attributes := win.SecurityAttributes{Length: uint32(unsafe.Sizeof(win.SecurityAttributes{})), SecurityDescriptor: descriptor}
	return win.CreateNamedPipe(name16, win.PIPE_ACCESS_DUPLEX|win.FILE_FLAG_FIRST_PIPE_INSTANCE,
		win.PIPE_TYPE_MESSAGE|win.PIPE_READMODE_MESSAGE|win.PIPE_WAIT|win.PIPE_REJECT_REMOTE_CLIENTS,
		win.PIPE_UNLIMITED_INSTANCES, maxBrokerFrameSize, maxBrokerFrameSize, 0, &attributes)
}

func (acceptor *win32BrokerServiceAcceptor) pipeOps() brokerPipeInstanceOps {
	if acceptor.pipes != nil {
		return acceptor.pipes
	}
	return win32BrokerPipeInstanceOps{}
}

func (acceptor *win32BrokerServiceAcceptor) createTrafficPipe() (win.Handle, error) {
	acceptor.mu.Lock()
	defer acceptor.mu.Unlock()
	if acceptor.closed {
		return 0, context.Canceled
	}
	ops := acceptor.pipeOps()
	if acceptor.anchorServer == 0 || acceptor.anchorClient == 0 {
		server, client, err := ops.CreateAnchor(acceptor.pipeName)
		if err != nil {
			return 0, fmt.Errorf("create protected broker pipe anchor: %w", err)
		}
		if server == 0 || client == 0 || server == win.InvalidHandle || client == win.InvalidHandle {
			if client != 0 && client != win.InvalidHandle {
				_ = ops.Close(client)
			}
			if server != 0 && server != win.InvalidHandle {
				_ = ops.Close(server)
			}
			return 0, errors.New("windows sandbox: invalid broker pipe anchor handles")
		}
		acceptor.anchorServer, acceptor.anchorClient = server, client
	}
	pipe, err := ops.CreateTraffic(acceptor.pipeName, acceptor.ownerSID)
	if err != nil {
		// The connected anchor intentionally survives a traffic creation error;
		// no external server can claim the name before orderly shutdown.
		return 0, err
	}
	acceptor.current = pipe
	return pipe, nil
}

func (acceptor *win32BrokerServiceAcceptor) Accept(ctx context.Context) (brokerServiceConnection, error) {
	if acceptor == nil {
		return brokerServiceConnection{}, errors.New("windows sandbox: nil broker acceptor")
	}
	if err := ctx.Err(); err != nil {
		return brokerServiceConnection{}, err
	}
	pipe, err := acceptor.createTrafficPipe()
	if err != nil {
		return brokerServiceConnection{}, err
	}
	clearCurrent := func() {
		acceptor.mu.Lock()
		if acceptor.current == pipe {
			acceptor.current = 0
		}
		acceptor.mu.Unlock()
	}
	fail := func(cause error) (brokerServiceConnection, error) {
		clearCurrent()
		_ = acceptor.pipeOps().Close(pipe)
		return brokerServiceConnection{}, cause
	}
	if err := acceptor.pipeOps().Connect(pipe); err != nil {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		return fail(err)
	}
	clearCurrent()
	authenticated, err := acceptor.authenticator.Authenticate(pipe)
	if err != nil {
		return fail(err)
	}
	stream := os.NewFile(uintptr(pipe), acceptor.pipeName)
	if stream == nil {
		_ = authenticated.Close()
		return fail(errors.New("windows sandbox: wrap broker pipe handle"))
	}
	impersonator := acceptor.impersonator
	if impersonator == nil {
		impersonator = win32BrokerPipeImpersonator{}
	}
	return brokerServiceConnection{stream: stream, connection: &authorizedBrokerPipeConnection{authenticatedBrokerConnection: authenticated, impersonator: impersonator}}, nil
}

// Close unblocks a synchronous ConnectNamedPipe by closing its server handle.
// It is idempotent and transfers no ownership of already accepted streams.
func (acceptor *win32BrokerServiceAcceptor) Close() error {
	if acceptor == nil {
		return nil
	}
	acceptor.mu.Lock()
	if acceptor.closed {
		acceptor.mu.Unlock()
		return nil
	}
	acceptor.closed = true
	pipe := acceptor.current
	anchorClient, anchorServer := acceptor.anchorClient, acceptor.anchorServer
	acceptor.current = 0
	acceptor.anchorClient, acceptor.anchorServer = 0, 0
	acceptor.mu.Unlock()
	ops := acceptor.pipeOps()
	var result error
	if pipe != 0 && pipe != win.InvalidHandle {
		result = errors.Join(result, ops.Close(pipe))
	}
	if anchorClient != 0 && anchorClient != win.InvalidHandle {
		result = errors.Join(result, ops.Close(anchorClient))
	}
	if anchorServer != 0 && anchorServer != win.InvalidHandle {
		result = errors.Join(result, ops.Close(anchorServer))
	}
	return result
}

type windowsBrokerServiceLoop struct {
	broker   *windowsBroker
	acceptor brokerServiceAcceptor
}

func (service windowsBrokerServiceLoop) Serve(ctx context.Context) error {
	if service.broker == nil || service.acceptor == nil {
		return errors.New("windows sandbox: incomplete broker service loop")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	var cancellationWatcher sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrentBrokerConnections)
	var activeMu sync.Mutex
	active := make(map[brokerFrameStream]struct{})
	cancellationWatcher.Add(1)
	go func() {
		defer cancellationWatcher.Done()
		<-ctx.Done()
		_ = service.acceptor.Close()
	}()
	shutdown := func() {
		cancel()
		_ = service.acceptor.Close()
		activeMu.Lock()
		streams := make([]brokerFrameStream, 0, len(active))
		for stream := range active {
			streams = append(streams, stream)
		}
		activeMu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		workers.Wait()
		cancellationWatcher.Wait()
	}
	defer shutdown()
	for {
		accepted, err := service.acceptor.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			_ = accepted.stream.Close()
			_ = accepted.connection.Close()
			return nil
		}
		activeMu.Lock()
		active[accepted.stream] = struct{}{}
		activeMu.Unlock()
		workers.Add(1)
		go func(connection brokerServiceConnection) {
			defer workers.Done()
			defer func() {
				activeMu.Lock()
				delete(active, connection.stream)
				activeMu.Unlock()
				<-semaphore
				_ = recover()
			}()
			// A malformed, panicking, or abruptly disconnected client cannot
			// terminate the service. serveConnection owns exact cleanup.
			_ = service.serveConnection(connection)
		}(accepted)
	}
}

func (service windowsBrokerServiceLoop) serveConnection(accepted brokerServiceConnection) error {
	if accepted.stream == nil || accepted.connection == nil {
		return errors.New("windows sandbox: invalid accepted broker connection")
	}
	binding := accepted.connection.LeaseBinding()
	defer accepted.stream.Close()
	defer accepted.connection.Close()
	defer service.broker.Disconnect(binding)
	for {
		request, err := decodeBrokerFrame(accepted.stream)
		if err != nil {
			return err
		}
		response := service.broker.Handle(accepted.connection, request)
		encoded, err := encodeBrokerFrame(response)
		if err != nil {
			return err
		}
		if err := writeBrokerFrame(accepted.stream, encoded); err != nil {
			return err
		}
	}
}

func writeBrokerFrame(writer io.Writer, encoded []byte) error {
	for len(encoded) != 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(encoded) {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

type win32BrokerACLMechanism struct{}

func (win32BrokerACLMechanism) Plan(authorized brokerAuthorizedObject, trustees []SID) ([]brokerACLMutation, error) {
	if len(trustees) != 2 || authorized.AuthorityHandle == 0 || !authorized.Identity.valid() {
		return nil, errors.New("windows sandbox: invalid broker ACL plan request")
	}
	authorityHandle := win.Handle(authorized.AuthorityHandle)
	object, err := openBoundWin32ACLObject(authorityHandle, authorized.Reference.Path, authorized.Reference.Kind == brokerObjectDirectory, false)
	if err != nil {
		return nil, err
	}
	defer object.close()
	snapshot, err := object.snapshot()
	if err != nil || snapshot.identity != authorized.Identity {
		return nil, errors.Join(errBrokerClientChanged, err)
	}
	mutations := make([]brokerACLMutation, 0, len(trustees)*3)
	for _, trustee := range trustees {
		for _, access := range []ACLAccess{ACLRead, ACLExecute, ACLWrite} {
			ace := encodeACE(trustee, authorized.Identity.Kind, ACLACE{Type: ACEAllow, Access: access, Inheritable: authorized.Identity.Kind == ACLObjectDirectory})
			mutations = append(mutations, brokerACLMutation{Object: authorized.Identity, SID: trustee, ACE: ace, BaselineOccurrences: uint32(countIdenticalACE(snapshot.aces, ace)), Path: authorized.Reference.Path})
		}
	}
	return mutations, nil
}

func (win32BrokerACLMechanism) Apply(mutation brokerACLMutation) error {
	if !brokerAllowACEForSID(mutation.ACE, mutation.SID, mutation.Object.Kind) {
		return errors.New("windows sandbox: invalid broker ACL mutation")
	}
	object, err := openWin32ACLObject(mutation.Path, mutation.Object.Kind == ACLObjectDirectory, false)
	if err != nil {
		return err
	}
	defer object.close()
	snapshot, err := object.snapshot()
	if err != nil || snapshot.identity != mutation.Object || uint32(countIdenticalACE(snapshot.aces, mutation.ACE)) != mutation.BaselineOccurrences {
		return errors.Join(errors.New("windows sandbox: broker ACL baseline changed"), err)
	}
	if err := object.setDACL(insertCanonicalACE(snapshot.aces, mutation.ACE)); err != nil {
		return err
	}
	readback, err := object.snapshot()
	if err != nil || readback.identity != mutation.Object || uint32(countIdenticalACE(readback.aces, mutation.ACE)) != mutation.BaselineOccurrences+1 {
		return errors.Join(errors.New("windows sandbox: broker ACL read-back mismatch"), err)
	}
	return nil
}

func (win32BrokerACLMechanism) Rollback(mutation brokerACLMutation) error {
	if !canonicalBrokerPath(mutation.Path) || !brokerAllowACEForSID(mutation.ACE, mutation.SID, mutation.Object.Kind) {
		return errors.New("windows sandbox: invalid broker ACL rollback")
	}
	// After restart no client handle survives. The path selects only a cleanup
	// candidate; the complete journaled identity must match before removal.
	object, err := openWin32ACLObject(mutation.Path, mutation.Object.Kind == ACLObjectDirectory, false)
	if err != nil {
		return err
	}
	defer object.close()
	snapshot, err := object.snapshot()
	if err != nil || snapshot.identity != mutation.Object {
		return errors.Join(ErrRestrictedTargetChanged, err)
	}
	updated, err := removeLeaseACEOccurrence(snapshot.aces, mutation.ACE, int(mutation.BaselineOccurrences))
	if err != nil {
		return err
	}
	if err := object.setDACL(updated); err != nil {
		return err
	}
	readback, err := object.snapshot()
	if err != nil || readback.identity != mutation.Object || uint32(countIdenticalACE(readback.aces, mutation.ACE)) > mutation.BaselineOccurrences {
		return errors.Join(errors.New("windows sandbox: broker ACL rollback read-back mismatch"), err)
	}
	return nil
}

type brokerCredentialSource interface {
	LoadCredential(brokerAccountKind) (account string, password []byte, err error)
}

type brokerLogonNative interface {
	LogonService(account string, password []byte) (win.Token, error)
	DuplicateToProcess(win.Token, win.Handle) (win.Handle, error)
	CloseToken(win.Token) error
}

type brokerTokenRestrictor interface {
	Restrict(win.Token, []SID) (win.Token, error)
}

type win32BrokerTokenRestrictor struct{}

func (win32BrokerTokenRestrictor) Restrict(source win.Token, trustees []SID) (win.Token, error) {
	return createBrokerRestrictedToken(source, trustees)
}

type win32BrokerLogonNative struct{}

var procLogonUserW = win.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")

func (win32BrokerLogonNative) LogonService(account string, password []byte) (win.Token, error) {
	account16, err := win.UTF16FromString(account)
	if err != nil {
		return 0, err
	}
	domain16, err := win.UTF16FromString(".")
	if err != nil {
		return 0, err
	}
	password16 := passwordUTF16(password)
	defer zeroUTF16(password16)
	var token win.Token
	ok, _, callErr := procLogonUserW.Call(uintptr(unsafe.Pointer(&account16[0])), uintptr(unsafe.Pointer(&domain16[0])), uintptr(unsafe.Pointer(&password16[0])), 5, 0, uintptr(unsafe.Pointer(&token))) // LOGON32_LOGON_SERVICE
	if ok == 0 {
		return 0, syscallErr(callErr)
	}
	return token, nil
}
func (win32BrokerLogonNative) DuplicateToProcess(token win.Token, process win.Handle) (win.Handle, error) {
	var duplicate win.Handle
	if err := win.DuplicateHandle(win.CurrentProcess(), win.Handle(token), process, &duplicate, 0, false, win.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, err
	}
	return duplicate, nil
}
func (win32BrokerLogonNative) CloseToken(token win.Token) error { return token.Close() }

type win32BrokerTokenIssuer struct {
	credentials brokerCredentialSource
	native      brokerLogonNative
	restrictor  brokerTokenRestrictor
}

func (issuer win32BrokerTokenIssuer) IssueRestricted(account brokerAccountKind, installation, restricting SID) (brokerRestrictedToken, error) {
	if issuer.credentials == nil || issuer.native == nil || (account != brokerAccountOffline && account != brokerAccountOnline) || installation.kind != sidKindInstallation || !restricting.isRestrictedTierTrustee() {
		return nil, errors.New("windows sandbox: invalid restricted account token request")
	}
	name, password, err := issuer.credentials.LoadCredential(account)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(password)
	if name == "" || len(password) == 0 {
		return nil, errors.New("windows sandbox: service credential is unavailable")
	}
	unrestricted, err := issuer.native.LogonService(name, password)
	if err != nil || unrestricted == 0 {
		if err == nil {
			err = errors.New("windows sandbox: account logon returned an invalid token")
		}
		return nil, err
	}
	restrictor := issuer.restrictor
	if restrictor == nil {
		restrictor = win32BrokerTokenRestrictor{}
	}
	restrictedToken, restrictErr := restrictor.Restrict(unrestricted, []SID{installation, restricting})
	closeErr := issuer.native.CloseToken(unrestricted)
	if restrictErr != nil || closeErr != nil {
		if restrictedToken != 0 {
			_ = issuer.native.CloseToken(restrictedToken)
		}
		return nil, errors.Join(restrictErr, closeErr)
	}
	return &win32BrokerRestrictedToken{token: restrictedToken, native: issuer.native}, nil
}

type win32BrokerRestrictedToken struct {
	token  win.Token
	native brokerLogonNative
}

type nativeBrokerClientProcess interface{ NativeProcessHandle() win.Handle }

func (token *win32BrokerRestrictedToken) DuplicateTo(binding brokerLeaseBinding) (uint64, error) {
	process, ok := binding.Process.(nativeBrokerClientProcess)
	if token == nil || token.token == 0 || !ok || process.NativeProcessHandle() == 0 {
		return 0, errBrokerClientChanged
	}
	handle, err := token.native.DuplicateToProcess(token.token, process.NativeProcessHandle())
	return uint64(handle), err
}
func (token *win32BrokerRestrictedToken) Close() error {
	if token == nil || token.token == 0 {
		return nil
	}
	err := token.native.CloseToken(token.token)
	token.token = 0
	return err
}

func (process *windowsBrokerClientProcess) NativeProcessHandle() win.Handle { return process.handle }

func (process *windowsBrokerClientProcess) DuplicateClientHandle(source win.Handle) (win.Handle, error) {
	if process == nil || process.handle == 0 || source == 0 || source == win.InvalidHandle {
		return 0, errBrokerClientChanged
	}
	var duplicate win.Handle
	if err := win.DuplicateHandle(process.handle, source, win.CurrentProcess(), &duplicate, 0, false, win.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, err
	}
	return duplicate, nil
}

func createBrokerRestrictedToken(source win.Token, trustees []SID) (win.Token, error) {
	if len(trustees) != 2 || trustees[0].kind != sidKindInstallation || !trustees[0].isModuleTrustee() || !trustees[1].isRestrictedTierTrustee() {
		return 0, errors.New("windows sandbox: invalid broker restricting SID set")
	}
	parsed := make([]*win.SID, len(trustees))
	for index, trustee := range trustees {
		sid, err := win.StringToSid(trustee.String())
		if err != nil || !sid.IsValid() {
			return 0, errors.New("windows sandbox: invalid broker restricting SID")
		}
		parsed[index] = sid
	}
	if win.EqualSid(parsed[0], parsed[1]) {
		return 0, errors.New("windows sandbox: duplicate broker restricting SID")
	}
	tokenType, err := tokenUint32Information(source, win.TokenType)
	if err != nil || tokenType != win.TokenPrimary {
		return 0, errors.Join(errors.New("windows sandbox: account logon token is not primary"), err)
	}
	integrity, err := tokenIntegritySID(source)
	if err != nil {
		return 0, err
	}
	groups, err := source.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	privileges, err := tokenPrivilegeList(source)
	if err != nil {
		return 0, err
	}
	user, err := source.GetTokenUser()
	if err != nil {
		return 0, err
	}
	if err := ensureRestrictingSIDsAreNew(user.User.Sid, groups.AllGroups(), parsed); err != nil {
		return 0, err
	}
	dangerous, err := dangerousGroupSIDs()
	if err != nil {
		return 0, err
	}
	disabled := make([]win.SIDAndAttributes, 0, len(dangerous))
	for _, sid := range dangerous {
		if groupIsEnabledForAllow(groups.AllGroups(), sid) {
			disabled = append(disabled, win.SIDAndAttributes{Sid: sid})
		}
	}
	restricting := make([]win.SIDAndAttributes, len(parsed))
	for index, sid := range parsed {
		restricting[index] = win.SIDAndAttributes{Sid: sid}
	}
	token, err := issueRestrictedToken(win32RestrictedTokenCreator{}, source, disabled, restricting)
	if err != nil {
		return 0, err
	}
	if err := validateRestrictedToken(token, integrity, disabled, privileges, parsed); err != nil {
		_ = token.Close()
		return 0, err
	}
	return token, nil
}

// RunInstalledBrokerService loads only protected, installation-derived state;
// no secret or authority-bearing value is accepted from argv or the environment.
func RunInstalledBrokerService(ctx context.Context) error {
	config, err := loadInstalledBrokerRuntimeConfig()
	if err != nil {
		return err
	}
	return runBrokerService(ctx, config)
}

func runBrokerService(ctx context.Context, config brokerRuntimeConfig) error {
	if config.Protocol != brokerProtocolVersion || config.InstallationID == "" || config.OwnerSID == "" || config.PipeName == "" || !filepath.IsAbs(config.JournalPath) {
		return errors.New("windows sandbox: invalid installed broker runtime configuration")
	}
	if err := requireLocalSystemBroker(); err != nil {
		return err
	}
	installation, err := InstallationSID(config.InstallationID)
	if err != nil {
		return err
	}
	store, err := openProtectedBrokerLeaseJournalStore(config.JournalPath)
	if err != nil {
		return err
	}
	defer store.Close()
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		return err
	}
	retirement, err := OpenRestrictedJournal(config.StateRoot)
	if err != nil {
		return err
	}
	sids, err := NewOneShotSIDGenerator(rand.Reader, retirement)
	if err != nil {
		return err
	}
	credentials := protectedBrokerCredentialSource{
		config:      config,
		store:       atomicCredentialStore{root: filepath.Join(config.StateRoot, "credentials"), files: realCredentialFileOps{}},
		unprotector: systemDPAPI{},
	}
	tokens := win32BrokerTokenIssuer{credentials: credentials, native: win32BrokerLogonNative{}, restrictor: win32BrokerTokenRestrictor{}}
	broker, err := newWindowsBroker(installation, sids, journal, win32BrokerACLMechanism{}, tokens, rand.Reader)
	if err != nil {
		return err
	}
	authenticator, err := newBrokerPipeAuthenticator(config.OwnerSID, installation.String())
	if err != nil {
		return err
	}
	acceptor := &win32BrokerServiceAcceptor{pipeName: config.PipeName, ownerSID: config.OwnerSID, authenticator: authenticator, impersonator: win32BrokerPipeImpersonator{}}
	return (windowsBrokerServiceLoop{broker: broker, acceptor: acceptor}).Serve(ctx)
}

func requireLocalSystemBroker() error {
	user, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if user.User.Sid == nil || !user.User.Sid.IsWellKnown(win.WinLocalSystemSid) {
		return errors.New("windows sandbox: broker service must run as LocalSystem")
	}
	return nil
}

type installedBrokerServiceHandler struct{}

func (installedBrokerServiceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status <- svc.Status{State: svc.StartPending}
	result := make(chan error, 1)
	go func() { result <- RunInstalledBrokerService(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-result:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-result; err != nil && !errors.Is(err, context.Canceled) {
					return false, 1
				}
				return false, 0
			}
		}
	}
}

// RunInstalledBrokerServiceDispatcher binds the protected runtime to the SCM
// service name derived from the installation identity.
func RunInstalledBrokerServiceDispatcher() error {
	config, err := loadInstalledBrokerRuntimeConfig()
	if err != nil {
		return err
	}
	names, err := deriveInstallationPrincipalNames(config.InstallationID)
	if err != nil {
		return err
	}
	return svc.Run(names.Service, installedBrokerServiceHandler{})
}

// syscallErr converts a zero-return lazy-proc call into a stable error even on
// runtimes that report ERROR_SUCCESS as the third result.
func syscallErr(err error) error {
	if err == nil || errors.Is(err, syscall.Errno(0)) {
		return errors.New("windows sandbox: Windows syscall failed")
	}
	return err
}
