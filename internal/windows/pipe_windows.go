//go:build windows

package windows

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

var (
	errBrokerClientUnauthorized = errors.New("windows sandbox: unauthorized broker pipe client")
	errBrokerClientChanged      = errors.New("windows sandbox: broker pipe client identity changed")
)

const tokenIsAppContainer = 29

// brokerClientFacts contains only identity obtained from Windows. No request
// field participates in client authentication.
type brokerClientFacts struct {
	PID            uint32
	CreationTime   uint64
	UserSID        string
	AppContainer   bool
	RestrictedSIDs []string
	// Restricted is IsTokenRestricted's answer: true for any token carrying
	// restricting SIDs, write-restricted or fully restricted.
	Restricted bool
	// IntegrityRID is the final subauthority of the token's mandatory label
	// (SECURITY_MANDATORY_*_RID).
	IntegrityRID uint32
}

// brokerMinimumClientIntegrityRID is SECURITY_MANDATORY_MEDIUM_RID. The
// broker serves the configured owner's ordinary (or elevated) processes; a
// Low or Untrusted process of that user is by construction one that was
// meant to be sandboxed, never a legitimate sandbox host.
const brokerMinimumClientIntegrityRID = 0x2000

type brokerClientProcess interface {
	Facts() (brokerClientFacts, error)
	CreationTime() (uint64, error)
	Close() error
}

type brokerPipeSystem interface {
	ClientPID(xwindows.Handle) (uint32, error)
	OpenClient(uint32) (brokerClientProcess, error)
}

type windowsBrokerPipeSystem struct{}

func (windowsBrokerPipeSystem) ClientPID(pipe xwindows.Handle) (uint32, error) {
	var pid uint32
	if err := xwindows.GetNamedPipeClientProcessId(pipe, &pid); err != nil {
		return 0, err
	}
	if pid == 0 {
		return 0, errBrokerClientUnauthorized
	}
	return pid, nil
}

func (windowsBrokerPipeSystem) OpenClient(pid uint32) (brokerClientProcess, error) {
	handle, err := xwindows.OpenProcess(xwindows.PROCESS_QUERY_LIMITED_INFORMATION|xwindows.PROCESS_DUP_HANDLE|xwindows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil, err
	}
	return &windowsBrokerClientProcess{pid: pid, handle: handle}, nil
}

type windowsBrokerClientProcess struct {
	pid    uint32
	handle xwindows.Handle
}

func (process *windowsBrokerClientProcess) Facts() (brokerClientFacts, error) {
	created, err := process.CreationTime()
	if err != nil {
		return brokerClientFacts{}, err
	}
	var token xwindows.Token
	if err := xwindows.OpenProcessToken(process.handle, xwindows.TOKEN_QUERY, &token); err != nil {
		return brokerClientFacts{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return brokerClientFacts{}, err
	}
	appContainer, err := tokenUint32Information(token, tokenIsAppContainer)
	if err != nil {
		return brokerClientFacts{}, fmt.Errorf("inspect AppContainer state: %w", err)
	}
	restricted, err := readTokenGroups(token, xwindows.TokenRestrictedSids)
	if err != nil {
		return brokerClientFacts{}, fmt.Errorf("inspect restricting SIDs: %w", err)
	}
	restrictedSIDs := make([]string, 0, len(restricted.groups))
	for _, group := range restricted.groups {
		restrictedSIDs = append(restrictedSIDs, group.Sid.String())
	}
	isRestricted, err := token.IsRestricted()
	if err != nil {
		return brokerClientFacts{}, fmt.Errorf("inspect restricted-token state: %w", err)
	}
	integrity, err := tokenIntegritySID(token)
	if err != nil {
		return brokerClientFacts{}, fmt.Errorf("inspect integrity level: %w", err)
	}
	subauthorities := integrity.SubAuthorityCount()
	if subauthorities == 0 {
		return brokerClientFacts{}, errors.New("windows sandbox: malformed client integrity label")
	}
	return brokerClientFacts{
		PID: process.pid, CreationTime: created, UserSID: user.User.Sid.String(),
		AppContainer: appContainer != 0, RestrictedSIDs: restrictedSIDs,
		Restricted: isRestricted, IntegrityRID: integrity.SubAuthority(uint32(subauthorities - 1)),
	}, nil
}

func (process *windowsBrokerClientProcess) CreationTime() (uint64, error) {
	var creation, exit, kernel, user xwindows.Filetime
	if err := xwindows.GetProcessTimes(process.handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(uint32(creation.HighDateTime))<<32 | uint64(creation.LowDateTime), nil
}

func (process *windowsBrokerClientProcess) Close() error { return xwindows.CloseHandle(process.handle) }

// Exited answers brokerClientLiveness from the retained process handle, which
// OpenClient opened with SYNCHRONIZE: a process object is signalled exactly
// when the process has terminated, and because the handle pins the object a
// recycled PID can never make a dead client look alive.
func (process *windowsBrokerClientProcess) Exited() (bool, error) {
	if process == nil || process.handle == 0 {
		return false, errBrokerClientChanged
	}
	event, err := xwindows.WaitForSingleObject(process.handle, 0)
	switch {
	case err != nil:
		return false, err
	case event == xwindows.WAIT_OBJECT_0:
		return true, nil
	case event == uint32(xwindows.WAIT_TIMEOUT):
		return false, nil
	default:
		return false, fmt.Errorf("windows sandbox: unexpected client process wait result %#x", event)
	}
}

type brokerPipeAuthenticator struct {
	system                     brokerPipeSystem
	nonceSource                io.Reader
	ownerSID                   string
	installationRestrictingSID string
}

func newBrokerPipeAuthenticator(ownerSID, installationRestrictingSID string) (*brokerPipeAuthenticator, error) {
	if _, err := xwindows.StringToSid(ownerSID); err != nil {
		return nil, fmt.Errorf("invalid broker owner SID: %w", err)
	}
	if _, err := xwindows.StringToSid(installationRestrictingSID); err != nil {
		return nil, fmt.Errorf("invalid installation restricting SID: %w", err)
	}
	return &brokerPipeAuthenticator{system: windowsBrokerPipeSystem{}, nonceSource: rand.Reader, ownerSID: ownerSID, installationRestrictingSID: installationRestrictingSID}, nil
}

type brokerLeaseBinding struct {
	Nonce        [brokerNonceSize]byte
	PID          uint32
	CreationTime uint64
	Process      brokerClientProcess
}

type authenticatedBrokerConnection struct {
	pipe      xwindows.Handle
	system    brokerPipeSystem
	process   brokerClientProcess
	binding   brokerLeaseBinding
	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
	closeErr  error
	cleanups  []func()
}

func (authenticator *brokerPipeAuthenticator) Authenticate(pipe xwindows.Handle) (*authenticatedBrokerConnection, error) {
	if authenticator == nil || authenticator.system == nil || authenticator.nonceSource == nil {
		return nil, errBrokerClientUnauthorized
	}
	pid, err := authenticator.system.ClientPID(pipe)
	if err != nil {
		return nil, fmt.Errorf("obtain real pipe client PID: %w", err)
	}
	process, err := authenticator.system.OpenClient(pid)
	if err != nil {
		return nil, fmt.Errorf("open pipe client process: %w", err)
	}
	fail := func(err error) (*authenticatedBrokerConnection, error) { _ = process.Close(); return nil, err }
	facts, err := process.Facts()
	if err != nil {
		return fail(fmt.Errorf("inspect pipe client token: %w", err))
	}
	pidAfterOpen, err := authenticator.system.ClientPID(pipe)
	if err != nil || pidAfterOpen != pid || facts.PID != pid || facts.CreationTime == 0 {
		return fail(errBrokerClientChanged)
	}
	if err := authorizeBrokerClientFacts(facts, authenticator.ownerSID, authenticator.installationRestrictingSID); err != nil {
		return fail(err)
	}
	var nonce [brokerNonceSize]byte
	if _, err := io.ReadFull(authenticator.nonceSource, nonce[:]); err != nil {
		return fail(fmt.Errorf("create broker connection nonce: %w", err))
	}
	if nonce == ([brokerNonceSize]byte{}) {
		return fail(errors.New("windows sandbox: zero broker connection nonce"))
	}
	binding := brokerLeaseBinding{Nonce: nonce, PID: pid, CreationTime: facts.CreationTime, Process: process}
	return &authenticatedBrokerConnection{pipe: pipe, system: authenticator.system, process: process, binding: binding}, nil
}

// authorizeBrokerClientFacts is the token half of pipe authentication. The
// DACL already limits the pipe to SYSTEM, Administrators and the owner SID;
// within the owner, only an ordinary, unrestricted process at Medium
// integrity or above may ask for broker authority (design §7.3, review L8):
//
//   - an AppContainer client is refused;
//   - ANY restricted token is refused, not only one carrying this
//     installation's SID: a restricted-tier sandbox runs as the owner with a
//     write-restricted token and its own executor/one-shot SIDs, and before
//     this check it could open the pipe and ask for leases and elevated
//     tokens. The installation-SID test is kept as defense in depth;
//   - a Low or Untrusted integrity token is refused.
func authorizeBrokerClientFacts(facts brokerClientFacts, ownerSID, installationRestrictingSID string) error {
	if !equalSIDText(facts.UserSID, ownerSID) || facts.AppContainer {
		return errBrokerClientUnauthorized
	}
	for _, sid := range facts.RestrictedSIDs {
		if equalSIDText(sid, installationRestrictingSID) {
			return errBrokerClientUnauthorized
		}
	}
	if facts.Restricted || len(facts.RestrictedSIDs) != 0 {
		return errBrokerClientUnauthorized
	}
	if facts.IntegrityRID < brokerMinimumClientIntegrityRID {
		return errBrokerClientUnauthorized
	}
	return nil
}

func (connection *authenticatedBrokerConnection) LeaseBinding() brokerLeaseBinding {
	return connection.binding
}

func (connection *authenticatedBrokerConnection) ValidateIdentity() error {
	if connection == nil || connection.process == nil {
		return errBrokerClientChanged
	}
	pid, err := connection.system.ClientPID(connection.pipe)
	if err != nil || pid != connection.binding.PID {
		return errBrokerClientChanged
	}
	creation, err := connection.process.CreationTime()
	if err != nil || creation != connection.binding.CreationTime {
		return errBrokerClientChanged
	}
	return nil
}

// OnDisconnect registers lease cleanup owned by this connection. Close is the
// single disconnect path and executes callbacks before releasing the process
// handle, preserving the identity binding throughout cleanup.
func (connection *authenticatedBrokerConnection) OnDisconnect(cleanup func()) {
	if cleanup == nil {
		return
	}
	connection.mu.Lock()
	if !connection.closed {
		connection.cleanups = append(connection.cleanups, cleanup)
		connection.mu.Unlock()
		return
	}
	connection.mu.Unlock()
	cleanup()
}

func (connection *authenticatedBrokerConnection) Close() error {
	if connection == nil {
		return nil
	}
	connection.closeOnce.Do(func() {
		connection.mu.Lock()
		connection.closed = true
		cleanups := append([]func(){}, connection.cleanups...)
		connection.cleanups = nil
		connection.mu.Unlock()
		for index := len(cleanups) - 1; index >= 0; index-- {
			cleanups[index]()
		}
		connection.closeErr = connection.process.Close()
	})
	return connection.closeErr
}

func equalSIDText(left, right string) bool { return strings.EqualFold(left, right) }

func brokerPipeSDDL(ownerSID string) (string, error) {
	sid, err := xwindows.StringToSid(ownerSID)
	if err != nil {
		return "", fmt.Errorf("invalid broker owner SID: %w", err)
	}
	// Protected DACL: LocalSystem and Administrators have full access; the
	// configured owner receives only read/write pipe access.
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + sid.String() + ")", nil
}

func createAuthenticatedBrokerPipe(name, ownerSID string) (xwindows.Handle, error) {
	return createBrokerPipeInstance(name, ownerSID, true)
}

func createBrokerPipeInstance(name, ownerSID string, first bool) (xwindows.Handle, error) {
	if !strings.HasPrefix(strings.ToLower(name), `\\.\pipe\`) || len(name) <= len(`\\.\pipe\`) || strings.IndexByte(name, 0) >= 0 {
		return xwindows.InvalidHandle, errors.New("windows sandbox: invalid local broker pipe name")
	}
	sddl, err := brokerPipeSDDL(ownerSID)
	if err != nil {
		return xwindows.InvalidHandle, err
	}
	descriptor, err := xwindows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return xwindows.InvalidHandle, fmt.Errorf("build broker pipe security descriptor: %w", err)
	}
	name16, err := xwindows.UTF16PtrFromString(name)
	if err != nil {
		return xwindows.InvalidHandle, err
	}
	attributes := xwindows.SecurityAttributes{Length: uint32(unsafe.Sizeof(xwindows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	openMode := uint32(xwindows.PIPE_ACCESS_DUPLEX)
	if first {
		openMode |= xwindows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	pipe, err := xwindows.CreateNamedPipe(name16,
		openMode,
		xwindows.PIPE_TYPE_MESSAGE|xwindows.PIPE_READMODE_MESSAGE|xwindows.PIPE_WAIT|xwindows.PIPE_REJECT_REMOTE_CLIENTS,
		xwindows.PIPE_UNLIMITED_INSTANCES, maxBrokerFrameSize, maxBrokerFrameSize, 0, &attributes)
	if err != nil {
		return xwindows.InvalidHandle, fmt.Errorf("create authenticated broker pipe: %w", err)
	}
	return pipe, nil
}
