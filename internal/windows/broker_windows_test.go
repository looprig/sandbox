//go:build windows

package windows

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type brokerTestProcess struct {
	id     int
	exited atomic.Bool
}

func (*brokerTestProcess) Facts() (brokerClientFacts, error) { return brokerClientFacts{}, nil }
func (*brokerTestProcess) CreationTime() (uint64, error)     { return 9, nil }
func (*brokerTestProcess) Close() error                      { return nil }

// Exited makes the fake answer brokerClientLiveness, so reconcile's
// dead-binding rule is exercised exactly as against a real process handle.
func (process *brokerTestProcess) Exited() (bool, error) { return process.exited.Load(), nil }

type brokerTestConnection struct {
	binding    brokerLeaseBinding
	dead       bool
	authorized map[uint64]brokerAuthorizedObject
}

func (connection *brokerTestConnection) LeaseBinding() brokerLeaseBinding { return connection.binding }
func (connection *brokerTestConnection) ValidateIdentity() error {
	if connection.dead {
		return errBrokerClientChanged
	}
	return nil
}
func (connection *brokerTestConnection) AuthorizeObject(reference brokerObjectReference) (brokerAuthorizedObject, error) {
	if connection.dead {
		return brokerAuthorizedObject{}, errBrokerClientChanged
	}
	object, ok := connection.authorized[reference.Handle]
	if !ok || object.Reference != reference {
		return brokerAuthorizedObject{}, errBrokerClientUnauthorized
	}
	return object, nil
}
func (*brokerTestConnection) Close() error { return nil }

type brokerTestJournalStore struct {
	data       bytes.Buffer
	operations []string
	flushed    bool
	flushErr   error
}

func (store *brokerTestJournalStore) Append(data []byte) error {
	store.flushed = false
	store.operations = append(store.operations, "append")
	_, err := store.data.Write(data)
	return err
}
func (store *brokerTestJournalStore) Flush() error {
	store.operations = append(store.operations, "flush")
	store.flushed = store.flushErr == nil
	return store.flushErr
}
func (store *brokerTestJournalStore) ReadAll() ([]byte, error) {
	return append([]byte(nil), store.data.Bytes()...), nil
}

type brokerTestACL struct {
	store       *brokerTestJournalStore
	restricting SID
	aces        map[ACLObjectIdentity][][]byte
	operations  []string
	forgeSID    SID
	forgeObject *ACLObjectIdentity
	forgeACE    []byte
	corruptMask bool
	rollbackErr error
	// applyHook, when set, runs at the start of every Apply; the L8 test uses
	// it to hold one acquire mid-projection.
	applyHook func()
	// trustees records every SID set the broker asked a plan for.
	trustees [][]SID
}

func (acl *brokerTestACL) Plan(object brokerAuthorizedObject, trustees []SID) ([]brokerACLMutation, error) {
	acl.trustees = append(acl.trustees, append([]SID(nil), trustees...))
	if len(trustees) != 1 {
		return nil, fmt.Errorf("broker asked to project %d trustees, want only the lease SID", len(trustees))
	}
	acl.restricting = trustees[0]
	mutations := make([]brokerACLMutation, 0, 1)
	for _, sid := range trustees {
		identity := object.Identity
		if acl.forgeObject != nil {
			identity = *acl.forgeObject
		}
		mutationSID := sid
		if acl.forgeSID.String() != "" {
			mutationSID = acl.forgeSID
		}
		ace := encodeACE(sid, identity.Kind, ACLACE{Type: ACEAllow, Access: ACLRead})
		if acl.forgeACE != nil {
			ace = append([]byte(nil), acl.forgeACE...)
		}
		if acl.corruptMask {
			ace[4] ^= 0x40
		}
		mutations = append(mutations, brokerACLMutation{Object: identity, SID: mutationSID, ACE: ace, BaselineOccurrences: uint32(countIdenticalACE(acl.aces[identity], ace)), Path: object.Reference.Path, Handle: object.Reference.Handle})
	}
	return mutations, nil
}
func (acl *brokerTestACL) Apply(mutation brokerACLMutation) error {
	if acl.applyHook != nil {
		acl.applyHook()
	}
	if acl.store != nil && !acl.store.flushed {
		return errors.New("mutation applied before durable flush")
	}
	acl.operations = append(acl.operations, "apply:"+mutation.SID.String())
	acl.aces[mutation.Object] = insertCanonicalACE(acl.aces[mutation.Object], append([]byte(nil), mutation.ACE...))
	return nil
}
func (acl *brokerTestACL) Rollback(mutation brokerACLMutation) error {
	acl.operations = append(acl.operations, "rollback:"+mutation.SID.String())
	if acl.rollbackErr != nil {
		return acl.rollbackErr
	}
	updated, err := removeLeaseACEOccurrence(acl.aces[mutation.Object], mutation.ACE, int(mutation.BaselineOccurrences))
	if err != nil {
		return err
	}
	acl.aces[mutation.Object] = updated
	return nil
}

type brokerTestTokenIssuer struct {
	issued  int
	account brokerAccountKind
	token   *brokerTestToken
}

func (issuer *brokerTestTokenIssuer) IssueRestricted(account brokerAccountKind, installation, restricting SID) (brokerRestrictedToken, error) {
	if account != brokerAccountOffline && account != brokerAccountOnline || installation.kind != sidKindInstallation || !restricting.isRestrictedTierTrustee() {
		return nil, errors.New("unsafe token request")
	}
	issuer.issued++
	issuer.account = account
	issuer.token = &brokerTestToken{handle: 77}
	return issuer.token, nil
}

type brokerTestToken struct {
	handle uint64
	closed bool
}

func (token *brokerTestToken) DuplicateTo(binding brokerLeaseBinding) (uint64, error) {
	if binding.Process == nil {
		return 0, errors.New("missing process authority")
	}
	return token.handle, nil
}
func (token *brokerTestToken) Close() error { token.closed = true; return nil }

type brokerTestDesktopManager struct {
	created []brokerDesktopContext
	closed  int
	fail    error
	name    string
}

func (manager *brokerTestDesktopManager) Create(context brokerDesktopContext) (brokerManagedDesktop, error) {
	if manager.fail != nil {
		return brokerManagedDesktop{}, manager.fail
	}
	manager.created = append(manager.created, context)
	name := manager.name
	if name == "" {
		name = `Sandbox-4242\Default`
	}
	closed := false
	return brokerManagedDesktop{Name: name, close: func() error {
		if !closed {
			closed = true
			manager.closed++
		}
		return nil
	}}, nil
}

// brokerTestEntropy yields a different, never-zero buffer on every read.
type brokerTestEntropy struct {
	mu    sync.Mutex
	seed  byte
	reads byte
}

func (entropy *brokerTestEntropy) Read(buffer []byte) (int, error) {
	entropy.mu.Lock()
	defer entropy.mu.Unlock()
	entropy.reads++
	for index := range buffer {
		buffer[index] = entropy.seed ^ byte(index)
	}
	buffer[0] = entropy.reads
	return len(buffer), nil
}

type brokerTestRetirement struct{ seen map[string]bool }

func (retirement *brokerTestRetirement) RetireSID(sid SID) (bool, error) {
	if retirement.seen[sid.String()] {
		return false, nil
	}
	retirement.seen[sid.String()] = true
	return true, nil
}

func newBrokerTestRig(t *testing.T) (*windowsBroker, *brokerTestConnection, *brokerTestACL, *brokerTestJournalStore, *brokerTestTokenIssuer, brokerObjectReference) {
	t.Helper()
	installation, err := InstallationSID("installation-A")
	if err != nil {
		t.Fatal(err)
	}
	store := &brokerTestJournalStore{}
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	// Distinct entropy per read: a fixed buffer yields one SID and one lease
	// identity only, so a second acquire on the rig failed with EOF (or
	// ErrSIDReuse) before it reached anything under test.
	sids, err := NewOneShotSIDGenerator(&brokerTestEntropy{seed: 0x31}, &brokerTestRetirement{seen: make(map[string]bool)})
	if err != nil {
		t.Fatal(err)
	}
	acl := &brokerTestACL{store: store, aces: make(map[ACLObjectIdentity][][]byte)}
	tokens := &brokerTestTokenIssuer{}
	broker, err := newWindowsBroker(installation, sids, journal, acl, tokens, &brokerTestDesktopManager{}, &brokerTestEntropy{seed: 0x42})
	if err != nil {
		t.Fatal(err)
	}
	var nonce [brokerNonceSize]byte
	copy(nonce[:], bytes.Repeat([]byte{0x21}, brokerNonceSize))
	process := &brokerTestProcess{id: 1}
	binding := brokerLeaseBinding{Nonce: nonce, PID: 41, CreationTime: 99, Process: process}
	var fileID [16]byte
	fileID[0] = 7
	reference := brokerObjectReference{Handle: 55, Path: `C:\data\input.txt`, VolumeSerial: 3, FileID: fileID, Kind: brokerObjectFile, Access: brokerAccessReadWrite, Scope: brokerScopeExact}
	identity := ACLObjectIdentity{VolumeSerial: 3, FileID: fileID, Kind: ACLObjectFile, LinkCount: 1}
	connection := &brokerTestConnection{binding: binding, authorized: map[uint64]brokerAuthorizedObject{55: {Reference: reference, Identity: identity}}}
	return broker, connection, acl, store, tokens, reference
}

func TestBrokerAcquireIssueReleasePreservesUnrelatedACLChanges(t *testing.T) {
	broker, connection, acl, store, tokens, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if acquire.Result != brokerResultOK || acquire.LeaseID == ([brokerLeaseIDSize]byte{}) {
		t.Fatalf("acquire = %#v", acquire)
	}
	for index := 0; index < len(store.operations); index += 2 {
		if index+1 >= len(store.operations) || store.operations[index] != "append" || store.operations[index+1] != "flush" {
			t.Fatalf("journal ordering = %v", store.operations)
		}
	}
	token := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOffline})
	if token.Result != brokerResultOK || token.TokenHandle != 77 || token.Desktop != `Sandbox-4242\Default` || tokens.issued != 1 || !tokens.token.closed {
		t.Fatalf("token response = %#v issuer = %#v", token, tokens)
	}
	identity := connection.authorized[reference.Handle].Identity
	unrelated := []byte{0, 0, 8, 0, 1, 2, 3, 4}
	acl.aces[identity] = append(acl.aces[identity], unrelated)
	release := broker.Handle(connection, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID})
	if release.Result != brokerResultOK {
		t.Fatalf("release = %#v", release)
	}
	if desktops := broker.desktops.(*brokerTestDesktopManager); desktops.closed != 1 {
		t.Fatalf("release closed %d desktops", desktops.closed)
	}
	if got := acl.aces[identity]; len(got) != 1 || !bytes.Equal(got[0], unrelated) {
		t.Fatalf("rollback altered unrelated ACEs: %x", got)
	}
}

func TestBrokerRejectsForgedAuthorityAndReplay(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*windowsBroker, *brokerTestConnection, *brokerTestACL, *brokerObjectReference)
	}{
		{name: "forged handle", mutate: func(_ *windowsBroker, _ *brokerTestConnection, _ *brokerTestACL, ref *brokerObjectReference) {
			ref.Handle++
		}},
		{name: "forged path", mutate: func(_ *windowsBroker, _ *brokerTestConnection, _ *brokerTestACL, ref *brokerObjectReference) {
			ref.Path = `C:\other.txt`
		}},
		{name: "dead client", mutate: func(_ *windowsBroker, conn *brokerTestConnection, _ *brokerTestACL, _ *brokerObjectReference) {
			conn.dead = true
		}},
		{name: "other installation SID", mutate: func(_ *windowsBroker, _ *brokerTestConnection, acl *brokerTestACL, _ *brokerObjectReference) {
			acl.forgeSID, _ = InstallationSID("other")
		}},
		{name: "changed object identity", mutate: func(_ *windowsBroker, _ *brokerTestConnection, acl *brokerTestACL, _ *brokerObjectReference) {
			changed := ACLObjectIdentity{Kind: ACLObjectFile, LinkCount: 1}
			acl.forgeObject = &changed
		}},
		{name: "arbitrary ACE", mutate: func(_ *windowsBroker, _ *brokerTestConnection, acl *brokerTestACL, _ *brokerObjectReference) {
			other, _ := InstallationSID("other")
			acl.forgeACE = encodeACE(other, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})
		}},
		{name: "arbitrary access mask", mutate: func(_ *windowsBroker, _ *brokerTestConnection, acl *brokerTestACL, _ *brokerObjectReference) {
			acl.corruptMask = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broker, connection, acl, _, _, reference := newBrokerTestRig(t)
			test.mutate(broker, connection, acl, &reference)
			response := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
			if response.Result != brokerResultUnauthorized {
				t.Fatalf("result = %v", response.Result)
			}
		})
	}

	broker, connection, _, _, _, reference := newBrokerTestRig(t)
	request := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}
	if got := broker.Handle(connection, request); got.Result != brokerResultOK {
		t.Fatalf("first acquire: %v", got.Result)
	}
	if got := broker.Handle(connection, request); got.Result != brokerResultUnauthorized {
		t.Fatalf("replayed acquire: %v", got.Result)
	}
}

func TestBrokerBindsLeaseAndTokenToExactClient(t *testing.T) {
	broker, connection, _, _, tokens, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	other := *connection
	other.binding.PID++
	if got := broker.Handle(&other, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: other.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOffline}); got.Result != brokerResultUnauthorized || tokens.issued != 0 {
		t.Fatalf("forged PID token result = %v issued=%d", got.Result, tokens.issued)
	}
	missing := acquire.LeaseID
	missing[0]++
	if got := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: missing, Account: brokerAccountOffline}); got.Result != brokerResultLeaseNotFound {
		t.Fatalf("missing lease result = %v", got.Result)
	}
	if got := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountUnspecified}); got.Result != brokerResultInvalidRequest {
		t.Fatalf("unrestricted token result = %v", got.Result)
	}
	valid := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOnline})
	if valid.Result != brokerResultOK {
		t.Fatalf("valid token result = %v", valid.Result)
	}
	if replay := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOnline}); replay.Result != brokerResultUnauthorized {
		t.Fatalf("token replay result = %v", replay.Result)
	}
}

func TestBrokerRejectsMalformedOrWrongNonceBeforeMechanisms(t *testing.T) {
	broker, connection, _, _, tokens, _ := newBrokerTestRig(t)
	wrong := connection.binding.Nonce
	wrong[0]++
	response := broker.Handle(connection, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: wrong})
	if response.Result != brokerResultUnauthorized || tokens.issued != 0 {
		t.Fatalf("wrong nonce result = %v", response.Result)
	}
	response = broker.Handle(connection, brokerFrame{Kind: brokerMessageKind(99), Direction: brokerRequest, Nonce: connection.binding.Nonce})
	if response.Result != brokerResultInvalidRequest {
		t.Fatalf("unknown operation result = %v (%s)", response.Result, fmt.Sprint(response))
	}
}

func TestBrokerDisconnectCleansOnlyExactBoundClientLeases(t *testing.T) {
	broker, connection, acl, _, _, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if acquire.Result != brokerResultOK {
		t.Fatalf("acquire = %v", acquire.Result)
	}
	issued := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOffline})
	if issued.Result != brokerResultOK {
		t.Fatalf("issue = %#v", issued)
	}
	desktops := broker.desktops.(*brokerTestDesktopManager)
	wrong := connection.binding
	wrong.CreationTime++
	if err := broker.Disconnect(wrong); err != nil {
		t.Fatal(err)
	}
	if len(broker.leases) != 1 || desktops.closed != 0 {
		t.Fatal("PID-only disconnect cleaned the lease")
	}
	if err := broker.Disconnect(connection.binding); err != nil {
		t.Fatal(err)
	}
	if len(broker.leases) != 0 || len(acl.aces[connection.authorized[reference.Handle].Identity]) != 0 || desktops.closed != 1 {
		t.Fatal("exact client disconnect retained lease authority")
	}
}

func TestBrokerDesktopCreationUsesOnlyValidatedLeaseAuthorityAndRollsBack(t *testing.T) {
	broker, connection, _, _, tokens, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	manager := broker.desktops.(*brokerTestDesktopManager)
	manager.fail = errors.New("desktop unavailable")
	response := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOffline})
	if response.Result != brokerResultUnavailable || response.TokenHandle != 0 || response.Desktop != "" {
		t.Fatalf("failed desktop response = %#v", response)
	}
	if len(manager.created) != 0 || tokens.issued != 1 || tokens.token == nil || !tokens.token.closed || broker.leases[ACLLeaseID(acquire.LeaseID)].tokenIssued {
		t.Fatalf("desktop failure leaked authority: manager=%#v tokens=%#v", manager, tokens)
	}

	manager.fail = nil
	response = broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOnline})
	if response.Result != brokerResultOK || len(manager.created) != 1 {
		t.Fatalf("retry response=%#v contexts=%#v", response, manager.created)
	}
	context := manager.created[0]
	if context.LeaseID != ACLLeaseID(acquire.LeaseID) || !sameBrokerBinding(context.Binding, connection.binding) ||
		context.Installation != broker.installationSID || context.Restricting != broker.leases[context.LeaseID].restricting ||
		context.Account != brokerAccountOnline {
		t.Fatalf("desktop context not bound to exact validated lease: %#v", context)
	}
}

// TestBrokerReconcileClosesDeadClientsDesktop: a reconcile request retires a
// lease (desktop included) only once its client process has exited; the same
// request against a live client's lease leaves it alone (review M14).
func TestBrokerReconcileClosesDeadClientsDesktop(t *testing.T) {
	broker, connection, _, _, _, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	issued := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID, Account: brokerAccountOffline})
	if issued.Result != brokerResultOK {
		t.Fatalf("issue = %#v", issued)
	}
	manager := broker.desktops.(*brokerTestDesktopManager)
	observer := brokerTestObserver(t, connection)
	if response := broker.Handle(observer, brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: observer.binding.Nonce}); response.Result != brokerResultOK || manager.closed != 0 || len(broker.leases) != 1 {
		t.Fatalf("reconcile against a live client = %#v desktops=%#v leases=%d", response, manager, len(broker.leases))
	}
	connection.binding.Process.(*brokerTestProcess).exited.Store(true)
	response := broker.Handle(observer, brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: observer.binding.Nonce})
	if response.Result != brokerResultOK || manager.closed != 1 || len(broker.leases) != 0 {
		t.Fatalf("reconcile against a dead client = %#v desktops=%#v leases=%d", response, manager, len(broker.leases))
	}
}

// brokerTestObserver is a second, independently bound, live connection that
// shares the first connection's authorized object table.
func brokerTestObserver(t *testing.T, first *brokerTestConnection) *brokerTestConnection {
	t.Helper()
	binding := first.binding
	binding.Nonce[2]++
	binding.PID++
	binding.Process = &brokerTestProcess{id: 2}
	return &brokerTestConnection{binding: binding, authorized: first.authorized}
}

func TestBrokerNeverReusesSIDAndNeverMutatesBeforeJournalFlush(t *testing.T) {
	broker, connection, acl, store, _, reference := newBrokerTestRig(t)
	store.flushErr = errors.New("disk unavailable")
	request := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}
	if response := broker.Handle(connection, request); response.Result != brokerResultUnavailable || len(acl.operations) != 0 {
		t.Fatalf("flush failure response=%v ACL=%v", response.Result, acl.operations)
	}

	installation, _ := InstallationSID("installation-A")
	retirement := &brokerTestRetirement{seen: make(map[string]bool)}
	makeGenerator := func() *OneShotSIDGenerator {
		generator, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{0x61}, sidEntropyBytes)), retirement)
		if err != nil {
			t.Fatal(err)
		}
		return generator
	}
	emptyStore := &brokerTestJournalStore{}
	acl.store = emptyStore
	journal, _ := newBrokerLeaseJournal(emptyStore)
	first, err := newWindowsBroker(installation, makeGenerator(), journal, acl, &brokerTestTokenIssuer{}, &brokerTestDesktopManager{}, bytes.NewReader(bytes.Repeat([]byte{1}, brokerLeaseIDSize)))
	if err != nil {
		t.Fatal(err)
	}
	connection.binding.Nonce[0]++
	if got := first.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}); got.Result != brokerResultOK {
		t.Fatalf("first SID result = %v", got.Result)
	}
	second, err := newWindowsBroker(installation, makeGenerator(), journal, acl, &brokerTestTokenIssuer{}, &brokerTestDesktopManager{}, bytes.NewReader(bytes.Repeat([]byte{2}, brokerLeaseIDSize)))
	if err != nil {
		t.Fatal(err)
	}
	connection.binding.Nonce[0]++
	if got := second.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}); got.Result != brokerResultUnavailable {
		t.Fatalf("reused SID result = %v", got.Result)
	}
}

// TestBrokerQuarantinesUnrollbackableLeaseInsteadOfWedging covers design §13:
// a lease whose rollback fails is retained in the journal and quarantined,
// construction still succeeds, status reports recovery pending, new work is
// refused, and a later successful retry releases it.
func TestBrokerQuarantinesUnrollbackableLeaseInsteadOfWedging(t *testing.T) {
	first, connection, acl, store, _, reference := newBrokerTestRig(t)
	acquire := first.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if acquire.Result != brokerResultOK {
		t.Fatalf("acquire = %v", acquire.Result)
	}
	leaseID := ACLLeaseID(acquire.LeaseID)
	identity := connection.authorized[reference.Handle].Identity
	if len(acl.aces[identity]) != 1 {
		t.Fatalf("lease ACEs = %d, want 1 (the lease SID only)", len(acl.aces[identity]))
	}

	// Service restart with a lease the ACL mechanism cannot roll back (the
	// object was replaced, or an identical ACE collides).
	acl.rollbackErr = fmt.Errorf("%w: injected", ErrRestrictedTargetChanged)
	installation, _ := InstallationSID("installation-A")
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	sids, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{0x77}, sidEntropyBytes)), &brokerTestRetirement{seen: make(map[string]bool)})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newWindowsBroker(installation, sids, journal, acl, &brokerTestTokenIssuer{}, &brokerTestDesktopManager{}, bytes.NewReader(bytes.Repeat([]byte{0x43}, 4*brokerLeaseIDSize)))
	if err != nil {
		t.Fatalf("one unrollbackable lease prevented broker start: %v", err)
	}
	if _, quarantined := restarted.quarantined[leaseID]; !quarantined || len(restarted.leases) != 0 {
		t.Fatalf("quarantine = %v, leases = %d", restarted.quarantined, len(restarted.leases))
	}
	if recovered, err := journal.recover(); err != nil || len(recovered) != 1 {
		t.Fatalf("quarantined lease left the journal: %v, %v", recovered, err)
	}

	status := restarted.Handle(connection, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: connection.binding.Nonce})
	if status.Result != brokerResultRecoveryPending || status.Generation == 0 {
		t.Fatalf("status = %#v, want recovery pending with a generation", status)
	}
	connection.binding.Nonce[0]++
	applied := len(acl.operations)
	refused := restarted.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if refused.Result != brokerResultRecoveryPending || refused.LeaseID != ([brokerLeaseIDSize]byte{}) {
		t.Fatalf("acquire during quarantine = %#v", refused)
	}
	for _, operation := range acl.operations[applied:] {
		if strings.HasPrefix(operation, "apply:") {
			t.Fatalf("ACL applied during quarantine: %v", acl.operations[applied:])
		}
	}
	reconcile := restarted.Handle(connection, brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: connection.binding.Nonce})
	if reconcile.Result != brokerResultRecoveryPending {
		t.Fatalf("failed reconcile = %v", reconcile.Result)
	}

	// The obstruction clears; the next status retries and releases the lease.
	acl.rollbackErr = nil
	status = restarted.Handle(connection, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: connection.binding.Nonce})
	if status.Result != brokerResultOK || len(restarted.quarantined) != 0 {
		t.Fatalf("status after recovery = %v, quarantine = %v", status.Result, restarted.quarantined)
	}
	if len(acl.aces[identity]) != 0 {
		t.Fatalf("recovered lease left ACEs: %x", acl.aces[identity])
	}
	if recovered, err := journal.recover(); err != nil || len(recovered) != 0 {
		t.Fatalf("recovered lease is still journaled: %v, %v", recovered, err)
	}
	connection.binding.Nonce[0]++
	if got := restarted.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}); got.Result != brokerResultOK {
		t.Fatalf("acquire after recovery = %v", got.Result)
	}
}

func TestBrokerReleaseFailureQuarantinesAndBlocksNewWork(t *testing.T) {
	broker, connection, acl, _, tokens, reference := newBrokerTestRig(t)
	first := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	other := *connection
	other.binding.Nonce[1]++
	second := broker.Handle(&other, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: other.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if first.Result != brokerResultOK || second.Result != brokerResultOK {
		t.Fatalf("acquire = %v/%v", first.Result, second.Result)
	}

	acl.rollbackErr = errACLIdenticalCollision
	release := broker.Handle(connection, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: first.LeaseID})
	if release.Result != brokerResultRecoveryPending {
		t.Fatalf("failed release = %v", release.Result)
	}
	if _, quarantined := broker.quarantined[ACLLeaseID(first.LeaseID)]; !quarantined || broker.leases[ACLLeaseID(first.LeaseID)] != nil {
		t.Fatal("lease whose release failed was not moved to quarantine")
	}
	// The sibling's already-active lease cannot obtain a token while the
	// broker is unhealthy: a spawn is new work.
	token := broker.Handle(&other, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: other.binding.Nonce, LeaseID: second.LeaseID, Account: brokerAccountOffline})
	if token.Result != brokerResultRecoveryPending || tokens.issued != 0 {
		t.Fatalf("token issued during quarantine: %#v issued=%d", token, tokens.issued)
	}
	// Releasing existing authority is still permitted, and its failure joins
	// the quarantine rather than wedging the lease in the live set.
	if got := broker.Handle(&other, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: other.binding.Nonce, LeaseID: second.LeaseID}); got.Result != brokerResultRecoveryPending || len(broker.quarantined) != 2 || len(broker.leases) != 0 {
		t.Fatalf("second release = %v quarantine=%d leases=%d", got.Result, len(broker.quarantined), len(broker.leases))
	}
	acl.rollbackErr = nil
	if err := broker.reconcile(); err != nil || len(broker.quarantined) != 0 {
		t.Fatalf("reconcile after recovery = %v, quarantine=%d", err, len(broker.quarantined))
	}
}
