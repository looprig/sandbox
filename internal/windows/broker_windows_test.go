//go:build windows

package windows

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

type brokerTestProcess struct{ id int }

func (*brokerTestProcess) Facts() (brokerClientFacts, error) { return brokerClientFacts{}, nil }
func (*brokerTestProcess) CreationTime() (uint64, error)     { return 9, nil }
func (*brokerTestProcess) Close() error                      { return nil }

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
	store        *brokerTestJournalStore
	installation SID
	restricting  SID
	aces         map[ACLObjectIdentity][][]byte
	operations   []string
	forgeSID     SID
	forgeObject  *ACLObjectIdentity
	forgeACE     []byte
	corruptMask  bool
}

func (acl *brokerTestACL) Plan(object brokerAuthorizedObject, trustees []SID) ([]brokerACLMutation, error) {
	acl.installation, acl.restricting = trustees[0], trustees[1]
	mutations := make([]brokerACLMutation, 0, 2)
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
	if !acl.store.flushed {
		return errors.New("mutation applied before durable flush")
	}
	acl.operations = append(acl.operations, "apply:"+mutation.SID.String())
	acl.aces[mutation.Object] = insertCanonicalACE(acl.aces[mutation.Object], append([]byte(nil), mutation.ACE...))
	return nil
}
func (acl *brokerTestACL) Rollback(mutation brokerACLMutation) error {
	acl.operations = append(acl.operations, "rollback:"+mutation.SID.String())
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
	sids, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{0x31}, sidEntropyBytes)), &brokerTestRetirement{seen: make(map[string]bool)})
	if err != nil {
		t.Fatal(err)
	}
	acl := &brokerTestACL{store: store, aces: make(map[ACLObjectIdentity][][]byte)}
	tokens := &brokerTestTokenIssuer{}
	broker, err := newWindowsBroker(installation, sids, journal, acl, tokens, bytes.NewReader(bytes.Repeat([]byte{0x42}, brokerLeaseIDSize)))
	if err != nil {
		t.Fatal(err)
	}
	var nonce [brokerNonceSize]byte
	copy(nonce[:], bytes.Repeat([]byte{0x21}, brokerNonceSize))
	process := &brokerTestProcess{id: 1}
	binding := brokerLeaseBinding{Nonce: nonce, PID: 41, CreationTime: 99, Process: process}
	var fileID [16]byte
	fileID[0] = 7
	reference := brokerObjectReference{Handle: 55, Path: `C:\data\input.txt`, VolumeSerial: 3, FileID: fileID, Kind: brokerObjectFile}
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
	if token.Result != brokerResultOK || token.TokenHandle != 77 || tokens.issued != 1 || !tokens.token.closed {
		t.Fatalf("token response = %#v issuer = %#v", token, tokens)
	}
	identity := connection.authorized[reference.Handle].Identity
	unrelated := []byte{0, 0, 8, 0, 1, 2, 3, 4}
	acl.aces[identity] = append(acl.aces[identity], unrelated)
	release := broker.Handle(connection, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: acquire.LeaseID})
	if release.Result != brokerResultOK {
		t.Fatalf("release = %#v", release)
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
	wrong := connection.binding
	wrong.CreationTime++
	if err := broker.Disconnect(wrong); err != nil {
		t.Fatal(err)
	}
	if len(broker.leases) != 1 {
		t.Fatal("PID-only disconnect cleaned the lease")
	}
	if err := broker.Disconnect(connection.binding); err != nil {
		t.Fatal(err)
	}
	if len(broker.leases) != 0 || len(acl.aces[connection.authorized[reference.Handle].Identity]) != 0 {
		t.Fatal("exact client disconnect retained lease authority")
	}
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
	first, err := newWindowsBroker(installation, makeGenerator(), journal, acl, &brokerTestTokenIssuer{}, bytes.NewReader(bytes.Repeat([]byte{1}, brokerLeaseIDSize)))
	if err != nil {
		t.Fatal(err)
	}
	connection.binding.Nonce[0]++
	if got := first.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}); got.Result != brokerResultOK {
		t.Fatalf("first SID result = %v", got.Result)
	}
	second, err := newWindowsBroker(installation, makeGenerator(), journal, acl, &brokerTestTokenIssuer{}, bytes.NewReader(bytes.Repeat([]byte{2}, brokerLeaseIDSize)))
	if err != nil {
		t.Fatal(err)
	}
	connection.binding.Nonce[0]++
	if got := second.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}}); got.Result != brokerResultUnavailable {
		t.Fatalf("reused SID result = %v", got.Result)
	}
}
