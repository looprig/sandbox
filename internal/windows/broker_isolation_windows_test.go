//go:build windows

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	win "golang.org/x/sys/windows"
)

// brokerAcquire is a terse helper over the broker's acquire request.
func brokerAcquire(t *testing.T, broker *windowsBroker, connection *brokerTestConnection, reference brokerObjectReference) [brokerLeaseIDSize]byte {
	t.Helper()
	response := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if response.Result != brokerResultOK {
		t.Fatalf("acquire = %v", response.Result)
	}
	return response.LeaseID
}

// aceTrustees returns the SID tail of every ACE in aces.
func aceTrustees(aces [][]byte) [][]byte {
	result := make([][]byte, 0, len(aces))
	for _, ace := range aces {
		result = append(result, append([]byte(nil), ace[8:]...))
	}
	return result
}

// TestBrokerProjectsOnlyTheLeaseSIDOntoUserObjects pins H10: the plan the
// broker requests names exactly the lease's one-shot SID, every applied and
// journaled ACE names it, none names the persistent installation SID, and
// the issued token still carries the installation SID in its restricting
// list (where it reaches only the runner and installation-owned objects).
func TestBrokerProjectsOnlyTheLeaseSIDOntoUserObjects(t *testing.T) {
	broker, connection, acl, store, tokens, reference := newBrokerTestRig(t)
	leaseID := brokerAcquire(t, broker, connection, reference)
	lease := broker.leases[ACLLeaseID(leaseID)]
	if lease == nil {
		t.Fatal("acquired lease is not live")
	}
	if len(acl.trustees) != 1 || len(acl.trustees[0]) != 1 || acl.trustees[0][0] != lease.restricting {
		t.Fatalf("plan trustees = %v, want only the lease SID %s", acl.trustees, lease.restricting)
	}
	installation := broker.installationSID.binary()
	for identity, aces := range acl.aces {
		for _, trustee := range aceTrustees(aces) {
			if bytes.Equal(trustee, installation) {
				t.Fatalf("object %#v carries an installation-SID ACE", identity)
			}
			if !bytes.Equal(trustee, lease.restricting.binary()) {
				t.Fatalf("object %#v carries an ACE for a SID other than the lease's", identity)
			}
		}
	}
	journal, _ := newBrokerLeaseJournal(store)
	recovered, err := journal.recover()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range recovered[ACLLeaseID(leaseID)].Mutations {
		if mutation.SID != lease.restricting {
			t.Fatalf("journaled trustee = %s, want the lease SID", mutation.SID)
		}
	}
	if got := broker.Handle(connection, brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: leaseID, Account: brokerAccountOffline}); got.Result != brokerResultOK || tokens.issued != 1 {
		t.Fatalf("token = %#v", got)
	}
}

// TestBrokerRefusesAPlanNamingTheInstallationSID: even a mechanism that tried
// to project the installation SID is refused before anything is applied.
func TestBrokerRefusesAPlanNamingTheInstallationSID(t *testing.T) {
	broker, connection, acl, _, _, reference := newBrokerTestRig(t)
	acl.forgeSID = broker.installationSID
	response := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if response.Result != brokerResultUnauthorized {
		t.Fatalf("installation-SID plan = %v, want unauthorized", response.Result)
	}
	for _, operation := range acl.operations {
		if operation == "apply:"+broker.installationSID.String() {
			t.Fatalf("installation-SID ACE applied: %v", acl.operations)
		}
	}
}

// TestBrokerRollbackOfOneLeaseLeavesAnotherLeaseIntact: two concurrent leases
// on one object own distinct, non-identical ACEs, so releasing one removes
// exactly its own and the other's survives (H10, and the H11 collision is
// impossible across leases).
func TestBrokerRollbackOfOneLeaseLeavesAnotherLeaseIntact(t *testing.T) {
	broker, first, acl, _, _, reference := newBrokerTestRig(t)
	second := brokerTestObserver(t, first)
	firstLease := brokerAcquire(t, broker, first, reference)
	secondLease := brokerAcquire(t, broker, second, reference)
	identity := first.authorized[reference.Handle].Identity
	secondSID := broker.leases[ACLLeaseID(secondLease)].restricting
	if aces := acl.aces[identity]; len(aces) != 2 || bytes.Equal(aces[0], aces[1]) {
		t.Fatalf("two leases share an identical ACE: %x", aces)
	}
	if got := broker.Handle(first, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: first.binding.Nonce, LeaseID: firstLease}); got.Result != brokerResultOK {
		t.Fatalf("release first = %v", got.Result)
	}
	remaining := aceTrustees(acl.aces[identity])
	if len(remaining) != 1 || !bytes.Equal(remaining[0], secondSID.binary()) {
		t.Fatalf("after releasing the first lease, remaining trustees = %x, want only the second lease's", remaining)
	}
	if got := broker.Handle(second, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: second.binding.Nonce, LeaseID: secondLease}); got.Result != brokerResultOK {
		t.Fatalf("release second = %v", got.Result)
	}
	if len(acl.aces[identity]) != 0 || len(broker.quarantined) != 0 {
		t.Fatalf("leftover ACEs %x quarantine %d", acl.aces[identity], len(broker.quarantined))
	}
}

// TestBrokerReinstallCannotReactivateALeftoverACE: an ACE orphaned by a lost
// journal (power loss, a hostile delete, a removal that could not reconcile)
// names only the dead lease's one-shot SID. A reinstall derives the SAME
// installation SID, and before H10 that SID's leftover ACEs went live again
// for every new token; now no leftover names it, and the new lease's SID is
// a fresh one the leftover cannot match.
func TestBrokerReinstallCannotReactivateALeftoverACE(t *testing.T) {
	_, connection, acl, _, _, reference := newBrokerTestRig(t)
	installation, _ := InstallationSID("installation-A")
	newBroker := func(entropy byte) *windowsBroker {
		store := &brokerTestJournalStore{}
		acl.store = store
		journal, _ := newBrokerLeaseJournal(store)
		sids, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{entropy}, sidEntropyBytes)), &brokerTestRetirement{seen: make(map[string]bool)})
		if err != nil {
			t.Fatal(err)
		}
		broker, err := newWindowsBroker(installation, sids, journal, acl, &brokerTestTokenIssuer{}, &brokerTestDesktopManager{}, bytes.NewReader(bytes.Repeat([]byte{entropy}, brokerLeaseIDSize)))
		if err != nil {
			t.Fatal(err)
		}
		return broker
	}
	before := newBroker(0x51)
	orphan := before.leases[ACLLeaseID(brokerAcquire(t, before, connection, reference))].restricting
	identity := connection.authorized[reference.Handle].Identity
	leftovers := aceTrustees(acl.aces[identity])

	// Reinstall with the same InstallationID and a lost journal.
	connection.binding.Nonce[0]++
	after := newBroker(0x52)
	fresh := after.leases[ACLLeaseID(brokerAcquire(t, after, connection, reference))].restricting
	if fresh == orphan {
		t.Fatal("reinstall reissued the orphaned lease SID")
	}
	for _, trustee := range leftovers {
		if bytes.Equal(trustee, installation.binary()) || bytes.Equal(trustee, fresh.binary()) {
			t.Fatalf("leftover ACE %x is reachable by the reinstalled broker's tokens", trustee)
		}
	}
}

// TestBrokerJournalRefusesInstallationTrusteeWritesButRecoversLegacyOnes: no
// current write may journal an installation-SID trustee, but a journal left
// by a pre-H10 broker still recovers, so its ACEs can be rolled back.
func TestBrokerJournalRefusesInstallationTrusteeWritesButRecoversLegacyOnes(t *testing.T) {
	installation, _ := InstallationSID("installation-A")
	lease := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "legacy")
	var id ACLLeaseID
	id[0] = 9
	var nonce [brokerNonceSize]byte
	nonce[0] = 3
	var fileID [16]byte
	fileID[0] = 1
	object := ACLObjectIdentity{VolumeSerial: 3, FileID: fileID, Kind: ACLObjectFile, LinkCount: 1}
	base := brokerLeaseEvent{LeaseID: id, Nonce: nonce, PID: 4, Created: 5, SID: lease}
	legacy := base
	legacy.Kind, legacy.Trustee, legacy.Object, legacy.Path = brokerLeaseEventMutationPrepared, installation, object, `C:\data\file.txt`
	legacy.ACE = encodeACE(installation, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})

	store := &brokerTestJournalStore{}
	journal, _ := newBrokerLeaseJournal(store)
	reserved := base
	reserved.Kind = brokerLeaseEventReserved
	if err := journal.appendAndFlush(reserved); err != nil {
		t.Fatal(err)
	}
	if err := journal.appendAndFlush(legacy); err == nil {
		t.Fatal("a current write journaled an installation-SID trustee")
	}
	// Hand-encode the record the old broker would have written.
	legacy.Version, legacy.SIDText, legacy.SIDKind = 1, lease.String(), lease.kind
	legacy.TrusteeText, legacy.TrusteeKind = installation.String(), installation.kind
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	store.data.Write(append(encoded, '\n'))
	recovered, err := journal.recover()
	if err != nil {
		t.Fatalf("legacy journal does not recover: %v", err)
	}
	if mutations := recovered[id].Mutations; len(mutations) != 1 || mutations[0].SID != installation {
		t.Fatalf("legacy mutation = %#v", recovered[id])
	}
}

// TestBrokerStatusIsServedWhileAnotherConnectionAcquires pins L8: the
// projection runs outside broker.mu, so a second connection's status request
// completes while the first connection's acquire is held mid-Apply.
func TestBrokerStatusIsServedWhileAnotherConnectionAcquires(t *testing.T) {
	broker, connection, acl, _, _, reference := newBrokerTestRig(t)
	observer := brokerTestObserver(t, connection)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	acl.applyHook = func() {
		close(entered)
		<-proceed
	}
	acquired := make(chan brokerFrame, 1)
	go func() {
		acquired <- broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("acquire never reached Apply")
	}
	status := make(chan brokerFrame, 1)
	go func() {
		status <- broker.Handle(observer, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: observer.binding.Nonce})
	}()
	select {
	case response := <-status:
		if response.Result != brokerResultOK || response.Generation == 0 {
			t.Fatalf("status during acquire = %#v", response)
		}
	case <-time.After(10 * time.Second):
		close(proceed)
		t.Fatal("status was blocked by another connection's in-progress acquire")
	}
	// The in-progress lease is invisible to a reconcile from the observer.
	if response := broker.Handle(observer, brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: observer.binding.Nonce}); response.Result != brokerResultOK {
		t.Fatalf("reconcile during acquire = %v", response.Result)
	}
	close(proceed)
	if response := <-acquired; response.Result != brokerResultOK {
		t.Fatalf("acquire after a concurrent reconcile = %v", response.Result)
	}
	if len(broker.leases) != 1 || len(broker.acquiring) != 0 {
		t.Fatalf("leases=%d acquiring=%d after publication", len(broker.leases), len(broker.acquiring))
	}
}

// TestBrokerReconcileScopeSparesLiveConnections pins M14's reconcile scope:
// a reconcile from connection B never rolls back connection A's live lease,
// and rolls it back once A's client process has exited.
func TestBrokerReconcileScopeSparesLiveConnections(t *testing.T) {
	broker, connection, acl, _, _, reference := newBrokerTestRig(t)
	observer := brokerTestObserver(t, connection)
	leaseID := brokerAcquire(t, broker, connection, reference)
	identity := connection.authorized[reference.Handle].Identity
	reconcile := func() brokerFrame {
		return broker.Handle(observer, brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: observer.binding.Nonce})
	}
	if response := reconcile(); response.Result != brokerResultOK || broker.leases[ACLLeaseID(leaseID)] == nil || len(acl.aces[identity]) != 1 {
		t.Fatalf("reconcile from B touched A's live lease: %v leases=%d aces=%d", response.Result, len(broker.leases), len(acl.aces[identity]))
	}
	connection.binding.Process.(*brokerTestProcess).exited.Store(true)
	if response := reconcile(); response.Result != brokerResultOK || broker.leases[ACLLeaseID(leaseID)] != nil || len(acl.aces[identity]) != 0 {
		t.Fatalf("reconcile did not retire a dead client's lease: %v leases=%d aces=%d", response.Result, len(broker.leases), len(acl.aces[identity]))
	}
}

// compactingJournalStore is a brokerLeaseJournalStore that also answers
// brokerLeaseJournalCompactor, with an injectable "full" refusal.
type compactingJournalStore struct {
	brokerTestJournalStore
	fullOnce  bool
	compacted int
	size      int
}

func (store *compactingJournalStore) Append(data []byte) error {
	if store.fullOnce {
		store.fullOnce = false
		return errBrokerLeaseJournalFull
	}
	return store.brokerTestJournalStore.Append(data)
}
func (store *compactingJournalStore) Size() int {
	if store.size != 0 {
		return store.size
	}
	return store.data.Len()
}
func (store *compactingJournalStore) Compact(rewrite func([]byte) ([]byte, error)) error {
	compacted, err := rewrite(store.data.Bytes())
	if err != nil {
		return err
	}
	store.compacted++
	store.data.Reset()
	store.data.Write(compacted)
	return nil
}

// TestBrokerJournalCompactsAtStartReleaseThresholdAndWhenFull pins M14's
// three triggers: after the constructor's reconcile, after a release once the
// journal passes the threshold (never below it), and when an append is
// refused because the journal is full, which is retried once after compaction
// so a Released record can always be written.
func TestBrokerJournalCompactsAtStartReleaseThresholdAndWhenFull(t *testing.T) {
	installation, _ := InstallationSID("installation-A")
	store := &compactingJournalStore{}
	journal, _ := newBrokerLeaseJournal(store)
	sids, _ := NewOneShotSIDGenerator(&brokerTestEntropy{seed: 0x33}, &brokerTestRetirement{seen: make(map[string]bool)})
	acl := &brokerTestACL{aces: make(map[ACLObjectIdentity][][]byte)}
	broker, err := newWindowsBroker(installation, sids, journal, acl, &brokerTestTokenIssuer{}, &brokerTestDesktopManager{}, &brokerTestEntropy{seed: 0x34})
	if err != nil {
		t.Fatal(err)
	}
	if store.compacted != 1 {
		t.Fatalf("startup compactions = %d, want 1", store.compacted)
	}
	_, connection, _, _, _, reference := newBrokerTestRig(t)
	first := brokerAcquire(t, broker, connection, reference)
	if got := broker.Handle(connection, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: first}); got.Result != brokerResultOK {
		t.Fatalf("release = %v", got.Result)
	}
	if store.compacted != 1 {
		t.Fatalf("a small journal was compacted on release (%d)", store.compacted)
	}
	connection.binding.Nonce[0]++
	second := brokerAcquire(t, broker, connection, reference)
	store.size = brokerLeaseJournalCompactionThreshold
	store.fullOnce = true // the Released record itself meets a full journal
	if got := broker.Handle(connection, brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, LeaseID: second}); got.Result != brokerResultOK {
		t.Fatalf("release into a full journal = %v", got.Result)
	}
	if store.compacted != 3 {
		t.Fatalf("compactions = %d, want full-journal retry plus post-release threshold", store.compacted)
	}
	if recovered, err := journal.recover(); err != nil || len(recovered) != 0 || store.data.Len() != 0 {
		t.Fatalf("compacted journal = %q recovered %v err %v, want empty", store.data.String(), recovered, err)
	}
}

// TestProtectedBrokerLeaseJournalCompactReplacesOnlyWhenSomethingIsDropped
// covers the store half of M14 against the fake file: no rewrite when nothing
// is released, an atomic Replace when something is, and an untouched journal
// (file and memory) when Replace fails.
func TestProtectedBrokerLeaseJournalCompactReplacesOnlyWhenSomethingIsDropped(t *testing.T) {
	file := &fakeBrokerJournalFile{}
	store, err := newProtectedBrokerLeaseJournalStore(file)
	if err != nil {
		t.Fatal(err)
	}
	journal, _ := newBrokerLeaseJournal(store)
	lease := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "compact")
	event := func(kind brokerLeaseEventKind, id byte) brokerLeaseEvent {
		var leaseID ACLLeaseID
		leaseID[0] = id
		return brokerLeaseEvent{Kind: kind, LeaseID: leaseID, Nonce: [brokerNonceSize]byte{1}, PID: 2, Created: 3, SID: lease}
	}
	for _, record := range []brokerLeaseEvent{event(brokerLeaseEventReserved, 1), event(brokerLeaseEventReserved, 2)} {
		if err := journal.appendAndFlush(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Compact(compactBrokerLeaseJournal); err != nil || slicesContain(file.operations, "replace") {
		t.Fatalf("nothing-to-drop compaction = %v operations %v", err, file.operations)
	}
	if err := journal.appendAndFlush(event(brokerLeaseEventReleased, 1)); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), file.data...)
	file.replaceErr = errors.New("injected rename failure")
	if err := store.Compact(compactBrokerLeaseJournal); err == nil {
		t.Fatal("failed replace reported success")
	}
	if data, _ := store.ReadAll(); !bytes.Equal(data, before) || !bytes.Equal(file.data, before) {
		t.Fatal("failed compaction altered the journal")
	}
	file.replaceErr = nil
	if err := store.Compact(compactBrokerLeaseJournal); err != nil {
		t.Fatal(err)
	}
	recovered, err := journal.recover()
	if err != nil || len(recovered) != 1 || store.Size() >= len(before) || !bytes.Equal(file.data, mustReadAll(t, store)) {
		t.Fatalf("compacted journal recovered %v err %v size %d", recovered, err, store.Size())
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mustReadAll(t *testing.T, store *protectedBrokerLeaseJournalStore) []byte {
	t.Helper()
	data, err := store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestBrokerTokenDuplicationRequestsOnlyLaunchAccess pins L8: the client's
// duplicate of an issued token is created with exactly
// TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_QUERY, never DUPLICATE_SAME_ACCESS.
func TestBrokerTokenDuplicationRequestsOnlyLaunchAccess(t *testing.T) {
	var gotAccess, gotOptions uint32
	var gotInherit bool
	fake := func(_ win.Handle, source win.Handle, target win.Handle, result *win.Handle, access uint32, inherit bool, options uint32) error {
		if source != win.Handle(9) || target != win.Handle(44) {
			t.Fatalf("duplicate source/target = %d/%d", source, target)
		}
		gotAccess, gotInherit, gotOptions = access, inherit, options
		*result = 88
		return nil
	}
	handle, err := duplicateBrokerTokenToProcess(fake, win.Token(9), win.Handle(44))
	if err != nil || handle != 88 {
		t.Fatalf("duplicate = %d, %v", handle, err)
	}
	if want := uint32(win.TOKEN_ASSIGN_PRIMARY | win.TOKEN_DUPLICATE | win.TOKEN_QUERY); gotAccess != want {
		t.Fatalf("requested access = %#x, want %#x", gotAccess, want)
	}
	if gotOptions&win.DUPLICATE_SAME_ACCESS != 0 || gotInherit {
		t.Fatalf("options = %#x inherit = %v, want an exact non-inheritable mask", gotOptions, gotInherit)
	}
}
