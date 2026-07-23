//go:build windows

package windows

import (
	"bytes"
	"testing"
)

func TestBrokerLeaseJournalRecoversExactPreparedMutation(t *testing.T) {
	broker, connection, _, store, _, reference := newBrokerTestRig(t)
	leaseID := ACLLeaseID{1}
	restricting, err := broker.sids.Next()
	if err != nil {
		t.Fatal(err)
	}
	object := connection.authorized[reference.Handle].Identity
	ace := encodeACE(restricting, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})
	lease := &brokerLease{id: leaseID, binding: connection.binding, restricting: restricting}
	mutation := brokerACLMutation{Object: object, SID: restricting, ACE: ace, BaselineOccurrences: 3}
	if err := broker.writeEvent(lease, brokerLeaseEventReserved, 0, brokerACLMutation{}); err != nil {
		t.Fatal(err)
	}
	if err := broker.writeEvent(lease, brokerLeaseEventMutationPrepared, 0, mutation); err != nil {
		t.Fatal(err)
	}
	if err := broker.writeEvent(lease, brokerLeaseEventActive, 0, brokerACLMutation{}); err != nil {
		t.Fatal(err)
	}
	recovered, err := broker.journal.recover()
	if err != nil {
		t.Fatal(err)
	}
	got := recovered[leaseID]
	if !got.Active || got.SID != restricting || len(got.Mutations) != 1 || got.Mutations[0].Object != object || got.Mutations[0].BaselineOccurrences != 3 || !bytes.Equal(got.Mutations[0].ACE, ace) {
		t.Fatalf("recovered = %#v", got)
	}
	if len(store.operations) != 6 {
		t.Fatalf("operations = %v", store.operations)
	}
}

func TestBrokerLeaseJournalRejectsOutOfOrderAndUnknownVersions(t *testing.T) {
	broker, connection, _, store, _, _ := newBrokerTestRig(t)
	restricting, err := broker.sids.Next()
	if err != nil {
		t.Fatal(err)
	}
	lease := &brokerLease{id: ACLLeaseID{2}, binding: connection.binding, restricting: restricting}
	if err := broker.writeEvent(lease, brokerLeaseEventReserved, 0, brokerACLMutation{}); err != nil {
		t.Fatal(err)
	}
	if err := broker.writeEvent(lease, brokerLeaseEventActive, 0, brokerACLMutation{}); err != nil {
		t.Fatal(err)
	}
	if err := broker.writeEvent(lease, brokerLeaseEventActive, 0, brokerACLMutation{}); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.journal.recover(); err == nil {
		t.Fatal("duplicate active event accepted")
	}
	store.data.Reset()
	store.data.WriteString(`{"version":2}` + "\n")
	if _, err := broker.journal.recover(); err == nil {
		t.Fatal("unknown version accepted")
	}
}

func TestBrokerReconcileRollsBackBeforeMarkingReleased(t *testing.T) {
	broker, connection, acl, store, _, reference := newBrokerTestRig(t)
	acquire := broker.Handle(connection, brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference}})
	if acquire.Result != brokerResultOK {
		t.Fatalf("acquire = %v", acquire.Result)
	}
	// Simulate service restart: volatile state is gone, durable journal and
	// object DACL state remain.
	broker.leases = make(map[ACLLeaseID]*brokerLease)
	acl.operations = nil
	before := len(store.operations)
	if err := broker.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(acl.operations) != 2 || len(store.operations) != before+2 || store.operations[before] != "append" || store.operations[before+1] != "flush" {
		t.Fatalf("reconcile ordering ACL=%v journal=%v", acl.operations, store.operations[before:])
	}
	recovered, err := broker.journal.recover()
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered) != 0 {
		t.Fatalf("released lease recovered: %#v", recovered)
	}
}
