//go:build windows

package windows

import "testing"

func TestRecoveryIntegrationRepeatedRestartLeavesNoLeaseOrACE(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
		broker, connection, acl, _, _, reference := newBrokerTestRig(t)
		acquire := broker.Handle(connection, brokerFrame{
			Kind: brokerMessageAcquireLease, Direction: brokerRequest,
			Nonce: connection.binding.Nonce, Objects: []brokerObjectReference{reference},
		})
		if acquire.Result != brokerResultOK {
			t.Fatalf("iteration %d acquire = %v", iteration, acquire.Result)
		}
		broker.leases = make(map[ACLLeaseID]*brokerLease)
		if err := broker.reconcile(); err != nil {
			t.Fatalf("iteration %d reconcile: %v", iteration, err)
		}
		recovered, err := broker.journal.recover()
		if err != nil || len(recovered) != 0 {
			t.Fatalf("iteration %d residual journal = %#v, %v", iteration, recovered, err)
		}
		for object, aces := range acl.aces {
			if len(aces) != 0 {
				t.Fatalf("iteration %d residual ACEs on %#v: %d", iteration, object, len(aces))
			}
		}
	}
}

func TestRecoveryIntegrationTornTailNeverHidesCompleteCorruption(t *testing.T) {
	file := &fakeBrokerJournalFile{data: []byte("{\"complete\":true}\n{\"torn\"")}
	store, err := newProtectedBrokerLeaseJournalStore(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.ReadAll()
	if err != nil || string(data) != "{\"complete\":true}\n" {
		t.Fatalf("torn-tail recovery = %q, %v", data, err)
	}
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.recover(); err == nil {
		t.Fatal("complete but invalid record was hidden after torn-tail recovery")
	}
}
