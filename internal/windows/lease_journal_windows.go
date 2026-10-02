//go:build windows

package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// brokerLeaseEventKind and its values live in lease_journal_compaction.go so
// the platform-neutral compaction helper can read them.

// brokerLeaseEvent is cleanup authority only. The exact ACE and object identity
// are persisted before the corresponding mutation. A path is deliberately not
// part of the record and can never become broker authority after a restart.
type brokerLeaseEvent struct {
	Version     uint8                 `json:"version"`
	Kind        brokerLeaseEventKind  `json:"kind"`
	LeaseID     ACLLeaseID            `json:"lease_id"`
	Nonce       [brokerNonceSize]byte `json:"nonce"`
	PID         uint32                `json:"pid"`
	Created     uint64                `json:"created"`
	SID         SID                   `json:"-"`
	SIDText     string                `json:"sid"`
	SIDKind     sidKind               `json:"sid_kind"`
	Trustee     SID                   `json:"-"`
	TrusteeText string                `json:"trustee,omitempty"`
	TrusteeKind sidKind               `json:"trustee_kind,omitempty"`
	MutationID  uint32                `json:"mutation_id,omitempty"`
	Object      ACLObjectIdentity     `json:"object,omitempty"`
	ACE         []byte                `json:"ace,omitempty"`
	Baseline    uint32                `json:"baseline,omitempty"`
	Path        string                `json:"path,omitempty"`
}

type brokerLeaseJournalStore interface {
	Append([]byte) error
	Flush() error
	ReadAll() ([]byte, error)
}

// brokerLeaseJournalCompactor is the optional store capability compaction
// uses (review M14). Size reports the durable byte count; Compact must apply
// rewrite to the store's exact current content and atomically and durably
// replace it with the result, or leave it untouched on any error.
type brokerLeaseJournalCompactor interface {
	Size() int
	Compact(rewrite func([]byte) ([]byte, error)) error
}

// errBrokerLeaseJournalFull is the store's typed refusal of an append that
// would push the journal past maxBrokerLeaseJournalBytes. appendAndFlush
// answers it with one compaction and one retry.
var errBrokerLeaseJournalFull = errors.New("windows sandbox: lease journal is full")

// brokerLeaseJournal owns framing and validation; the injected store owns only
// durable bytes. This keeps service policy independent of a filesystem format.
type brokerLeaseJournal struct{ store brokerLeaseJournalStore }

func newBrokerLeaseJournal(store brokerLeaseJournalStore) (*brokerLeaseJournal, error) {
	if store == nil {
		return nil, errors.New("windows sandbox: lease journal store is required")
	}
	return &brokerLeaseJournal{store: store}, nil
}

func (journal *brokerLeaseJournal) appendAndFlush(event brokerLeaseEvent) error {
	if journal == nil || journal.store == nil {
		return errors.New("windows sandbox: lease journal is unavailable")
	}
	// Writes are held to the current rule: a mutation's trustee is the lease's
	// own one-shot SID and nothing else (design §9.2, review H10).
	if err := validateBrokerLeaseEvent(event, false); err != nil {
		return err
	}
	event.Version = 1
	event.SIDText, event.SIDKind = event.SID.String(), event.SID.kind
	if event.Kind == brokerLeaseEventMutationPrepared {
		event.TrusteeText, event.TrusteeKind = event.Trustee.String(), event.Trustee.kind
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode broker lease event: %w", err)
	}
	encoded = append(encoded, '\n')
	err = journal.store.Append(encoded)
	if errors.Is(err, errBrokerLeaseJournalFull) {
		// A full journal must never be the reason a Released record cannot be
		// written; that would make the lease permanent. Drop what is no
		// longer owed and try once more.
		if compactErr := journal.compact(); compactErr == nil {
			err = journal.store.Append(encoded)
		} else {
			err = errors.Join(err, compactErr)
		}
	}
	if err != nil {
		return fmt.Errorf("append broker lease journal: %w", err)
	}
	if err := journal.store.Flush(); err != nil {
		return fmt.Errorf("flush broker lease journal: %w", err)
	}
	return nil
}

type recoveredBrokerLease struct {
	Binding   brokerLeaseBinding
	SID       SID
	Mutations []brokerACLMutation
	Active    bool
}

func (journal *brokerLeaseJournal) recover() (map[ACLLeaseID]recoveredBrokerLease, error) {
	if journal == nil || journal.store == nil {
		return nil, errors.New("windows sandbox: lease journal is unavailable")
	}
	data, err := journal.store.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read broker lease journal: %w", err)
	}
	leases := make(map[ACLLeaseID]recoveredBrokerLease)
	lines := bytes.Split(data, []byte{'\n'})
	for index, line := range lines {
		if len(line) == 0 {
			continue
		}
		var event brokerLeaseEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, fmt.Errorf("decode broker lease journal event %d: %w", index, err)
		}
		if event.Version != 1 {
			return nil, errors.New("windows sandbox: unsupported lease journal version")
		}
		event.SID = SID{text: event.SIDText, kind: event.SIDKind}
		event.Trustee = SID{text: event.TrusteeText, kind: event.TrusteeKind}
		// Recovery still accepts the installation SID as a trustee, but only so
		// the ACEs an older broker projected with it can be rolled back; no
		// current write produces one (see appendAndFlush).
		if err := validateBrokerLeaseEvent(event, true); err != nil {
			return nil, fmt.Errorf("validate broker lease journal event %d: %w", index, err)
		}
		lease := leases[event.LeaseID]
		switch event.Kind {
		case brokerLeaseEventReserved:
			if lease.SID.String() != "" {
				return nil, errors.New("windows sandbox: duplicate lease reservation")
			}
			lease.Binding = brokerLeaseBinding{Nonce: event.Nonce, PID: event.PID, CreationTime: event.Created}
			lease.SID = event.SID
		case brokerLeaseEventMutationPrepared:
			if lease.SID != event.SID || uint32(len(lease.Mutations)) != event.MutationID {
				return nil, errors.New("windows sandbox: out-of-order lease mutation")
			}
			lease.Mutations = append(lease.Mutations, brokerACLMutation{Object: event.Object, SID: event.Trustee, ACE: append([]byte(nil), event.ACE...), BaselineOccurrences: event.Baseline, Path: event.Path})
		case brokerLeaseEventActive:
			if lease.SID != event.SID || lease.Active {
				return nil, errors.New("windows sandbox: invalid active lease event")
			}
			lease.Active = true
		case brokerLeaseEventReleased:
			if lease.SID != event.SID {
				return nil, errors.New("windows sandbox: invalid released lease event")
			}
			delete(leases, event.LeaseID)
			continue
		}
		leases[event.LeaseID] = lease
	}
	return leases, nil
}

// compact rewrites the journal down to the records of unreleased leases, if
// the store supports it. A store that does not is left to grow, exactly as
// before; a compaction error leaves the store's content untouched.
func (journal *brokerLeaseJournal) compact() error {
	if journal == nil || journal.store == nil {
		return errors.New("windows sandbox: lease journal is unavailable")
	}
	compactor, ok := journal.store.(brokerLeaseJournalCompactor)
	if !ok {
		return nil
	}
	return compactor.Compact(compactBrokerLeaseJournal)
}

// compactIfLarge is the post-release trigger: compact once the journal has
// reached brokerLeaseJournalCompactionThreshold.
func (journal *brokerLeaseJournal) compactIfLarge() error {
	if journal == nil || journal.store == nil {
		return nil
	}
	compactor, ok := journal.store.(brokerLeaseJournalCompactor)
	if !ok || !brokerLeaseJournalNeedsCompaction(compactor.Size()) {
		return nil
	}
	return journal.compact()
}

// validateBrokerLeaseEvent checks one record. legacyInstallationTrustee
// admits a MutationPrepared whose trustee is an installation SID: brokers
// before the H10 fix projected the persistent installation SID onto user
// objects alongside the lease SID, and a journal they left behind must still
// be recoverable so those ACEs can be removed. Writes never set it.
func validateBrokerLeaseEvent(event brokerLeaseEvent, legacyInstallationTrustee bool) error {
	if event.LeaseID == (ACLLeaseID{}) || event.Nonce == ([brokerNonceSize]byte{}) || event.PID == 0 || event.Created == 0 || !event.SID.isRestrictedTierTrustee() {
		return errors.New("windows sandbox: invalid lease journal event identity")
	}
	switch event.Kind {
	case brokerLeaseEventReserved, brokerLeaseEventActive, brokerLeaseEventReleased:
		if event.MutationID != 0 || event.Object != (ACLObjectIdentity{}) || len(event.ACE) != 0 || event.Baseline != 0 || event.Trustee.String() != "" || event.Path != "" {
			return errors.New("windows sandbox: unexpected lease event mutation")
		}
	case brokerLeaseEventMutationPrepared:
		trusteeAllowed := event.Trustee == event.SID ||
			(legacyInstallationTrustee && event.Trustee.kind == sidKindInstallation)
		if !event.Object.valid() || !canonicalBrokerPath(event.Path) || !trusteeAllowed || !event.Trustee.isModuleTrustee() || !brokerAllowACEForSID(event.ACE, event.Trustee, event.Object.Kind) {
			return errors.New("windows sandbox: invalid prepared lease mutation")
		}
	default:
		return errors.New("windows sandbox: invalid lease journal event kind")
	}
	return nil
}
