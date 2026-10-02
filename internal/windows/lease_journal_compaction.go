package windows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// maxBrokerLeaseJournalBytes bounds the broker's durable lease journal. Every
// event is one fsynced JSON line, and before compaction existed the file only
// ever grew: once it reached this cap every append failed, including the
// Released record that ends a lease, so every lease from then on became
// permanent (review M14).
const maxBrokerLeaseJournalBytes = 64 << 20

// brokerLeaseJournalCompactionThreshold is the size past which a successful
// release compacts the journal. Half the cap leaves the other half as
// headroom for the leases that are live when compaction runs, so a journal
// whose live set is small can never again creep up to the cap.
const brokerLeaseJournalCompactionThreshold = maxBrokerLeaseJournalBytes / 2

type brokerLeaseEventKind uint8

const (
	brokerLeaseEventInvalid brokerLeaseEventKind = iota
	brokerLeaseEventReserved
	brokerLeaseEventMutationPrepared
	brokerLeaseEventActive
	brokerLeaseEventReleased
)

// brokerLeaseJournalLineKey is the only part of an event compaction reads: the
// lease it belongs to and whether it releases that lease. Everything else is
// carried through byte for byte, so compaction can never re-encode (and so
// never reinterpret) a record recovery will later validate.
type brokerLeaseJournalLineKey struct {
	Kind    brokerLeaseEventKind `json:"kind"`
	LeaseID ACLLeaseID           `json:"lease_id"`
}

// compactBrokerLeaseJournal returns data with every line that belongs to a
// released lease removed: for each lease identity, every line up to and
// including its LAST Released record goes, and every line after it (a later
// lease that happened to draw the same identity) stays. Kept lines keep their
// exact bytes and relative order, so recovering the compacted journal yields
// exactly the leases recovering the original would: recovery deletes a lease
// on Released and builds one only from the records after it.
//
// It refuses rather than guesses: a line that does not decode or names no
// valid lease or kind, or a final line with no terminating newline (a torn
// append the store should already have truncated), is an error, and the
// caller keeps the uncompacted journal, which recovery then fails closed on
// exactly as it would have anyway. It does not re-run recovery's full
// semantic validation on the records it drops: those belong to leases whose
// Released record is already durable, so nothing they describe is owed.
func compactBrokerLeaseJournal(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("windows sandbox: lease journal ends in a torn record")
	}
	lines := bytes.SplitAfter(data, []byte{'\n'})
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	keys := make([]brokerLeaseJournalLineKey, len(lines))
	lastReleased := make(map[ACLLeaseID]int)
	for index, line := range lines {
		if len(line) == 1 {
			// An empty line ("\n" alone) is skipped by recovery too.
			continue
		}
		if err := json.Unmarshal(line, &keys[index]); err != nil {
			return nil, fmt.Errorf("decode broker lease journal event %d for compaction: %w", index, err)
		}
		if keys[index].LeaseID == (ACLLeaseID{}) || keys[index].Kind == brokerLeaseEventInvalid || keys[index].Kind > brokerLeaseEventReleased {
			// Recovery would refuse this record; compaction must not be the
			// step that quietly drops it and turns a corrupt journal valid.
			return nil, fmt.Errorf("windows sandbox: lease journal event %d has no valid lease identity or kind", index)
		}
		if keys[index].Kind == brokerLeaseEventReleased {
			lastReleased[keys[index].LeaseID] = index
		}
	}
	compacted := make([]byte, 0, len(data))
	for index, line := range lines {
		if len(line) == 1 {
			// Empty lines carry nothing recovery reads; dropping them is the
			// only rewrite compaction performs on a kept region.
			continue
		}
		if released, ok := lastReleased[keys[index].LeaseID]; ok && index <= released {
			continue
		}
		compacted = append(compacted, line...)
	}
	return compacted, nil
}

// brokerLeaseJournalNeedsCompaction is the post-release trigger.
func brokerLeaseJournalNeedsCompaction(size int) bool {
	return size >= brokerLeaseJournalCompactionThreshold
}
