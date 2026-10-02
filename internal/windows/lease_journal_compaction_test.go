package windows

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func compactionTestLine(t *testing.T, kind brokerLeaseEventKind, lease byte, extra string) string {
	t.Helper()
	var id ACLLeaseID
	id[0] = lease
	encoded, err := json.Marshal(struct {
		Version uint8                `json:"version"`
		Kind    brokerLeaseEventKind `json:"kind"`
		LeaseID ACLLeaseID           `json:"lease_id"`
		Extra   string               `json:"extra"`
	}{1, kind, id, extra})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded) + "\n"
}

// TestCompactBrokerLeaseJournalKeepsOnlyUnreleasedLeasesByteForByte pins M14's
// compaction rule: every line of a released lease goes, every line of an
// unreleased one stays with its exact bytes and relative order (interleaving
// included), and a later lease that reused a released identity keeps the
// records after that Released.
func TestCompactBrokerLeaseJournalKeepsOnlyUnreleasedLeasesByteForByte(t *testing.T) {
	lines := []string{
		compactionTestLine(t, brokerLeaseEventReserved, 1, "a-reserve"),
		compactionTestLine(t, brokerLeaseEventReserved, 2, "b-reserve"),
		compactionTestLine(t, brokerLeaseEventMutationPrepared, 1, "a-mutation"),
		compactionTestLine(t, brokerLeaseEventMutationPrepared, 2, "b-mutation"),
		compactionTestLine(t, brokerLeaseEventActive, 1, "a-active"),
		compactionTestLine(t, brokerLeaseEventReleased, 1, "a-released"),
		"\n",
		compactionTestLine(t, brokerLeaseEventActive, 2, "b-active"),
		compactionTestLine(t, brokerLeaseEventReserved, 3, "c-reserve"),
		compactionTestLine(t, brokerLeaseEventReleased, 3, "c-released"),
		compactionTestLine(t, brokerLeaseEventReserved, 1, "a2-reserve"),
	}
	compacted, err := compactBrokerLeaseJournal([]byte(strings.Join(lines, "")))
	if err != nil {
		t.Fatal(err)
	}
	want := lines[1] + lines[3] + lines[7] + lines[10]
	if string(compacted) != want {
		t.Fatalf("compacted =\n%s\nwant\n%s", compacted, want)
	}
}

func TestCompactBrokerLeaseJournalIsANoOpWithoutReleases(t *testing.T) {
	data := []byte(compactionTestLine(t, brokerLeaseEventReserved, 4, "x") + compactionTestLine(t, brokerLeaseEventActive, 4, "y"))
	compacted, err := compactBrokerLeaseJournal(data)
	if err != nil || !bytes.Equal(compacted, data) {
		t.Fatalf("compacted = %q err %v, want unchanged", compacted, err)
	}
	if compacted, err := compactBrokerLeaseJournal(nil); err != nil || len(compacted) != 0 {
		t.Fatalf("empty journal = %q err %v", compacted, err)
	}
	everything := []byte(compactionTestLine(t, brokerLeaseEventReserved, 5, "x") + compactionTestLine(t, brokerLeaseEventReleased, 5, "y"))
	if compacted, err := compactBrokerLeaseJournal(everything); err != nil || len(compacted) != 0 {
		t.Fatalf("fully released journal = %q err %v, want empty", compacted, err)
	}
}

// TestCompactBrokerLeaseJournalRefusesWhatRecoveryWouldRefuse proves
// compaction never turns an unreadable journal into a readable one.
func TestCompactBrokerLeaseJournalRefusesWhatRecoveryWouldRefuse(t *testing.T) {
	valid := compactionTestLine(t, brokerLeaseEventReleased, 6, "z")
	for name, data := range map[string]string{
		"torn tail":     valid + `{"kind":1`,
		"not json":      "garbage\n" + valid,
		"no lease":      `{"version":1,"kind":4}` + "\n",
		"invalid kind":  strings.Replace(valid, `"kind":4`, `"kind":0`, 1),
		"unknown kind":  strings.Replace(valid, `"kind":4`, `"kind":9`, 1),
		"blank padding": "   \n" + valid,
	} {
		if _, err := compactBrokerLeaseJournal([]byte(data)); err == nil {
			t.Errorf("%s: compaction accepted a journal recovery refuses", name)
		}
	}
}

func TestBrokerLeaseJournalCompactionThresholdIsHalfTheCap(t *testing.T) {
	if brokerLeaseJournalNeedsCompaction(maxBrokerLeaseJournalBytes/2-1) || !brokerLeaseJournalNeedsCompaction(maxBrokerLeaseJournalBytes/2) {
		t.Fatal("compaction threshold is not half the journal cap")
	}
}
