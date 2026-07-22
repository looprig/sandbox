package windows

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func restrictedTestSID(label string) SID {
	return deriveCapabilitySID(sidKindOneShot, oneShotSIDDomain, label)
}

func restrictedTestRecord(t *testing.T, label string) RestrictedCleanupRecord {
	t.Helper()
	sid := restrictedTestSID(label)
	ace := encodeACE(sid, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})
	var lease ACLLeaseID
	lease[0] = 1
	var fileID [16]byte
	fileID[0] = 2
	return RestrictedCleanupRecord{
		Path:     `C:\stable\target`,
		Object:   ACLObjectIdentity{VolumeSerial: 7, FileID: fileID, Kind: ACLObjectFile, LinkCount: 1},
		Rollback: ACLRollbackMetadata{LeaseID: lease, Role: ACERoleRestrictingAllow, SID: sid, ACEHash: sha256.Sum256(ace)},
		ACE:      ace,
	}
}

func prepareRestrictedTestMutation(t *testing.T, journal *RestrictedJournal, record RestrictedCleanupRecord) string {
	t.Helper()
	retired, err := journal.RetireSID(record.Rollback.SID)
	if err != nil || !retired {
		t.Fatalf("retire test SID = (%v, %v)", retired, err)
	}
	key, err := journal.PrepareMutation(record)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type recordingCleaner struct {
	called  int
	record  RestrictedCleanupRecord
	removed bool
	err     error
}

func (cleaner *recordingCleaner) RemoveRestrictedAllowACE(record RestrictedCleanupRecord) (bool, error) {
	cleaner.called++
	cleaner.record = record
	return cleaner.removed, cleaner.err
}

func TestRestrictedJournalPersistsBeforeMutationAndRemovesAfterCleanup(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := restrictedTestRecord(t, "ordered")
	key := prepareRestrictedTestMutation(t, journal, record)
	if _, err := os.Stat(filepath.Join(journal.recordsDir, key+".json")); err != nil {
		t.Fatalf("mutation became callable before durable record: %v", err)
	}
	if err := journal.CompleteCleanup(key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(journal.recordsDir, key+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record remains after confirmed cleanup: %v", err)
	}
}

func TestRestrictedJournalConstructionSweep(t *testing.T) {
	root := t.TempDir()
	first, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	want := restrictedTestRecord(t, "sweep")
	prepareRestrictedTestMutation(t, first, want)

	cleaner := &recordingCleaner{removed: true}
	reopened, report, err := OpenRestrictedJournalAndSweep(root, cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if reopened == nil {
		t.Fatal("construction sweep returned nil journal")
	}
	if report.Removed != 1 || report.Retained != 0 || cleaner.called != 1 {
		t.Fatalf("report = %+v, calls = %d", report, cleaner.called)
	}
	if cleaner.record.Path != want.Path || cleaner.record.Object != want.Object || string(cleaner.record.ACE) != string(want.ACE) {
		t.Fatalf("cleanup record = %+v, want exact persisted identity and ACE", cleaner.record)
	}
}

func TestRestrictedJournalToleratesCorruptAndDeletedRecords(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal.recordsDir, "corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	record := restrictedTestRecord(t, "deleted")
	key := prepareRestrictedTestMutation(t, journal, record)
	if err := os.Remove(filepath.Join(journal.recordsDir, key+".json")); err != nil {
		t.Fatal(err)
	}
	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if report.Corrupt != 1 || report.Retained != 1 || cleaner.called != 0 {
		t.Fatalf("report = %+v, calls = %d", report, cleaner.called)
	}
}

func TestRestrictedJournalRefusesIdentityMismatch(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prepareRestrictedTestMutation(t, journal, restrictedTestRecord(t, "mismatch"))
	cleaner := &recordingCleaner{err: ErrRestrictedTargetChanged}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.called != 1 || report.Retained != 1 || report.Removed != 0 {
		t.Fatalf("identity mismatch was not safely retained: report=%+v calls=%d", report, cleaner.called)
	}
	entries, err := os.ReadDir(journal.recordsDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("mismatched record not retained: entries=%d err=%v", len(entries), err)
	}
}

func TestRestrictedJournalRetiresSIDAtomicallyAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	sid := restrictedTestSID("never-reuse")
	stores := []*RestrictedJournal{first, second}
	results := make(chan bool, len(stores)*8)
	errorsSeen := make(chan error, len(stores)*8)
	var group sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		group.Add(1)
		go func(store *RestrictedJournal) {
			defer group.Done()
			retired, err := store.RetireSID(sid)
			results <- retired
			errorsSeen <- err
		}(stores[index%len(stores)])
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	winners := 0
	for retired := range results {
		if retired {
			winners++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("successful retirements = %d, want exactly 1", winners)
	}
	reopened, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := reopened.RetireSID(sid); err != nil || retired {
		t.Fatalf("reopened retirement = (%v, %v), want (false, nil)", retired, err)
	}
}

func TestRestrictedJournalRetiresExecutorSIDAcrossReopen(t *testing.T) {
	root := t.TempDir()
	sid, err := ExecutorSID("installation", "random-executor-identity")
	if err != nil {
		t.Fatal(err)
	}
	first, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := first.RetireSID(sid); err != nil || !retired {
		t.Fatalf("first executor retirement = (%v, %v), want (true, nil)", retired, err)
	}
	reopened, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := reopened.RetireSID(sid); err != nil || retired {
		t.Fatalf("reopened executor retirement = (%v, %v), want (false, nil)", retired, err)
	}
	installation, err := InstallationSID("installation")
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := reopened.RetireSID(installation); err == nil || retired {
		t.Fatalf("installation SID retirement = (%v, %v), want (false, error)", retired, err)
	}
}

type testPruner struct {
	wanted SID
	allow  func(SID, ACERole, []byte) bool
}

func (pruner *testPruner) PruneRestrictedACEs(allow func(SID, ACERole, []byte) bool) error {
	pruner.allow = allow
	return nil
}

func TestRestrictedJournalPrunesOnlyRecognizedInertACEs(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	retired := restrictedTestSID("retired")
	if ok, err := journal.RetireSID(retired); err != nil || !ok {
		t.Fatalf("retire = (%v, %v)", ok, err)
	}
	pruner := &testPruner{}
	if err := journal.Prune(pruner); err != nil {
		t.Fatal(err)
	}
	allowACE := encodeACE(retired, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})
	denyACE := encodeACE(retired, ACLObjectFile, ACLACE{Type: ACEDeny, Access: ACLRead})
	if !pruner.allow(retired, ACERoleRestrictingAllow, allowACE) {
		t.Fatal("recognized retired restricting allow rejected")
	}
	if pruner.allow(retired, ACERoleRestrictingDeny, denyACE) {
		t.Fatal("caller-writable retirement state authorized widening deny removal")
	}
	if pruner.allow(restrictedTestSID("unknown"), ACERoleRestrictingAllow, allowACE) {
		t.Fatal("unrecognized SID authorized for pruning")
	}
	if pruner.allow(retired, ACERoleAccountNormal, allowACE) || pruner.allow(retired, ACERoleRestrictingDeny, allowACE) || pruner.allow(retired, ACERoleRestrictingAllow, nil) {
		t.Fatal("non-inert ACE authorized for pruning")
	}
	installation, err := InstallationSID("installation")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := journal.RetireSID(installation); err == nil || ok {
		t.Fatal("reusable installation SID accepted by retirement store")
	}
}

func TestRestrictedJournalForgedDenyCannotAuthorizeWideningCleanup(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := restrictedTestRecord(t, "forged-deny")
	record.Rollback.Role = ACERoleRestrictingDeny
	record.ACE = encodeACE(record.Rollback.SID, ACLObjectFile, ACLACE{Type: ACEDeny, Access: ACLWrite})
	record.Rollback.ACEHash = sha256.Sum256(record.ACE)
	if retired, err := journal.RetireSID(record.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	// Simulate hostile construction of an otherwise perfectly valid record.
	data, err := encodeRestrictedRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if err := os.WriteFile(filepath.Join(journal.recordsDir, hexString(digest[:])+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.called != 0 || report.Removed != 0 || report.Retained != 1 {
		t.Fatalf("forged deny reached cleanup: calls=%d report=%+v", cleaner.called, report)
	}
}

func TestRestrictedJournalCrashSweepNeverRemovesLeaseDeny(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	allow := restrictedTestRecord(t, "mixed-lease")
	if retired, err := journal.RetireSID(allow.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	if _, err := journal.PrepareMutation(allow); err != nil {
		t.Fatal(err)
	}
	deny := allow
	deny.Rollback.Role = ACERoleRestrictingDeny
	deny.ACE = encodeACE(deny.Rollback.SID, ACLObjectFile, ACLACE{Type: ACEDeny, Access: ACLWrite})
	deny.Rollback.ACEHash = sha256.Sum256(deny.ACE)
	if _, err := journal.PrepareMutation(deny); err != nil {
		t.Fatal(err)
	}

	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.called != 1 || cleaner.record.Rollback.Role != ACERoleRestrictingAllow {
		t.Fatalf("cleanup calls=%d role=%v, want only narrowing allow removal", cleaner.called, cleaner.record.Rollback.Role)
	}
	if report.Removed != 1 || report.Retained != 1 {
		t.Fatalf("mixed lease report = %+v", report)
	}
}

func hexString(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&0xf]
	}
	return string(result)
}

func TestRestrictedJournalRejectsTamperedCleanupAuthority(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := restrictedTestRecord(t, "tampered")
	if retired, err := journal.RetireSID(record.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	record.ACE[0] ^= 0xff
	if _, err := journal.PrepareMutation(record); err == nil {
		t.Fatal("ACE whose exact hash does not match accepted")
	}
	record = restrictedTestRecord(t, "normal")
	if retired, err := journal.RetireSID(record.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	record.Rollback.Role = ACERoleAccountNormal
	if _, err := journal.PrepareMutation(record); err == nil {
		t.Fatal("account-normal ACE accepted by cleanup-only journal")
	}
}

func TestRestrictedJournalRequiresRetirementBeforeMutation(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.PrepareMutation(restrictedTestRecord(t, "not-retired")); err == nil {
		t.Fatal("mutation record accepted before durable SID retirement")
	}
}
