package windows

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func restrictedTestSID(label string) SID {
	return deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, label)
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

func closeRestrictedTestJournal(t *testing.T, journal *RestrictedJournal) {
	t.Helper()
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close restricted journal: %v", err)
		}
	})
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

type reentrantCleaner struct {
	journal *RestrictedJournal
	entered chan struct{}
	proceed chan struct{}
	err     error
}

func (cleaner *reentrantCleaner) RemoveRestrictedAllowACE(RestrictedCleanupRecord) (bool, error) {
	close(cleaner.entered)
	<-cleaner.proceed
	_, cleaner.err = cleaner.journal.RetireSID(restrictedTestSID("cleaner-reentry"))
	return false, nil
}

func TestRestrictedJournalPersistsBeforeMutationAndRemovesAfterCleanup(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
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

func TestOpenRestrictedJournalRejectsPreexistingSymlinkDirectory(t *testing.T) {
	stable := t.TempDir()
	root := filepath.Join(stable, restrictedJournalDirectory)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "records")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := OpenRestrictedJournal(stable); err == nil {
		t.Fatal("preexisting symlink records directory was accepted")
	}
}

func TestOpenRestrictedJournalRejectsPreexistingJournalRootSymlink(t *testing.T) {
	stable := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(stable, restrictedJournalDirectory)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if journal, err := OpenRestrictedJournal(stable); err == nil {
		_ = journal.Close()
		t.Fatal("preexisting symlink journal root was accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("journal initialization escaped anchored scratch root: %v", entries)
	}
}

func TestRestrictedJournalCreationSyncsParentDirectoriesInOrder(t *testing.T) {
	stable := t.TempDir()
	var synced []string
	journal, err := openRestrictedJournalWithSync(stable, func(root *os.Root) error {
		synced = append(synced, root.Name())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	want := []string{stable, journal.root, journal.root}
	if len(synced) != len(want) {
		t.Fatalf("directory sync calls = %v, want %v", synced, want)
	}
	for index := range want {
		if filepath.Clean(synced[index]) != filepath.Clean(want[index]) {
			t.Fatalf("directory sync calls = %v, want %v", synced, want)
		}
	}
}

type recordingBatchDirectory struct {
	calls     []int
	remaining int
}

func (directory *recordingBatchDirectory) ReadDir(size int) ([]fs.DirEntry, error) {
	directory.calls = append(directory.calls, size)
	if directory.remaining == 0 {
		return nil, io.EOF
	}
	count := min(size, directory.remaining)
	directory.remaining -= count
	return make([]fs.DirEntry, count), nil
}

func TestRestrictedJournalEnumerationUsesBoundedBatchesUntilEOF(t *testing.T) {
	directory := &recordingBatchDirectory{remaining: restrictedJournalReadBatchSize*3 + 7}
	visited := 0
	if err := forEachRestrictedJournalEntry(directory, func(fs.DirEntry) error {
		visited++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if visited != restrictedJournalReadBatchSize*3+7 {
		t.Fatalf("visited entries = %d, want all entries", visited)
	}
	if len(directory.calls) < 5 {
		t.Fatalf("ReadDir calls = %v, want repeated batches through EOF", directory.calls)
	}
	for _, size := range directory.calls {
		if size != restrictedJournalReadBatchSize || size <= 0 {
			t.Fatalf("ReadDir batch size = %d, want fixed positive %d", size, restrictedJournalReadBatchSize)
		}
	}
}

func TestRestrictedJournalCreationStopsWhenParentSyncFails(t *testing.T) {
	stable := t.TempDir()
	fault := errors.New("injected directory sync failure")
	calls := 0
	journal, err := openRestrictedJournalWithSync(stable, func(*os.Root) error {
		calls++
		return fault
	})
	if journal != nil {
		_ = journal.Close()
		t.Fatal("journal returned after creation durability failure")
	}
	if !errors.Is(err, fault) {
		t.Fatalf("creation error = %v, want injected sync failure", err)
	}
	if calls != 1 {
		t.Fatalf("directory sync calls = %d, want stop after first failure", calls)
	}
	if _, err := os.Stat(filepath.Join(stable, restrictedJournalDirectory, "records")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal children created after parent sync failure: %v", err)
	}
}

func TestRestrictedJournalCreationPropagatesStateDirectorySyncFailure(t *testing.T) {
	for _, failAt := range []int{2, 3} {
		t.Run(fmt.Sprintf("sync-call-%d", failAt), func(t *testing.T) {
			stable := t.TempDir()
			fault := errors.New("injected state directory sync failure")
			calls := 0
			journal, err := openRestrictedJournalWithSync(stable, func(*os.Root) error {
				calls++
				if calls == failAt {
					return fault
				}
				return nil
			})
			if journal != nil {
				_ = journal.Close()
				t.Fatal("journal returned after state directory durability failure")
			}
			if !errors.Is(err, fault) {
				t.Fatalf("creation error = %v, want injected sync failure", err)
			}
			if calls != failAt {
				t.Fatalf("directory sync calls = %d, want stop at %d", calls, failAt)
			}
		})
	}
}

func TestRestrictedJournalCleanerReentryDoesNotDeadlockConcurrentClose(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record := restrictedTestRecord(t, "cleaner-reentry-record")
	prepareRestrictedTestMutation(t, journal, record)
	cleaner := &reentrantCleaner{
		journal: journal,
		entered: make(chan struct{}),
		proceed: make(chan struct{}),
	}
	sweepDone := make(chan error, 1)
	go func() {
		_, err := journal.Sweep(cleaner)
		sweepDone <- err
	}()
	<-cleaner.entered

	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- journal.Close()
	}()
	<-closeStarted
	time.Sleep(25 * time.Millisecond)
	close(cleaner.proceed)

	select {
	case err := <-sweepDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Cleaner reentry deadlocked with concurrent Close")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not finish after Cleaner returned")
	}
}

func TestRestrictedJournalCloseIsIdempotentAndRejectsFurtherUse(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := journal.RetireSID(restrictedTestSID("after-close")); err == nil {
		t.Fatal("closed journal accepted a retirement")
	}
	if _, err := journal.PrepareMutation(restrictedTestRecord(t, "after-close")); err == nil {
		t.Fatal("closed journal accepted a mutation")
	}
	if err := journal.CompleteCleanup(strings.Repeat("0", sha256.Size*2)); err == nil {
		t.Fatal("closed journal accepted cleanup completion")
	}
	if _, err := journal.Sweep(&recordingCleaner{}); err == nil {
		t.Fatal("closed journal accepted a sweep")
	}
	if err := journal.Prune(&testPruner{}); err == nil {
		t.Fatal("closed journal accepted pruning")
	}
}

func TestBrokerJournalOwnershipJoinsCloseFailure(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	operationFault := errors.New("broker operation failure")
	closeFault := errors.New("injected broker journal close failure")
	originalClose := journal.closeRoots
	closeCalls := 0
	journal.closeRoots = func(records, retired *os.Root) error {
		closeCalls++
		return errors.Join(originalClose(records, retired), closeFault)
	}
	result := error(operationFault)
	joinRestrictedJournalClose(&result, journal)
	if !errors.Is(result, operationFault) || !errors.Is(result, closeFault) {
		t.Fatalf("joined broker result = %v, want operation and close failures", result)
	}
	if closeCalls != 1 {
		t.Fatalf("journal close calls = %d, want 1", closeCalls)
	}
	if err := journal.Close(); !errors.Is(err, closeFault) {
		t.Fatalf("idempotent Close = %v, want preserved close failure", err)
	}
	if closeCalls != 1 {
		t.Fatalf("idempotent journal close calls = %d, want 1", closeCalls)
	}
}

func TestRestrictedJournalConstructionSweep(t *testing.T) {
	root := t.TempDir()
	first, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, first)
	want := restrictedTestRecord(t, "sweep")
	prepareRestrictedTestMutation(t, first, want)

	cleaner := &recordingCleaner{removed: true}
	reopened, report, err := OpenRestrictedJournalAndSweep(root, cleaner)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, reopened)
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
	closeRestrictedTestJournal(t, journal)
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

func TestRestrictedJournalRetainsOversizedRecordWithoutReadingItAsAuthority(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	record := restrictedTestRecord(t, "oversized")
	if retired, err := journal.RetireSID(record.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	data, err := encodeRestrictedRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, strings.Repeat(" ", 1<<20)...)
	path := filepath.Join(journal.recordsDir, "oversized.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if report.Corrupt != 1 || report.Retained != 1 || cleaner.called != 0 {
		t.Fatalf("oversized record used as authority: report=%+v calls=%d", report, cleaner.called)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("oversized corrupt record was not retained: %v", err)
	}
}

func TestRestrictedJournalDoesNotFollowSymlinkRecord(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	record := restrictedTestRecord(t, "symlink")
	if retired, err := journal.RetireSID(record.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	data, err := encodeRestrictedRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(journal.recordsDir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if report.Corrupt != 1 || report.Retained != 1 || cleaner.called != 0 {
		t.Fatalf("symlink record used as authority: report=%+v calls=%d", report, cleaner.called)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink record was not retained: %v", err)
	}
}

func TestRestrictedJournalDirectoryReplacementCannotRedirectOperations(t *testing.T) {
	root := t.TempDir()
	journal, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	first := restrictedTestRecord(t, "before-replacement")
	firstKey := prepareRestrictedTestMutation(t, journal, first)

	originalRecords := journal.recordsDir + "-original"
	if err := os.Rename(journal.recordsDir, originalRecords); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal.recordsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	redirected := restrictedTestRecord(t, "redirected")
	if retired, err := journal.RetireSID(redirected.Rollback.SID); err != nil || !retired {
		t.Fatalf("retire redirected SID = (%v, %v)", retired, err)
	}
	redirectedData, err := encodeRestrictedRecord(redirected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal.recordsDir, "redirected.json"), redirectedData, 0o600); err != nil {
		t.Fatal(err)
	}

	second := restrictedTestRecord(t, "after-replacement")
	secondKey := prepareRestrictedTestMutation(t, journal, second)
	if _, err := os.Stat(filepath.Join(originalRecords, secondKey+".json")); err != nil {
		t.Fatalf("create did not stay in originally opened directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(journal.recordsDir, secondKey+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("create was redirected into replacement directory: %v", err)
	}

	cleaner := &recordingCleaner{removed: true}
	report, err := journal.Sweep(cleaner)
	if err != nil {
		t.Fatal(err)
	}
	if cleaner.called != 2 || report.Removed != 2 || report.Retained != 0 {
		t.Fatalf("sweep escaped originally opened directory: calls=%d report=%+v", cleaner.called, report)
	}
	for _, key := range []string{firstKey, secondKey} {
		if _, err := os.Stat(filepath.Join(originalRecords, key+".json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("original record %q remains after sweep: %v", key, err)
		}
	}
	if _, err := os.Stat(filepath.Join(journal.recordsDir, "redirected.json")); err != nil {
		t.Fatalf("sweep modified replacement directory: %v", err)
	}
}

func TestRestrictedJournalRootReplacementCannotRedirectOperations(t *testing.T) {
	stable := t.TempDir()
	journal, err := OpenRestrictedJournal(stable)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)

	originalRoot := journal.root + "-original"
	if err := os.Rename(journal.root, originalRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal.root, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideRecords := filepath.Join(journal.root, "records")
	outsideRetired := filepath.Join(journal.root, "retired-sids")
	for _, directory := range []string{outsideRecords, outsideRetired} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	record := restrictedTestRecord(t, "journal-root-replacement")
	key := prepareRestrictedTestMutation(t, journal, record)
	if _, err := os.Stat(filepath.Join(originalRoot, "records", key+".json")); err != nil {
		t.Fatalf("record did not stay below originally opened journal root: %v", err)
	}
	if entries, err := os.ReadDir(outsideRecords); err != nil || len(entries) != 0 {
		t.Fatalf("record escaped into replacement journal root: entries=%v err=%v", entries, err)
	}
	if entries, err := os.ReadDir(outsideRetired); err != nil || len(entries) != 0 {
		t.Fatalf("retirement escaped into replacement journal root: entries=%v err=%v", entries, err)
	}
	if err := journal.CompleteCleanup(key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(originalRoot, "records", key+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup did not remove record from original root: %v", err)
	}
}

func TestRestrictedJournalRetirementDirectoryReplacementCannotRedirectState(t *testing.T) {
	root := t.TempDir()
	journal, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	before := restrictedTestSID("retired-before-replacement")
	if retired, err := journal.RetireSID(before); err != nil || !retired {
		t.Fatalf("retire before replacement = (%v, %v)", retired, err)
	}

	originalRetired := journal.retiredDir + "-original"
	if err := os.Rename(journal.retiredDir, originalRetired); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal.retiredDir, 0o700); err != nil {
		t.Fatal(err)
	}
	forged := restrictedTestSID("forged-replacement-retirement")
	forgedDigest := sha256.Sum256([]byte(forged.String()))
	forgedName := hexString(forgedDigest[:]) + ".sid"
	if err := os.WriteFile(filepath.Join(journal.retiredDir, forgedName), []byte(forged.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if journal.isDurablyRetired(forged) {
		t.Fatal("replacement retirement directory became retirement authority")
	}
	if !journal.isDurablyRetired(before) {
		t.Fatal("originally opened retirement state was lost after directory replacement")
	}

	after := restrictedTestSID("retired-after-replacement")
	if retired, err := journal.RetireSID(after); err != nil || !retired {
		t.Fatalf("retire after replacement = (%v, %v)", retired, err)
	}
	afterDigest := sha256.Sum256([]byte(after.String()))
	afterName := hexString(afterDigest[:]) + ".sid"
	if _, err := os.Stat(filepath.Join(originalRetired, afterName)); err != nil {
		t.Fatalf("retirement did not stay in originally opened directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(journal.retiredDir, afterName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retirement was redirected into replacement directory: %v", err)
	}
}

func TestRestrictedJournalRefusesIdentityMismatch(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
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
	closeRestrictedTestJournal(t, first)
	second, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, second)
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
	closeRestrictedTestJournal(t, reopened)
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
	closeRestrictedTestJournal(t, first)
	if retired, err := first.RetireSID(sid); err != nil || !retired {
		t.Fatalf("first executor retirement = (%v, %v), want (true, nil)", retired, err)
	}
	reopened, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, reopened)
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
	allow func(SID, ACERole, []byte) bool
}

func (pruner *testPruner) PruneRestrictedACEs(allow func(SID, ACERole, []byte) bool) error {
	pruner.allow = allow
	return nil
}

type reentrantTestPruner struct {
	journal *RestrictedJournal
	sid     SID
	ace     []byte
}

func (pruner *reentrantTestPruner) PruneRestrictedACEs(allow func(SID, ACERole, []byte) bool) error {
	if _, err := pruner.journal.RetireSID(restrictedTestSID("pruner-reentry")); err != nil {
		return err
	}
	if !allow(pruner.sid, ACERoleRestrictingAllow, pruner.ace) {
		return errors.New("retired SID rejected after pruner reentry")
	}
	return nil
}

func TestRestrictedJournalPrunerMayReenterJournal(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
	sid := restrictedTestSID("pruner-authority")
	if retired, err := journal.RetireSID(sid); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	pruner := &reentrantTestPruner{
		journal: journal,
		sid:     sid,
		ace:     encodeACE(sid, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead}),
	}
	if err := journal.Prune(pruner); err != nil {
		t.Fatal(err)
	}
}

func TestRestrictedJournalRetainedPruneCallbackPinsOperationAcrossClose(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sid := restrictedTestSID("retained-callback")
	if retired, err := journal.RetireSID(sid); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	pruner := &testPruner{}
	if err := journal.Prune(pruner); err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	releaseRead := make(chan struct{})
	originalRead := journal.readRegularFile
	journal.readRegularFile = func(root *os.Root, name string, maximum int64) ([]byte, error) {
		close(entered)
		<-releaseRead
		return originalRead(root, name, maximum)
	}
	ace := encodeACE(sid, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead})
	callbackDone := make(chan bool, 1)
	go func() {
		callbackDone <- pruner.allow(sid, ACERoleRestrictingAllow, ace)
	}()
	<-entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- journal.Close() }()
	waitForRestrictedJournalClosing(t, journal)
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while retained callback held an active read: %v", err)
	default:
	}
	close(releaseRead)
	if allowed := <-callbackDone; !allowed {
		t.Fatal("retained callback lost retirement authority while active")
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func waitForRestrictedJournalClosing(t *testing.T, journal *RestrictedJournal) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		journal.mu.Lock()
		closing := journal.closing
		journal.mu.Unlock()
		if closing {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("journal Close did not enter closing state")
		}
		runtime.Gosched()
	}
}

type blockingTestPruner struct {
	entered chan struct{}
	release chan struct{}
	sid     SID
	ace     []byte
	allowed bool
}

func (pruner *blockingTestPruner) PruneRestrictedACEs(allow func(SID, ACERole, []byte) bool) error {
	close(pruner.entered)
	<-pruner.release
	pruner.allowed = allow(pruner.sid, ACERoleRestrictingAllow, pruner.ace)
	return nil
}

func TestRestrictedJournalCloseWaitsForPruneCallback(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sid := restrictedTestSID("blocking-prune")
	if retired, err := journal.RetireSID(sid); err != nil || !retired {
		t.Fatalf("retire = (%v, %v)", retired, err)
	}
	pruner := &blockingTestPruner{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		sid:     sid,
		ace:     encodeACE(sid, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead}),
	}
	defer func() {
		select {
		case <-pruner.release:
		default:
			close(pruner.release)
		}
	}()
	pruneDone := make(chan error, 1)
	go func() { pruneDone <- journal.Prune(pruner) }()
	<-pruner.entered

	closeDone := make(chan error, 1)
	closeStarted := make(chan struct{})
	go func() {
		close(closeStarted)
		closeDone <- journal.Close()
	}()
	<-closeStarted
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned while Prune callback remained active: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(pruner.release)
	if err := <-pruneDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestRestrictedJournalPrunesOnlyRecognizedInertACEs(t *testing.T) {
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	closeRestrictedTestJournal(t, journal)
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
	closeRestrictedTestJournal(t, journal)
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
	closeRestrictedTestJournal(t, journal)
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
	closeRestrictedTestJournal(t, journal)
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
	closeRestrictedTestJournal(t, journal)
	if _, err := journal.PrepareMutation(restrictedTestRecord(t, "not-retired")); err == nil {
		t.Fatal("mutation record accepted before durable SID retirement")
	}
}
