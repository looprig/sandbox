package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	restrictedJournalDirectory      = "restricted-journal-v1"
	restrictedJournalRecordMaxBytes = 64 << 10
	restrictedJournalSIDMaxBytes    = 1 << 10
	restrictedJournalReadBatchSize  = 128
)

var (
	errRestrictedJournalRecordTooLarge = errors.New("sandbox: restricted journal record is too large")
	errRestrictedJournalNonRegular     = errors.New("sandbox: restricted journal entry is not a regular file")
)

// ErrRestrictedTargetChanged means cleanup found a different filesystem object
// at the recorded path. The journal must never use a path alone as authority.
var ErrRestrictedTargetChanged = errors.New("sandbox: restricted cleanup target changed")

// RestrictedCleanupRecord is cleanup authority, never access authority. An ACL
// implementation may use it only to remove the exact lease-owned occurrence
// above BaselineOccurrences after revalidating Object on a retained handle.
type RestrictedCleanupRecord struct {
	Path                string
	Object              ACLObjectIdentity
	Rollback            ACLRollbackMetadata
	ACE                 []byte
	BaselineOccurrences uint32
}

// RestrictedJournalCleaner is the handle-bound half of crash recovery. Sweep
// deliberately supplies restricting allows only: removing one can only narrow
// access, even when every byte of the caller-writable journal was forged. Deny
// cleanup requires live, independently trusted lease state and is never
// authorized by this journal. The implementation must re-open without
// following links, compare the complete object identity, and remove only the
// recorded ACE occurrence. A false result retains the record. Cleaners may call
// other journal operations, but must not call Close from the callback.
type RestrictedJournalCleaner interface {
	RemoveRestrictedAllowACE(RestrictedCleanupRecord) (removed bool, err error)
}

// RestrictedPruner may opportunistically remove exact allow ACEs for retired SIDs
// while it performs an independently safe, handle-bound tree enumeration.
// Journal data is supplied only as removal authority. Pruners may call other
// journal operations, but must not call Close while PruneRestrictedACEs is
// active because Close deliberately waits for the callback to return.
type RestrictedPruner interface {
	PruneRestrictedACEs(func(SID, ACERole, []byte) bool) error
}

type RestrictedSweepReport struct {
	Removed  int
	Retained int
	Corrupt  int
}

// RestrictedJournal is rooted outside any executor-owned temporary subtree.
// Separate instances coordinate through create-exclusive files; no in-memory
// check-then-write is used for SID retirement.
type RestrictedJournal struct {
	root       string
	recordsDir string
	retiredDir string

	mu            sync.Mutex
	cond          *sync.Cond
	active        int
	closing       bool
	closed        bool
	closeErr      error
	recordsRoot   *os.Root
	retiredRoot   *os.Root
	syncDirectory func(*os.Root) error
}

// OpenRestrictedJournal creates the durable store below stableScratchRoot.
// Construction is deliberately separate from Sweep so callers control the
// handle-bound cleanup implementation and can report retained cleanup loss.
func OpenRestrictedJournal(stableScratchRoot string) (*RestrictedJournal, error) {
	return openRestrictedJournalWithSync(stableScratchRoot, syncRestrictedJournalDirectory)
}

func openRestrictedJournalWithSync(stableScratchRoot string, syncDirectory func(*os.Root) error) (*RestrictedJournal, error) {
	if stableScratchRoot == "" {
		return nil, errors.New("sandbox: stable scratch root is required")
	}
	if syncDirectory == nil {
		return nil, errors.New("sandbox: restricted journal directory sync is required")
	}
	abs, err := filepath.Abs(stableScratchRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve restricted journal root: %w", err)
	}
	root := filepath.Join(abs, restrictedJournalDirectory)
	j := &RestrictedJournal{
		root:          root,
		recordsDir:    filepath.Join(root, "records"),
		retiredDir:    filepath.Join(root, "retired-sids"),
		syncDirectory: syncDirectory,
	}
	j.cond = sync.NewCond(&j.mu)
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create stable scratch root: %w", err)
	}
	scratch, err := os.OpenRoot(abs)
	if err != nil {
		return nil, fmt.Errorf("open stable scratch root: %w", err)
	}
	defer scratch.Close()
	if err := scratch.Mkdir(restrictedJournalDirectory, 0o700); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("create restricted journal: %w", err)
		}
	}
	if err := syncDirectory(scratch); err != nil {
		return nil, fmt.Errorf("sync stable scratch root after restricted journal creation: %w", err)
	}
	outer, err := openRestrictedJournalSubroot(scratch, restrictedJournalDirectory)
	if err != nil {
		return nil, fmt.Errorf("open restricted journal root: %w", err)
	}
	defer outer.Close()
	for _, directory := range []string{"records", "retired-sids"} {
		if err := outer.Mkdir(directory, 0o700); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return nil, fmt.Errorf("create restricted journal: %w", err)
			}
		}
		if err := syncDirectory(outer); err != nil {
			return nil, fmt.Errorf("sync restricted journal root after state directory creation: %w", err)
		}
	}
	j.recordsRoot, err = openRestrictedJournalSubroot(outer, "records")
	if err != nil {
		return nil, fmt.Errorf("open restricted journal records: %w", err)
	}
	j.retiredRoot, err = openRestrictedJournalSubroot(outer, "retired-sids")
	if err != nil {
		_ = j.recordsRoot.Close()
		return nil, fmt.Errorf("open restricted journal retirements: %w", err)
	}
	return j, nil
}

// OpenRestrictedJournalAndSweep is the construction path used by the backend:
// recovery runs before a fresh restricted SID or ACL lease is created.
func OpenRestrictedJournalAndSweep(stableScratchRoot string, cleaner RestrictedJournalCleaner) (*RestrictedJournal, RestrictedSweepReport, error) {
	j, err := OpenRestrictedJournal(stableScratchRoot)
	if err != nil {
		return nil, RestrictedSweepReport{}, err
	}
	report, err := j.Sweep(cleaner)
	if err != nil {
		closeErr := j.Close()
		return nil, report, errors.Join(err, closeErr)
	}
	return j, report, nil
}

// Close releases the retained directory handles. It is safe to call more than
// once and waits for in-flight journal operations to finish.
func (j *RestrictedJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	j.ensureCondLocked()
	if j.closed {
		err := j.closeErr
		j.mu.Unlock()
		return err
	}
	if j.closing {
		for !j.closed {
			j.cond.Wait()
		}
		err := j.closeErr
		j.mu.Unlock()
		return err
	}
	j.closing = true
	for j.active != 0 {
		j.cond.Wait()
	}
	recordsRoot, retiredRoot := j.recordsRoot, j.retiredRoot
	j.recordsRoot, j.retiredRoot = nil, nil
	j.mu.Unlock()

	var result error
	if recordsRoot != nil {
		result = errors.Join(result, recordsRoot.Close())
	}
	if retiredRoot != nil {
		result = errors.Join(result, retiredRoot.Close())
	}

	j.mu.Lock()
	j.closeErr = result
	j.closed = true
	j.cond.Broadcast()
	j.mu.Unlock()
	return result
}

func (j *RestrictedJournal) ensureCondLocked() {
	if j.cond == nil {
		j.cond = sync.NewCond(&j.mu)
	}
}

func (j *RestrictedJournal) beginOperation() error {
	if j == nil {
		return errors.New("sandbox: nil restricted journal")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.ensureCondLocked()
	if j.closing || j.closed {
		return errors.New("sandbox: restricted journal is closed")
	}
	j.active++
	return nil
}

func (j *RestrictedJournal) endOperation() {
	j.mu.Lock()
	j.active--
	if j.active == 0 {
		j.cond.Broadcast()
	}
	j.mu.Unlock()
}

// PrepareMutation durably records cleanup before a caller changes a DACL. The
// returned opaque key is passed to CompleteCleanup only after read-back proves
// the recorded ACE absent.
func (j *RestrictedJournal) PrepareMutation(record RestrictedCleanupRecord) (string, error) {
	if err := j.beginOperation(); err != nil {
		return "", err
	}
	defer j.endOperation()
	encoded, err := encodeRestrictedRecord(record)
	if err != nil {
		return "", err
	}
	if !j.isDurablyRetiredLocked(record.Rollback.SID) {
		return "", errors.New("sandbox: cleanup SID was not durably retired before mutation")
	}
	digest := sha256.Sum256(encoded)
	key := hex.EncodeToString(digest[:])
	if err := createExclusiveDurable(j.recordsRoot, key+".json", encoded, j.syncDirectory); err != nil {
		return "", fmt.Errorf("prepare restricted ACL mutation: %w", err)
	}
	return key, nil
}

// CompleteCleanup removes a cleanup record only after its exact ACE is known
// absent. A missing record is tolerated because the untrusted child may delete
// journal data; the corresponding SID remains permanently retired.
func (j *RestrictedJournal) CompleteCleanup(key string) error {
	if j == nil || !validJournalKey(key) {
		return errors.New("sandbox: invalid restricted journal record key")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	err := j.recordsRoot.Remove(key + ".json")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove restricted journal record: %w", err)
	}
	if err == nil {
		if err := j.syncDirectory(j.recordsRoot); err != nil {
			return fmt.Errorf("sync restricted journal records: %w", err)
		}
	}
	return nil
}

// Sweep attempts cleanup for every valid record. Corrupt or concurrently
// deleted records are tolerated as cleanup loss. A target mismatch or a false
// cleaner result retains the record and cannot authorize any access.
func (j *RestrictedJournal) Sweep(cleaner RestrictedJournalCleaner) (RestrictedSweepReport, error) {
	var report RestrictedSweepReport
	if j == nil || cleaner == nil {
		return report, errors.New("sandbox: restricted journal cleaner is required")
	}
	if err := j.beginOperation(); err != nil {
		return report, err
	}
	defer j.endOperation()
	directory, err := j.recordsRoot.Open(".")
	if err != nil {
		return report, fmt.Errorf("read restricted journal: %w", err)
	}
	err = forEachRestrictedJournalEntry(directory, func(entry fs.DirEntry) error {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			return nil
		}
		data, readErr := readRestrictedJournalRegularFile(j.recordsRoot, entry.Name(), restrictedJournalRecordMaxBytes)
		if errors.Is(readErr, fs.ErrNotExist) {
			return nil
		}
		if readErr != nil {
			report.Retained++
			if errors.Is(readErr, errRestrictedJournalRecordTooLarge) || errors.Is(readErr, errRestrictedJournalNonRegular) {
				report.Corrupt++
			}
			return nil
		}
		record, decodeErr := decodeRestrictedRecord(data)
		if decodeErr != nil {
			report.Corrupt++
			report.Retained++
			return nil
		}
		if !j.isDurablyRetiredLocked(record.Rollback.SID) {
			report.Corrupt++
			report.Retained++
			return nil
		}
		// The journal is writable by the sandboxed interactive user. Its SID,
		// role, lease, retirement marker, and exact bytes are therefore not
		// authority to remove a deny ACE, which could widen access. Normal
		// rollback can remove denies from its trusted in-memory lease after all
		// matching allows are absent; crash recovery safely leaves them inert.
		if record.Rollback.Role != ACERoleRestrictingAllow {
			report.Retained++
			return nil
		}
		removed, cleanupErr := cleaner.RemoveRestrictedAllowACE(record)
		if cleanupErr != nil {
			report.Retained++
			if errors.Is(cleanupErr, ErrRestrictedTargetChanged) {
				return nil
			}
			return cleanupErr
		}
		if !removed {
			report.Retained++
			return nil
		}
		if removeErr := j.recordsRoot.Remove(entry.Name()); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return fmt.Errorf("remove swept restricted journal record: %w", removeErr)
		}
		if err := j.syncDirectory(j.recordsRoot); err != nil {
			return fmt.Errorf("sync swept restricted journal records: %w", err)
		}
		report.Removed++
		return nil
	})
	closeErr := directory.Close()
	if err != nil {
		return report, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return report, fmt.Errorf("close restricted journal directory: %w", closeErr)
	}
	return report, nil
}

// RetireSID atomically and durably records a transient executor or one-shot SID
// before issuance. Installation SIDs are persistent names and are never valid
// restricted-tier cleanup capabilities.
func (j *RestrictedJournal) RetireSID(sid SID) (bool, error) {
	if err := j.beginOperation(); err != nil {
		return false, err
	}
	defer j.endOperation()
	if !retirableRestrictedSID(sid) {
		return false, errors.New("sandbox: only module-issued transient restricted SIDs may be retired")
	}
	digest := sha256.Sum256([]byte(sid.String()))
	name := hex.EncodeToString(digest[:]) + ".sid"
	err := createExclusiveDurable(j.retiredRoot, name, []byte(sid.String()+"\n"), j.syncDirectory)
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("persist retired SID: %w", err)
	}
	return true, nil
}

// Prune asks a safe enumerator to remove only exact restricting allows for SIDs
// durably retired by this store. Denies are intentionally excluded because the
// caller-writable retirement store cannot prove that removing one is harmless.
func (j *RestrictedJournal) Prune(pruner RestrictedPruner) error {
	if j == nil || pruner == nil {
		return errors.New("sandbox: restricted journal pruner is required")
	}
	if err := j.beginOperation(); err != nil {
		return err
	}
	defer j.endOperation()
	var callbackActive atomic.Bool
	callbackActive.Store(true)
	defer callbackActive.Store(false)
	return pruner.PruneRestrictedACEs(func(sid SID, role ACERole, ace []byte) bool {
		if role != ACERoleRestrictingAllow || !retirableRestrictedSID(sid) || !recognizedRestrictingACE(sid, role, ace) {
			return false
		}
		if callbackActive.Load() {
			return j.isDurablyRetiredLocked(sid)
		}
		return j.isDurablyRetired(sid)
	})
}

func (j *RestrictedJournal) isDurablyRetired(sid SID) bool {
	if j == nil || !retirableRestrictedSID(sid) {
		return false
	}
	if err := j.beginOperation(); err != nil {
		return false
	}
	defer j.endOperation()
	return j.isDurablyRetiredLocked(sid)
}

func (j *RestrictedJournal) isDurablyRetiredLocked(sid SID) bool {
	if !retirableRestrictedSID(sid) {
		return false
	}
	digest := sha256.Sum256([]byte(sid.String()))
	data, err := readRestrictedJournalRegularFile(j.retiredRoot, hex.EncodeToString(digest[:])+".sid", restrictedJournalSIDMaxBytes)
	return err == nil && string(data) == sid.String()+"\n"
}

type restrictedRecordV1 struct {
	Version             int               `json:"version"`
	Path                string            `json:"path"`
	Object              ACLObjectIdentity `json:"object"`
	LeaseID             ACLLeaseID        `json:"lease_id"`
	Role                ACERole           `json:"role"`
	SID                 string            `json:"sid"`
	SIDKind             sidKind           `json:"sid_kind"`
	ACE                 []byte            `json:"ace"`
	ACEHash             [sha256.Size]byte `json:"ace_hash"`
	BaselineOccurrences uint32            `json:"baseline_occurrences"`
}

func encodeRestrictedRecord(record RestrictedCleanupRecord) ([]byte, error) {
	if err := validateRestrictedRecord(record); err != nil {
		return nil, err
	}
	persisted := restrictedRecordV1{
		Version: 1, Path: record.Path, Object: record.Object,
		LeaseID: record.Rollback.LeaseID, Role: record.Rollback.Role,
		SID: record.Rollback.SID.String(), SIDKind: record.Rollback.SID.kind,
		ACE: append([]byte(nil), record.ACE...), ACEHash: record.Rollback.ACEHash,
		BaselineOccurrences: record.BaselineOccurrences,
	}
	return json.Marshal(persisted)
}

func decodeRestrictedRecord(data []byte) (RestrictedCleanupRecord, error) {
	var persisted restrictedRecordV1
	if err := json.Unmarshal(data, &persisted); err != nil || persisted.Version != 1 {
		return RestrictedCleanupRecord{}, errors.New("sandbox: corrupt restricted journal record")
	}
	record := RestrictedCleanupRecord{
		Path: persisted.Path, Object: persisted.Object,
		Rollback: ACLRollbackMetadata{LeaseID: persisted.LeaseID, Role: persisted.Role,
			SID: SID{text: persisted.SID, kind: persisted.SIDKind}, ACEHash: persisted.ACEHash},
		ACE: append([]byte(nil), persisted.ACE...), BaselineOccurrences: persisted.BaselineOccurrences,
	}
	if err := validateRestrictedRecord(record); err != nil {
		return RestrictedCleanupRecord{}, err
	}
	return record, nil
}

func validateRestrictedRecord(record RestrictedCleanupRecord) error {
	if record.Path == "" || !record.Object.valid() || record.Rollback.LeaseID == (ACLLeaseID{}) {
		return errors.New("sandbox: invalid restricted cleanup record")
	}
	if record.Rollback.Role != ACERoleRestrictingAllow && record.Rollback.Role != ACERoleRestrictingDeny {
		return errors.New("sandbox: restricted journal accepts restricting ACEs only")
	}
	if !retirableRestrictedSID(record.Rollback.SID) || len(record.ACE) == 0 {
		return errors.New("sandbox: invalid restricted cleanup ACE")
	}
	if !recognizedRestrictingACE(record.Rollback.SID, record.Rollback.Role, record.ACE) {
		return errors.New("sandbox: cleanup ACE does not encode its restricting SID and role")
	}
	if sha256.Sum256(record.ACE) != record.Rollback.ACEHash {
		return errors.New("sandbox: restricted cleanup ACE hash mismatch")
	}
	return nil
}

func retirableRestrictedSID(sid SID) bool {
	return sid.isRestrictedTierTrustee()
}

func recognizedRestrictingACE(sid SID, role ACERole, ace []byte) bool {
	if len(ace) < 8 || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) {
		return false
	}
	wantType := byte(0) // ACCESS_ALLOWED_ACE_TYPE
	switch role {
	case ACERoleRestrictingAllow:
	case ACERoleRestrictingDeny:
		wantType = 1 // ACCESS_DENIED_ACE_TYPE
	default:
		return false
	}
	return ace[0] == wantType && bytes.Equal(ace[8:], sid.binary())
}

func createExclusiveDurable(root *os.Root, name string, data []byte, syncDirectory func(*os.Root) error) error {
	if root == nil || syncDirectory == nil || name == "" || name == "." || filepath.Base(name) != name {
		return errors.New("sandbox: invalid restricted journal filename")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = root.Remove(name)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = syncDirectory(root); err != nil {
		return err
	}
	remove = false
	return nil
}

type restrictedJournalDirectoryReader interface {
	ReadDir(int) ([]fs.DirEntry, error)
}

func forEachRestrictedJournalEntry(directory restrictedJournalDirectoryReader, visit func(fs.DirEntry) error) error {
	for {
		entries, err := directory.ReadDir(restrictedJournalReadBatchSize)
		for _, entry := range entries {
			if visitErr := visit(entry); visitErr != nil {
				return visitErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read restricted journal: %w", err)
		}
		if len(entries) == 0 {
			return io.ErrNoProgress
		}
	}
}

func readRestrictedJournalRegularFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	if root == nil || name == "" || name == "." || filepath.Base(name) != name {
		return nil, errors.New("sandbox: invalid restricted journal filename")
	}
	entryInfo, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
		return nil, errRestrictedJournalNonRegular
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(entryInfo, info) || !restrictedJournalHandleIsSafe(file, info) {
		return nil, errRestrictedJournalNonRegular
	}
	if info.Size() < 0 || info.Size() > maximum {
		return nil, errRestrictedJournalRecordTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errRestrictedJournalRecordTooLarge
	}
	return data, nil
}

func openRestrictedJournalSubroot(outer *os.Root, name string) (*os.Root, error) {
	entryInfo, err := outer.Lstat(name)
	if err != nil {
		return nil, err
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.IsDir() {
		return nil, errors.New("sandbox: restricted journal state directory is not a directory")
	}
	root, err := outer.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	info, statErr := directory.Stat()
	safe := statErr == nil && info.IsDir() && os.SameFile(entryInfo, info) && restrictedJournalHandleIsSafe(directory, info)
	closeErr := directory.Close()
	if statErr != nil {
		_ = root.Close()
		return nil, statErr
	}
	if closeErr != nil {
		_ = root.Close()
		return nil, closeErr
	}
	if !safe {
		_ = root.Close()
		return nil, errors.New("sandbox: restricted journal state directory changed while opening")
	}
	return root, nil
}

func validJournalKey(key string) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}
