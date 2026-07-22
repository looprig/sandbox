package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const restrictedJournalDirectory = "restricted-journal-v1"

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
// recorded ACE occurrence. A false result retains the record.
type RestrictedJournalCleaner interface {
	RemoveRestrictedAllowACE(RestrictedCleanupRecord) (removed bool, err error)
}

// RestrictedPruner may opportunistically remove exact allow ACEs for retired SIDs
// while it performs an independently safe, handle-bound tree enumeration.
// Journal data is supplied only as removal authority.
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
}

// OpenRestrictedJournal creates the durable store below stableScratchRoot.
// Construction is deliberately separate from Sweep so callers control the
// handle-bound cleanup implementation and can report retained cleanup loss.
func OpenRestrictedJournal(stableScratchRoot string) (*RestrictedJournal, error) {
	if stableScratchRoot == "" {
		return nil, errors.New("sandbox: stable scratch root is required")
	}
	abs, err := filepath.Abs(stableScratchRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve restricted journal root: %w", err)
	}
	root := filepath.Join(abs, restrictedJournalDirectory)
	j := &RestrictedJournal{
		root:       root,
		recordsDir: filepath.Join(root, "records"),
		retiredDir: filepath.Join(root, "retired-sids"),
	}
	for _, directory := range []string{j.recordsDir, j.retiredDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create restricted journal: %w", err)
		}
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
	return j, report, err
}

// PrepareMutation durably records cleanup before a caller changes a DACL. The
// returned opaque key is passed to CompleteCleanup only after read-back proves
// the recorded ACE absent.
func (j *RestrictedJournal) PrepareMutation(record RestrictedCleanupRecord) (string, error) {
	if j == nil {
		return "", errors.New("sandbox: nil restricted journal")
	}
	encoded, err := encodeRestrictedRecord(record)
	if err != nil {
		return "", err
	}
	if !j.isDurablyRetired(record.Rollback.SID) {
		return "", errors.New("sandbox: cleanup SID was not durably retired before mutation")
	}
	digest := sha256.Sum256(encoded)
	key := hex.EncodeToString(digest[:])
	if err := createExclusiveDurable(filepath.Join(j.recordsDir, key+".json"), encoded); err != nil {
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
	err := os.Remove(filepath.Join(j.recordsDir, key+".json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove restricted journal record: %w", err)
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
	entries, err := os.ReadDir(j.recordsDir)
	if err != nil {
		return report, fmt.Errorf("read restricted journal: %w", err)
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Name() < entries[k].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(j.recordsDir, entry.Name())
		data, readErr := os.ReadFile(path)
		if errors.Is(readErr, fs.ErrNotExist) {
			continue
		}
		if readErr != nil {
			report.Retained++
			continue
		}
		record, decodeErr := decodeRestrictedRecord(data)
		if decodeErr != nil {
			report.Corrupt++
			report.Retained++
			continue
		}
		if !j.isDurablyRetired(record.Rollback.SID) {
			report.Corrupt++
			report.Retained++
			continue
		}
		// The journal is writable by the sandboxed interactive user. Its SID,
		// role, lease, retirement marker, and exact bytes are therefore not
		// authority to remove a deny ACE, which could widen access. Normal
		// rollback can remove denies from its trusted in-memory lease after all
		// matching allows are absent; crash recovery safely leaves them inert.
		if record.Rollback.Role != ACERoleRestrictingAllow {
			report.Retained++
			continue
		}
		removed, cleanupErr := cleaner.RemoveRestrictedAllowACE(record)
		if cleanupErr != nil {
			report.Retained++
			if errors.Is(cleanupErr, ErrRestrictedTargetChanged) {
				continue
			}
			return report, cleanupErr
		}
		if !removed {
			report.Retained++
			continue
		}
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			return report, fmt.Errorf("remove swept restricted journal record: %w", removeErr)
		}
		report.Removed++
	}
	return report, nil
}

// RetireSID atomically and durably records a one-shot SID before issuance.
func (j *RestrictedJournal) RetireSID(sid SID) (bool, error) {
	if j == nil {
		return false, errors.New("sandbox: nil restricted journal")
	}
	if sid.kind != sidKindOneShot || !sid.isPrivateCapability() {
		return false, errors.New("sandbox: only module-issued one-shot SIDs may be retired")
	}
	digest := sha256.Sum256([]byte(sid.String()))
	path := filepath.Join(j.retiredDir, hex.EncodeToString(digest[:])+".sid")
	err := createExclusiveDurable(path, []byte(sid.String()+"\n"))
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
	return pruner.PruneRestrictedACEs(func(sid SID, role ACERole, ace []byte) bool {
		if role != ACERoleRestrictingAllow || sid.kind != sidKindOneShot || !sid.isPrivateCapability() || !recognizedRestrictingACE(sid, role, ace) {
			return false
		}
		return j.isDurablyRetired(sid)
	})
}

func (j *RestrictedJournal) isDurablyRetired(sid SID) bool {
	if j == nil || sid.kind != sidKindOneShot || !sid.isPrivateCapability() {
		return false
	}
	digest := sha256.Sum256([]byte(sid.String()))
	data, err := os.ReadFile(filepath.Join(j.retiredDir, hex.EncodeToString(digest[:])+".sid"))
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
	if record.Rollback.SID.kind != sidKindOneShot || !record.Rollback.SID.isPrivateCapability() || len(record.ACE) == 0 {
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

func createExclusiveDurable(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
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
	remove = false
	return nil
}

func validJournalKey(key string) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}
