//go:build windows

package windows

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/winpath"
	win "golang.org/x/sys/windows"
)

const (
	aceInheritedFlag = 0x10
	aclRevision      = 4 // ACL_REVISION_DS accepts basic and object ACEs.
)

var (
	errACLIdenticalCollision = errors.New("sandbox: byte-identical ACL mutation collision")
)

// ACLMutationRecord is the cleanup-only fact persisted before one DACL write.
// BaselineIdentical disambiguates a pre-existing byte-identical ACE from the
// occurrence owned by this lease.
type ACLMutationRecord struct {
	Object            ACLObjectIdentity
	Rollback          ACLRollbackMetadata
	ACE               []byte
	BaselineIdentical int
}

// ACLMutationRecorder lets the restricted journal establish write-ahead
// durability without coupling DACL mechanics to a journal representation.
type ACLMutationRecorder interface {
	BeforeACLMutation(ACLMutationRecord) error
	AfterACLRollback(ACLMutationRecord) error
}

type restrictedACLRecorder struct {
	journal *RestrictedJournal
	paths   map[aclIdentityKey]string
	keys    map[string][]string
}

// NewRestrictedACLProjection couples handle-bound mutation to the restricted
// tier's durable write-ahead journal. The journal path is descriptive cleanup
// data only; every live mutation still uses the retained handle.
func NewRestrictedACLProjection(plan ACLPlan, handles []*policy.PathHandle, journal *RestrictedJournal) (*ACLProjection, error) {
	if journal == nil {
		return nil, errors.New("sandbox: restricted ACL projection requires a journal")
	}
	recorder := &restrictedACLRecorder{
		journal: journal, paths: make(map[aclIdentityKey]string, len(handles)), keys: make(map[string][]string),
	}
	projection, err := NewACLProjection(plan, handles, recorder)
	if err != nil {
		return nil, err
	}
	for key, object := range projection.objects {
		win32Object, ok := object.(*win32ACLObject)
		if !ok {
			_ = projection.Close()
			return nil, errors.New("sandbox: restricted ACL projection requires Windows retained handles")
		}
		recorder.paths[key] = win32Object.target
	}
	return projection, nil
}

func (recorder *restrictedACLRecorder) BeforeACLMutation(record ACLMutationRecord) error {
	path := recorder.paths[identityKey(record.Object)]
	if path == "" || record.BaselineIdentical < 0 || uint64(record.BaselineIdentical) > uint64(^uint32(0)) {
		return errors.New("sandbox: invalid restricted ACL journal mutation")
	}
	key, err := recorder.journal.PrepareMutation(RestrictedCleanupRecord{
		Path: path, Object: record.Object, Rollback: record.Rollback, ACE: record.ACE,
		BaselineOccurrences: uint32(record.BaselineIdentical),
	})
	if err != nil {
		return err
	}
	signature := aclMutationSignature(record)
	recorder.keys[signature] = append(recorder.keys[signature], key)
	return nil
}

func (recorder *restrictedACLRecorder) AfterACLRollback(record ACLMutationRecord) error {
	signature := aclMutationSignature(record)
	keys := recorder.keys[signature]
	if len(keys) == 0 {
		return errors.New("sandbox: restricted ACL journal record is missing")
	}
	key := keys[len(keys)-1]
	if err := recorder.journal.CompleteCleanup(key); err != nil {
		return err
	}
	if len(keys) == 1 {
		delete(recorder.keys, signature)
	} else {
		recorder.keys[signature] = keys[:len(keys)-1]
	}
	return nil
}

func aclMutationSignature(record ACLMutationRecord) string {
	return fmt.Sprintf("%#v/%x/%d/%x/%d", record.Object, record.Rollback.LeaseID,
		record.Rollback.Role, record.Rollback.ACEHash, record.BaselineIdentical)
}

// ACLProjection owns no policy path handles. It binds separately owned,
// ACL-capable no-follow handles to the complete identity of each borrowed
// PathHandle before any mutation.
type ACLProjection struct {
	plan             ACLPlan
	objects          map[aclIdentityKey]aclProjectionObject
	owners           map[aclIdentityKey][]byte
	recorder         ACLMutationRecorder
	applied          []appliedACLMutation
	relaxTreeSharing bool
}

type aclProjectionObject interface {
	snapshot() (aclObjectSnapshot, error)
	setDACL([][]byte) error
	close() error
}

type aclTreeSharingPreparer interface {
	prepareWriteShared() (aclProjectionObject, error)
}

type aclObjectSnapshot struct {
	identity ACLObjectIdentity
	owner    []byte
	aces     [][]byte
}

type boundACLObject struct {
	object aclProjectionObject
	owner  []byte
}

type appliedACLMutation struct {
	record              ACLMutationRecord
	object              aclProjectionObject
	owner               []byte
	terminalRollbackErr error
}

type aclIdentityKey struct {
	volume uint64
	fileID [16]byte
	kind   ACLObjectKind
}

func identityKey(identity ACLObjectIdentity) aclIdentityKey {
	return aclIdentityKey{volume: identity.VolumeSerial, fileID: identity.FileID, kind: identity.Kind}
}

// NewACLProjection binds every planned ordinary object to exactly one retained
// no-follow handle. recorder may be nil only when the caller does not require a
// crash journal (for example, the broker's own durable lease machinery).
func NewACLProjection(plan ACLPlan, handles []*policy.PathHandle, recorder ACLMutationRecorder) (*ACLProjection, error) {
	objects := make(map[aclIdentityKey]aclProjectionObject, len(handles))
	closeObjects := func() {
		for _, object := range objects {
			_ = object.close()
		}
	}
	for _, handle := range handles {
		if handle == nil || handle.NativeHandle() == 0 {
			closeObjects()
			return nil, errors.New("sandbox: ACL projection requires an open retained handle")
		}
		object, err := newWin32ACLObject(handle)
		if err != nil {
			closeObjects()
			return nil, err
		}
		snapshot, err := object.snapshot()
		if err != nil {
			_ = object.close()
			closeObjects()
			return nil, fmt.Errorf("inspect retained ACL handle: %w", err)
		}
		key := identityKey(snapshot.identity)
		if _, duplicate := objects[key]; duplicate {
			_ = object.close()
			closeObjects()
			return nil, errors.New("sandbox: duplicate retained ACL object identity")
		}
		objects[key] = object
	}
	projection, err := newACLProjection(plan, objects, recorder)
	if err != nil {
		closeObjects()
		return nil, err
	}
	return projection, nil
}

func newACLProjection(plan ACLPlan, objects map[aclIdentityKey]aclProjectionObject, recorder ACLMutationRecorder) (*ACLProjection, error) {
	needed := plan.ValidationTargets()
	if len(objects) != len(needed) {
		return nil, errors.New("sandbox: retained ACL handle set does not exactly match the plan")
	}
	for _, target := range needed {
		object, ok := objects[identityKey(target.Object)]
		if !ok {
			return nil, errors.New("sandbox: planned ACL identity has no retained handle")
		}
		snapshot, err := object.snapshot()
		if err != nil || snapshot.identity != target.Object || len(snapshot.owner) == 0 {
			return nil, fmt.Errorf("%w: ACL object changed before binding", policy.ErrTargetChanged)
		}
	}
	owners := make(map[aclIdentityKey][]byte, len(needed))
	for _, target := range needed {
		snapshot, err := objects[identityKey(target.Object)].snapshot()
		if err != nil {
			return nil, err
		}
		owners[identityKey(target.Object)] = append([]byte(nil), snapshot.owner...)
	}
	return &ACLProjection{plan: plan, objects: objects, owners: owners, recorder: recorder}, nil
}

// Apply writes each exact ACE transactionally, validates every resulting DACL,
// and rolls back all lease occurrences if any step fails.
func (projection *ACLProjection) Apply() error {
	if projection == nil {
		return errors.New("sandbox: nil ACL projection")
	}
	if len(projection.applied) != 0 {
		return errors.New("sandbox: ACL projection is already applied")
	}
	for _, mutation := range projection.plan.Mutations() {
		object := projection.objects[identityKey(mutation.Object())]
		snapshot, err := object.snapshot()
		if err != nil {
			return projection.failApply(err)
		}
		if snapshot.identity != mutation.Object() {
			return projection.failApply(fmt.Errorf("%w: ACL identity, type, or link count changed", policy.ErrTargetChanged))
		}
		owner := append([]byte(nil), snapshot.owner...)
		if !bytes.Equal(projection.owners[identityKey(mutation.Object())], owner) {
			return projection.failApply(fmt.Errorf("%w: ACL owner changed", policy.ErrTargetChanged))
		}
		ace := mutation.ACE().Bytes
		record := ACLMutationRecord{
			Object: mutation.Object(), Rollback: mutation.Rollback(), ACE: append([]byte(nil), ace...),
			BaselineIdentical: countIdenticalACE(snapshot.aces, ace),
		}
		if projection.recorder != nil {
			if err := projection.recorder.BeforeACLMutation(record); err != nil {
				return projection.failApply(fmt.Errorf("flush ACL mutation record: %w", err))
			}
		}
		updated := insertCanonicalACE(snapshot.aces, ace)
		projection.applied = append(projection.applied, appliedACLMutation{record: record, object: object, owner: owner})
		if err := object.setDACL(updated); err != nil {
			return projection.failApply(fmt.Errorf("set retained-handle DACL: %w", err))
		}
		readback, err := object.snapshot()
		if err != nil || readback.identity != mutation.Object() || !bytes.Equal(readback.owner, owner) ||
			countIdenticalACE(readback.aces, ace) != record.BaselineIdentical+1 {
			return projection.failApply(errors.New("sandbox: ACL mutation read-back mismatch"))
		}
	}
	if err := projection.validatePlanReadback(); err != nil {
		return projection.failApply(err)
	}
	if projection.relaxTreeSharing {
		if err := projection.relaxRetainedTreeSharing(); err != nil {
			return projection.failApply(err)
		}
	}
	return nil
}

func (projection *ACLProjection) validatePlanReadback() error {
	for _, target := range projection.plan.ValidationTargets() {
		snapshot, err := projection.objects[identityKey(target.Object)].snapshot()
		if err != nil || snapshot.identity != target.Object {
			return fmt.Errorf("%w: ACL validation target changed", policy.ErrTargetChanged)
		}
		for _, expected := range target.Required {
			if !containsExpectedACE(snapshot.aces, target.Object.Kind, expected) {
				return errors.New("sandbox: required projected ACE missing from DACL read-back")
			}
		}
	}
	return nil
}

// relaxRetainedTreeSharing prepares every replacement while the original
// read-sharing-only set still freezes data writes and namespace changes. Only
// after all replacements have been identity/owner validated are they installed
// as one logical set. Delete sharing remains omitted for the lease lifetime.
func (projection *ACLProjection) relaxRetainedTreeSharing() error {
	replacements := make(map[aclIdentityKey]aclProjectionObject, len(projection.objects))
	expected := make(map[aclIdentityKey]ACLObjectIdentity, len(projection.objects))
	for _, target := range projection.plan.ValidationTargets() {
		expected[identityKey(target.Object)] = target.Object
	}
	closeReplacements := func() {
		for _, object := range replacements {
			_ = object.close()
		}
	}
	for key, object := range projection.objects {
		preparer, ok := object.(aclTreeSharingPreparer)
		if !ok {
			closeReplacements()
			return errors.New("sandbox: retained ACL tree object cannot relax write sharing")
		}
		replacement, err := preparer.prepareWriteShared()
		if err != nil {
			closeReplacements()
			return fmt.Errorf("relax retained ACL tree sharing: %w", err)
		}
		snapshot, err := replacement.snapshot()
		if err != nil || snapshot.identity != expected[key] || !bytes.Equal(snapshot.owner, projection.owners[key]) {
			_ = replacement.close()
			closeReplacements()
			return errors.Join(fmt.Errorf("%w: relaxed ACL tree handle changed", policy.ErrTargetChanged), err)
		}
		replacements[key] = replacement
	}
	old := projection.objects
	projection.objects = replacements
	for index := range projection.applied {
		projection.applied[index].object = replacements[identityKey(projection.applied[index].record.Object)]
	}
	var closeErr error
	for _, object := range old {
		closeErr = errors.Join(closeErr, object.close())
	}
	if closeErr != nil {
		return fmt.Errorf("close frozen ACL tree handles: %w", closeErr)
	}
	return nil
}

func (projection *ACLProjection) failApply(cause error) error {
	return errors.Join(cause, projection.Rollback())
}

// Rollback removes one byte-identical occurrence above its captured baseline
// for each mutation, in reverse order. It reads the current DACL each time and
// therefore preserves unrelated concurrent edits.
func (projection *ACLProjection) Rollback() error {
	if projection == nil {
		return nil
	}
	var result error
	remaining := make([]appliedACLMutation, 0, len(projection.applied))
	for index := len(projection.applied) - 1; index >= 0; index-- {
		applied := projection.applied[index]
		if applied.terminalRollbackErr != nil {
			result = errors.Join(result, applied.terminalRollbackErr)
			remaining = append(remaining, applied)
			continue
		}
		snapshot, err := applied.object.snapshot()
		if err == nil && (snapshot.identity != applied.record.Object || !bytes.Equal(snapshot.owner, applied.owner)) {
			err = fmt.Errorf("%w: refusing ACL rollback after identity or owner change", policy.ErrTargetChanged)
		}
		if err == nil {
			if applied.record.Rollback.Role == ACERoleRestrictingDeny && hasAllowForSID(snapshot.aces, applied.record.Rollback.SID) {
				err = errors.New("sandbox: refusing to remove restricting deny while a matching allow remains")
			}
		}
		if err == nil {
			var updated [][]byte
			updated, err = removeLeaseACEOccurrence(snapshot.aces, applied.record.ACE, applied.record.BaselineIdentical)
			if err == nil {
				err = applied.object.setDACL(updated)
			}
		}
		if err == nil {
			var readback aclObjectSnapshot
			readback, err = applied.object.snapshot()
			if err == nil && countIdenticalACE(readback.aces, applied.record.ACE) > applied.record.BaselineIdentical {
				err = errors.New("sandbox: lease ACE remains after rollback")
			}
		}
		if err == nil && projection.recorder != nil {
			err = projection.recorder.AfterACLRollback(applied.record)
		}
		if err != nil {
			if errors.Is(err, errACLIdenticalCollision) {
				applied.terminalRollbackErr = err
			}
			result = errors.Join(result, err)
			remaining = append(remaining, applied)
			continue
		}
	}
	for left, right := 0, len(remaining)-1; left < right; left, right = left+1, right-1 {
		remaining[left], remaining[right] = remaining[right], remaining[left]
	}
	projection.applied = remaining
	return result
}

func hasAllowForSID(aces [][]byte, sid SID) bool {
	want := sid.binary()
	for _, ace := range aces {
		if len(ace) >= 8 && ace[0] == win.ACCESS_ALLOWED_ACE_TYPE && bytes.Equal(ace[8:], want) {
			return true
		}
	}
	return false
}

// Close releases only the ACL-capable duplicate handles. The caller retains
// ownership of the original policy handles.
func (projection *ACLProjection) Close() error {
	if projection == nil {
		return nil
	}
	result := projection.Rollback()
	for key, object := range projection.objects {
		result = errors.Join(result, object.close())
		delete(projection.objects, key)
	}
	return result
}

func countIdenticalACE(aces [][]byte, target []byte) int {
	count := 0
	for _, ace := range aces {
		if bytes.Equal(ace, target) {
			count++
		}
	}
	return count
}

func insertCanonicalACE(aces [][]byte, inserted []byte) [][]byte {
	result := cloneACEs(aces)
	index := len(result)
	insertedDeny := len(inserted) != 0 && inserted[0] == win.ACCESS_DENIED_ACE_TYPE
	for i, existing := range result {
		inherited := len(existing) > 1 && existing[1]&aceInheritedFlag != 0
		existingDeny := len(existing) != 0 && existing[0] == win.ACCESS_DENIED_ACE_TYPE
		if inherited || (insertedDeny && !existingDeny) {
			index = i
			break
		}
	}
	result = append(result, nil)
	copy(result[index+1:], result[index:])
	result[index] = append([]byte(nil), inserted...)
	return result
}

func removeLeaseACEOccurrence(aces [][]byte, target []byte, baseline int) ([][]byte, error) {
	count := countIdenticalACE(aces, target)
	if count <= baseline {
		return cloneACEs(aces), nil
	}
	if count != baseline+1 {
		return cloneACEs(aces), fmt.Errorf("%w: observed %d occurrences above baseline %d", errACLIdenticalCollision, count, baseline)
	}
	result := cloneACEs(aces)
	for index := len(result) - 1; index >= 0; index-- {
		if bytes.Equal(result[index], target) {
			return append(result[:index], result[index+1:]...), nil
		}
	}
	panic("identical ACE count disagreed with scan")
}

func cloneACEs(aces [][]byte) [][]byte {
	result := make([][]byte, len(aces))
	for i := range aces {
		result[i] = append([]byte(nil), aces[i]...)
	}
	return result
}

func containsExpectedACE(aces [][]byte, kind ACLObjectKind, expected ACLACEExpectation) bool {
	wantType := byte(win.ACCESS_ALLOWED_ACE_TYPE)
	if expected.Role == ACERoleRestrictingDeny {
		wantType = win.ACCESS_DENIED_ACE_TYPE
	}
	wantMask := windowsFileAccessMask(expected.Access, kind)
	wantSID := expected.SID.binary()
	for _, ace := range aces {
		if len(ace) < 8 || ace[0] != wantType || (ace[1]&aceInheritedFlag != 0) != expected.Inherited {
			continue
		}
		mask := binary.LittleEndian.Uint32(ace[4:8])
		if mask&wantMask == wantMask && bytes.Equal(ace[8:], wantSID) {
			return true
		}
	}
	return false
}

type win32ACLObject struct {
	handle    win.Handle
	target    string
	closeOnce func() error
}

func newWin32ACLObject(handle *policy.PathHandle) (*win32ACLObject, error) {
	if handle == nil || handle.NativeHandle() == 0 {
		return nil, errors.New("sandbox: ACL projection requires an open retained handle")
	}
	return openBoundWin32ACLObject(win.Handle(handle.NativeHandle()), handle.Target(), handle.IsDir(), false)
}

func openBoundWin32ACLObject(source win.Handle, target string, directory, freezeWrites bool) (*win32ACLObject, error) {
	expected, err := identityFromHandle(source, target)
	if err != nil {
		return nil, fmt.Errorf("inspect ACL source %q: %w", target, err)
	}
	object, err := openWin32ACLObject(target, directory, freezeWrites)
	if err != nil {
		return nil, err
	}
	actual, err := object.snapshot()
	if err != nil || actual.identity != expected {
		_ = object.close()
		return nil, errors.Join(fmt.Errorf("%w: ACL target %q changed while acquiring authority", policy.ErrTargetChanged, target), err)
	}
	return object, nil
}

// duplicateBoundWin32ACLObject retains the already validated object's exact
// kernel identity and authority. Unlike openBoundWin32ACLObject it never
// resolves target again, so an elevated grant cannot be redirected between
// validation and broker lease construction.
func duplicateBoundWin32ACLObject(source win.Handle, target string, directory bool) (*win32ACLObject, error) {
	if invalidExplicitHandle(source) {
		return nil, errors.New("sandbox: invalid retained ACL source handle")
	}
	expected, err := identityFromHandle(source, target)
	if err != nil {
		return nil, fmt.Errorf("inspect retained ACL source %q: %w", target, err)
	}
	if (expected.Kind == ACLObjectDirectory) != directory {
		return nil, fmt.Errorf("%w: retained ACL source %q has unexpected type", policy.ErrTargetChanged, target)
	}
	var duplicate win.Handle
	if err := win.DuplicateHandle(win.CurrentProcess(), source, win.CurrentProcess(), &duplicate,
		0, false, win.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, fmt.Errorf("duplicate retained ACL source %q: %w", target, err)
	}
	object := &win32ACLObject{
		handle: duplicate, target: target,
		closeOnce: func() error { return win.CloseHandle(duplicate) },
	}
	actual, err := object.snapshot()
	if err != nil || actual.identity != expected {
		_ = object.close()
		return nil, errors.Join(fmt.Errorf("%w: retained ACL source %q changed", policy.ErrTargetChanged, target), err)
	}
	return object, nil
}

func openWin32ACLObject(target string, directory, freezeWrites bool) (*win32ACLObject, error) {
	pinned, err := winpath.OpenForACL(target, directory, freezeWrites)
	if err != nil {
		return nil, fmt.Errorf("open retained ACL target %q: %w", target, err)
	}
	return &win32ACLObject{handle: pinned.Handle, target: pinned.DOSPath, closeOnce: pinned.Close}, nil
}

func (object *win32ACLObject) prepareWriteShared() (aclProjectionObject, error) {
	if object == nil || object.handle == 0 || object.handle == win.InvalidHandle {
		return nil, errors.New("sandbox: invalid retained ACL tree handle")
	}
	snapshot, err := object.snapshot()
	if err != nil {
		return nil, err
	}
	replacement, err := openWin32ACLObject(object.target, snapshot.identity.Kind == ACLObjectDirectory, false)
	if err != nil {
		return nil, fmt.Errorf("prepare write-shared ACL target %q: %w", object.target, err)
	}
	return replacement, nil
}

// RestrictedACLCleaner is the allow-only crash-recovery half of restricted ACL
// projection. A journal path can select a candidate, but complete object
// identity and exact ACE metadata must validate before the retained no-follow
// handle is mutated. Deny cleanup is restricted to trusted live reverse
// rollback after all matching allows are absent.
type RestrictedACLCleaner struct{}

func (RestrictedACLCleaner) RemoveRestrictedAllowACE(record RestrictedCleanupRecord) (bool, error) {
	if record.Rollback.Role != ACERoleRestrictingAllow ||
		!retirableRestrictedSID(record.Rollback.SID) ||
		!recognizedRestrictingACE(record.Rollback.SID, record.Rollback.Role, record.ACE) ||
		sha256.Sum256(record.ACE) != record.Rollback.ACEHash {
		return false, errors.New("sandbox: untrusted restricted cleanup record")
	}
	object, err := openWin32ACLObject(record.Path, record.Object.Kind == ACLObjectDirectory, false)
	if err != nil {
		return false, fmt.Errorf("open restricted cleanup candidate %q: %w", record.Path, err)
	}
	defer object.close()
	snapshot, err := object.snapshot()
	if err != nil {
		return false, err
	}
	if snapshot.identity != record.Object {
		return false, ErrRestrictedTargetChanged
	}
	baseline := int(record.BaselineOccurrences)
	if uint32(baseline) != record.BaselineOccurrences {
		return false, errors.New("sandbox: restricted cleanup baseline overflows int")
	}
	if countIdenticalACE(snapshot.aces, record.ACE) <= baseline {
		return true, nil
	}
	updated, err := removeLeaseACEOccurrence(snapshot.aces, record.ACE, baseline)
	if err != nil {
		return false, err
	}
	if err := object.setDACL(updated); err != nil {
		return false, err
	}
	readback, err := object.snapshot()
	if err != nil || readback.identity != record.Object {
		return false, errors.Join(ErrRestrictedTargetChanged, err)
	}
	return countIdenticalACE(readback.aces, record.ACE) <= baseline, nil
}

func (object *win32ACLObject) snapshot() (aclObjectSnapshot, error) {
	identity, err := identityFromHandle(object.handle, object.target)
	if err != nil {
		return aclObjectSnapshot{}, err
	}
	sd, err := win.GetSecurityInfo(object.handle, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION)
	if err != nil {
		return aclObjectSnapshot{}, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return aclObjectSnapshot{}, errors.New("sandbox: object has no readable owner SID")
	}
	ownerBytes := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(owner)), win.GetLengthSid(owner))...)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return aclObjectSnapshot{}, errors.New("sandbox: object has no protected DACL")
	}
	aces, err := aclEntries(dacl)
	return aclObjectSnapshot{identity: identity, owner: ownerBytes, aces: aces}, err
}

func (object *win32ACLObject) setDACL(aces [][]byte) error {
	buffer, acl, err := makeACL(aces)
	if err != nil {
		return err
	}
	err = win.SetSecurityInfo(object.handle, win.SE_FILE_OBJECT, win.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	runtime.KeepAlive(buffer)
	return err
}

func (object *win32ACLObject) close() error {
	if object == nil || object.handle == 0 || object.handle == win.InvalidHandle {
		return nil
	}
	var err error
	if object.closeOnce != nil {
		err = object.closeOnce()
		object.closeOnce = nil
	} else {
		err = win.CloseHandle(object.handle)
	}
	object.handle = win.InvalidHandle
	return err
}

func aclEntries(acl *win.ACL) ([][]byte, error) {
	result := make([][]byte, 0, acl.AceCount)
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *win.ACCESS_ALLOWED_ACE
		if err := win.GetAce(acl, index, &ace); err != nil {
			return nil, err
		}
		size := ace.Header.AceSize
		if size < 4 {
			return nil, errors.New("sandbox: malformed ACE in DACL")
		}
		result = append(result, append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(ace)), size)...))
	}
	return result, nil
}

func makeACL(aces [][]byte) ([]byte, *win.ACL, error) {
	size := 8
	for _, ace := range aces {
		if len(ace) < 4 || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) {
			return nil, nil, errors.New("sandbox: malformed ACE bytes")
		}
		size += len(ace)
	}
	if size > 0xffff || len(aces) > 0xffff {
		return nil, nil, errors.New("sandbox: DACL exceeds Windows ACL limits")
	}
	buffer := make([]byte, size)
	buffer[0] = aclRevision
	binary.LittleEndian.PutUint16(buffer[2:4], uint16(size))
	binary.LittleEndian.PutUint16(buffer[4:6], uint16(len(aces)))
	offset := 8
	for _, ace := range aces {
		copy(buffer[offset:], ace)
		offset += len(ace)
	}
	return buffer, (*win.ACL)(unsafe.Pointer(&buffer[0])), nil
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
	_              [2]byte
}

func identityFromHandle(handle win.Handle, target string) (ACLObjectIdentity, error) {
	var id fileIDInfo
	var tag fileAttributeTagInfo
	var standard fileStandardInfo
	if err := win.GetFileInformationByHandleEx(handle, win.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return ACLObjectIdentity{}, err
	}
	if err := win.GetFileInformationByHandleEx(handle, win.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return ACLObjectIdentity{}, err
	}
	if err := win.GetFileInformationByHandleEx(handle, win.FileStandardInfo, (*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard))); err != nil {
		return ACLObjectIdentity{}, err
	}
	finalPath, err := finalPathFromHandle(handle)
	if err != nil || !winpath.EqualPath(finalPath, target) {
		return ACLObjectIdentity{}, fmt.Errorf("%w: retained handle final path changed", policy.ErrTargetChanged)
	}
	identity := ACLObjectIdentity{VolumeSerial: id.VolumeSerialNumber, FileID: id.FileID, ReparseTag: tag.ReparseTag, LinkCount: standard.NumberOfLinks}
	switch {
	case tag.FileAttributes&win.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		identity.Kind = ACLObjectReparsePoint
	case standard.Directory != 0:
		identity.Kind = ACLObjectDirectory
	default:
		identity.Kind = ACLObjectFile
	}
	if !identity.valid() {
		return ACLObjectIdentity{}, fmt.Errorf("%w: invalid retained ACL object identity", policy.ErrTargetChanged)
	}
	return identity, nil
}

func finalPathFromHandle(handle win.Handle) (string, error) {
	size, err := win.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil && size == 0 {
		return "", err
	}
	buffer := make([]uint16, size+1)
	n, err := win.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil || n >= uint32(len(buffer)) {
		return "", errors.New("sandbox: final ACL handle path changed while reading")
	}
	path, err := winpath.Normalize(win.UTF16ToString(buffer[:n]))
	if err != nil {
		return "", fmt.Errorf("sandbox: normalize final ACL handle path: %w", err)
	}
	return path, nil
}
