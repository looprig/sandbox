//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/winpath"
	win "golang.org/x/sys/windows"
)

// elevatedBrokerLeaseConfig is constructed only from the already verified
// installation snapshot. Environment variables, argv, and policy input are
// intentionally absent.
type elevatedBrokerLeaseConfig struct {
	InstallationID       string
	PipeName             string
	HostPath             string
	OfflineSID           string
	OnlineSID            string
	Generation           uint64
	RuntimeBaselineReady bool
}

type elevatedBrokerLeaseClient interface {
	Status() (uint64, error)
	AcquireLease([]brokerObjectReference) (ACLLeaseID, error)
	IssueRestrictedToken(ACLLeaseID, brokerAccountKind) (brokerIssuedToken, error)
	ReleaseLease(ACLLeaseID) error
}

type elevatedBrokerLeaseSession struct {
	client elevatedBrokerLeaseClient
	close  func() error
}

type elevatedBrokerLeaseDependencies struct {
	connect func(context.Context, string, string) (elevatedBrokerLeaseSession, error)
	objects func(policy.Effective) ([]brokerObjectReference, func() error, []string, error)
	token   func(uint64, elevatedBrokerLeaseConfig, brokerAccountKind) (win.Token, error)
}

type brokerBackedElevatedLease struct {
	client     elevatedBrokerLeaseClient
	close      func() error
	id         ACLLeaseID
	config     elevatedBrokerLeaseConfig
	validate   func(uint64, elevatedBrokerLeaseConfig, brokerAccountKind) (win.Token, error)
	narrowings []string
	once       sync.Once
	releaseErr error
}

// brokerBackedElevatedLeaseFactory retains only immutable, identity-bound
// object handles. Each execution obtains its own authenticated connection and
// ACL lease so completing one execution cannot revoke a sibling's authority.
type brokerBackedElevatedLeaseFactory struct {
	config     elevatedBrokerLeaseConfig
	deps       elevatedBrokerLeaseDependencies
	objects    []brokerObjectReference
	narrowings []string
	close      func() error
	once       sync.Once
	closeErr   error
}

func (factory *brokerBackedElevatedLeaseFactory) retainedBrokerObjects() []brokerObjectReference {
	if factory == nil {
		return nil
	}
	return append([]brokerObjectReference(nil), factory.objects...)
}

func productionElevatedBrokerLeaseDependencies() elevatedBrokerLeaseDependencies {
	return elevatedBrokerLeaseDependencies{
		connect: func(ctx context.Context, pipeName, hostPath string) (elevatedBrokerLeaseSession, error) {
			client, transport, err := connectAuthenticatedBrokerClient(ctx, pipeName, hostPath)
			if err != nil {
				return elevatedBrokerLeaseSession{}, err
			}
			return elevatedBrokerLeaseSession{client: client, close: transport.Close}, nil
		},
		objects: compileElevatedBrokerObjects,
		token:   validateBrokerTokenHandle,
	}
}

func acquireBrokerBackedElevatedLease(ctx context.Context, config elevatedBrokerLeaseConfig, effective policy.Effective, deps elevatedBrokerLeaseDependencies) (_ *brokerBackedElevatedLeaseFactory, err error) {
	if ctx == nil || config.InstallationID == "" ||
		!normalizedAbsoluteWindowsPath(config.HostPath) || config.PipeName == "" ||
		config.OfflineSID == "" || config.OnlineSID == "" || !config.RuntimeBaselineReady {
		return nil, errors.New("windows sandbox: incomplete verified broker lease configuration")
	}
	if deps.connect == nil || deps.objects == nil || deps.token == nil {
		return nil, errors.New("windows sandbox: incomplete broker lease dependencies")
	}
	objects, closeObjects, narrowings, err := deps.objects(policy.Clone(effective))
	if err != nil {
		return nil, err
	}
	if closeObjects == nil {
		closeObjects = func() error { return nil }
	}
	return &brokerBackedElevatedLeaseFactory{
		config: config, deps: deps,
		objects:    append([]brokerObjectReference(nil), objects...),
		narrowings: append([]string(nil), narrowings...),
		close:      closeObjects,
	}, nil
}

type elevatedRetainedObjectAuthority interface {
	retainedBrokerObjects() []brokerObjectReference
}

// acquireBrokerBackedElevatedGrantLease composes the executor's already
// retained base objects with grant objects derived only from ACL-capable
// validation handles. Grant objects override matching base identities; no
// pathname is reopened and the base factory retains ownership of base handles.
func acquireBrokerBackedElevatedGrantLease(ctx context.Context, config elevatedBrokerLeaseConfig, effective policy.Effective, base elevatedLease, handles []*policy.PathHandle, deps elevatedBrokerLeaseDependencies) (_ *brokerBackedElevatedLeaseFactory, err error) {
	authority, ok := base.(elevatedRetainedObjectAuthority)
	if !ok || len(handles) == 0 {
		return nil, errors.New("windows sandbox: elevated grant requires retained base authority and grant handles")
	}
	baseObjects := authority.retainedBrokerObjects()
	if len(baseObjects) == 0 {
		return nil, errors.New("windows sandbox: elevated base authority is empty")
	}
	grantObjects, closeGrant, narrowings, err := compileElevatedBrokerObjectsFromHandles(effective, handles)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*brokerBackedElevatedLeaseFactory, error) {
		return nil, errors.Join(cause, closeGrant())
	}
	merged := append([]brokerObjectReference(nil), baseObjects...)
	for _, grant := range grantObjects {
		replaced := false
		for index := range merged {
			if merged[index].VolumeSerial == grant.VolumeSerial &&
				merged[index].FileID == grant.FileID && merged[index].Kind == grant.Kind {
				merged[index] = grant
				replaced = true
				break
			}
		}
		if !replaced {
			merged = append(merged, grant)
		}
	}
	if len(merged) == 0 || len(merged) > maxBrokerObjects {
		return fail(errors.New("windows sandbox: composed elevated grant object set is invalid"))
	}
	slices.SortFunc(merged, func(a, b brokerObjectReference) int { return winpath.Compare(a.Path, b.Path) })
	if ctx == nil || config.InstallationID == "" ||
		!normalizedAbsoluteWindowsPath(config.HostPath) || config.PipeName == "" ||
		config.OfflineSID == "" || config.OnlineSID == "" || !config.RuntimeBaselineReady ||
		deps.connect == nil || deps.token == nil {
		return fail(errors.New("windows sandbox: incomplete verified broker grant configuration"))
	}
	return &brokerBackedElevatedLeaseFactory{
		config: config, deps: deps, objects: merged,
		narrowings: append([]string(nil), narrowings...), close: closeGrant,
	}, nil
}

func (factory *brokerBackedElevatedLeaseFactory) Acquire(ctx context.Context) (_ elevatedExecutionLease, err error) {
	if factory == nil || ctx == nil || factory.deps.connect == nil || factory.deps.token == nil ||
		len(factory.objects) == 0 {
		return nil, errors.New("windows sandbox: incomplete elevated execution lease factory")
	}
	session, err := factory.deps.connect(ctx, factory.config.PipeName, factory.config.HostPath)
	if err != nil {
		return nil, fmt.Errorf("connect authenticated Windows broker: %w", err)
	}
	if session.client == nil || session.close == nil {
		if session.close != nil {
			_ = session.close()
		}
		return nil, errors.New("windows sandbox: broker connector returned an incomplete session")
	}
	fail := func(cause error) (*brokerBackedElevatedLease, error) {
		return nil, errors.Join(cause, session.close())
	}
	generation, err := session.client.Status()
	if err != nil || generation == 0 || (factory.config.Generation != 0 && generation != factory.config.Generation) {
		return fail(errors.Join(errors.New("windows sandbox: broker generation does not match verified setup"), err))
	}
	id, err := session.client.AcquireLease(factory.objects)
	if err != nil {
		return fail(fmt.Errorf("acquire Windows broker ACL lease: %w", err))
	}
	if id == (ACLLeaseID{}) {
		return fail(errors.New("windows sandbox: broker returned an empty ACL lease"))
	}
	return &brokerBackedElevatedLease{
		client: session.client, close: session.close, id: id, config: factory.config,
		validate: factory.deps.token,
	}, nil
}

// Narrowings returns immutable compiler facts such as deny-only multi-link
// objects. The backend uses these facts to avoid claiming LevelFull.
func (factory *brokerBackedElevatedLeaseFactory) Narrowings() []string {
	if factory == nil {
		return nil
	}
	return append([]string(nil), factory.narrowings...)
}

// IssueToken is the only token operation and is intentionally per spawn.
func (lease *brokerBackedElevatedLease) IssueToken(account brokerAccountKind) (brokerIssuedToken, error) {
	if lease == nil || lease.client == nil || lease.id == (ACLLeaseID{}) ||
		(account != brokerAccountOffline && account != brokerAccountOnline) || lease.validate == nil {
		return brokerIssuedToken{}, errors.New("windows sandbox: invalid restricted-token lease request")
	}
	issued, err := lease.client.IssueRestrictedToken(lease.id, account)
	if err != nil {
		return brokerIssuedToken{}, err
	}
	token, err := lease.validate(issued.Handle, lease.config, account)
	if err != nil {
		if issued.Handle != 0 {
			_ = win.CloseHandle(win.Handle(issued.Handle))
		}
		return brokerIssuedToken{}, fmt.Errorf("validate broker duplicated token: %w", err)
	}
	issued.Handle = uint64(token)
	return issued, nil
}

func (lease *brokerBackedElevatedLease) Release() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		if lease.client != nil && lease.id != (ACLLeaseID{}) {
			lease.releaseErr = lease.client.ReleaseLease(lease.id)
		}
		if lease.close != nil {
			lease.releaseErr = errors.Join(lease.releaseErr, lease.close())
		}
	})
	return lease.releaseErr
}

func (factory *brokerBackedElevatedLeaseFactory) Release() error {
	if factory == nil {
		return nil
	}
	factory.once.Do(func() {
		if factory.close != nil {
			factory.closeErr = factory.close()
		}
	})
	return factory.closeErr
}

func validateElevatedRuntimeVocabulary(effective policy.Effective) error {
	if len(effective.RuntimeBaselines) != 1 || effective.RuntimeBaselines[0] != policy.WindowsRuntimeBaseline {
		return errors.New("windows sandbox: unsupported or absent Windows runtime baseline")
	}
	for _, entry := range effective.FS {
		if entry.Access&^policy.AllAccess != 0 || entry.Denied&^policy.AllAccess != 0 ||
			entry.Access&entry.Denied != 0 ||
			(entry.Access&policy.ExecAccess != 0) != (entry.Access&policy.ReadAccess != 0) {
			return errors.New("windows sandbox: unsupported Windows filesystem access shape")
		}
	}
	return nil
}

func compileElevatedBrokerObjects(effective policy.Effective) (_ []brokerObjectReference, _ func() error, _ []string, err error) {
	if err := validateElevatedRuntimeVocabulary(effective); err != nil {
		return nil, nil, nil, err
	}
	entries := append([]policy.FSEntry(nil), effective.FS...)
	slices.SortFunc(entries, func(a, b policy.FSEntry) int {
		if len(a.Path) != len(b.Path) {
			return len(a.Path) - len(b.Path)
		}
		return winpath.Compare(a.Path, b.Path)
	})
	var handles []*policy.PathHandle
	var trees []*RetainedACLTree
	closeAll := func() error {
		var result error
		for _, tree := range trees {
			result = errors.Join(result, tree.Close())
		}
		for _, handle := range handles {
			result = errors.Join(result, handle.Close())
		}
		return result
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeAll())
		}
	}()

	var refs []brokerObjectReference
	var narrowings []string
	var coveredTrees []string
	for _, entry := range entries {
		if strings.EqualFold(entry.Path, policy.NullDevicePath) || entry.Access == policy.DenyAccess {
			continue
		}
		covered := false
		for _, root := range coveredTrees {
			relative, relErr := filepath.Rel(root, entry.Path)
			if relErr == nil && relative != ".." && !strings.HasPrefix(relative, `..\`) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		binding, bindErr := policy.CapturePathBinding(entry.Path)
		if bindErr != nil {
			return nil, nil, nil, fmt.Errorf("bind elevated filesystem root %q: %w", entry.Path, bindErr)
		}
		handle, openErr := policy.AcquirePathHandle(&binding, binding.CanonicalPath, entry.Exact)
		if openErr != nil {
			return nil, nil, nil, fmt.Errorf("pin elevated filesystem root %q: %w", entry.Path, openErr)
		}
		handles = append(handles, handle)
		if entry.Exact {
			object, openErr := openBoundWin32ACLObject(win.Handle(handle.NativeHandle()), handle.Target(), false, true)
			if openErr != nil {
				return nil, nil, nil, openErr
			}
			snapshot, snapshotErr := object.snapshot()
			closeErr := object.close()
			if snapshotErr != nil || closeErr != nil {
				return nil, nil, nil, errors.Join(snapshotErr, closeErr)
			}
			reference := policyBrokerReference(handle.NativeHandle(), handle.Target(), snapshot.identity, brokerScopeExact, effective)
			if err := rejectAmbientRestrictedCodeAuthority(snapshot.aces, reference); err != nil {
				return nil, nil, nil, err
			}
			refs = append(refs, reference)
			continue
		}
		tree, treeErr := EnumerateRetainedACLTree(handle)
		if treeErr != nil {
			return nil, nil, nil, fmt.Errorf("enumerate elevated filesystem tree %q: %w", entry.Path, treeErr)
		}
		trees = append(trees, tree)
		coveredTrees = append(coveredTrees, handle.Target())
		for _, raw := range tree.objects {
			object, ok := raw.(*win32ACLObject)
			if !ok {
				return nil, nil, nil, errors.New("windows sandbox: retained ACL tree returned a non-Windows object")
			}
			snapshot, snapshotErr := object.snapshot()
			if snapshotErr != nil {
				return nil, nil, nil, snapshotErr
			}
			reference := policyBrokerReference(uintptr(object.handle), object.target, snapshot.identity, brokerScopeTree, effective)
			if snapshot.identity.Kind == ACLObjectFile {
				reference.Scope = brokerScopeExact
				if snapshot.identity.LinkCount > 1 {
					reference.Access, reference.Denied = brokerAccessNone, brokerAccessReadWrite
					narrowings = append(narrowings, "denied multi-link tree object "+object.target)
				}
			}
			if err := rejectAmbientRestrictedCodeAuthority(snapshot.aces, reference); err != nil {
				return nil, nil, nil, err
			}
			refs = append(refs, reference)
		}
	}
	if len(refs) == 0 {
		return nil, nil, nil, errors.New("windows sandbox: elevated policy contains no broker ACL objects")
	}
	if len(refs) > maxBrokerObjects {
		return nil, nil, nil, errors.New("windows sandbox: elevated ACL object set exceeds broker protocol limit")
	}
	slices.SortFunc(refs, func(a, b brokerObjectReference) int { return winpath.Compare(a.Path, b.Path) })
	return refs, closeAll, narrowings, nil
}

func compileElevatedBrokerObjectsFromHandles(effective policy.Effective, handles []*policy.PathHandle) (_ []brokerObjectReference, _ func() error, _ []string, err error) {
	if err := validateElevatedRuntimeVocabulary(effective); err != nil {
		return nil, nil, nil, err
	}
	var exactObjects []*win32ACLObject
	var trees []*RetainedACLTree
	closeAll := func() error {
		var result error
		for _, tree := range trees {
			result = errors.Join(result, tree.Close())
		}
		for _, object := range exactObjects {
			result = errors.Join(result, object.close())
		}
		return result
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, closeAll())
		}
	}()
	var refs []brokerObjectReference
	var narrowings []string
	for _, handle := range handles {
		if handle == nil || handle.NativeHandle() == 0 || handle.Target() == "" ||
			handle.Access() == policy.DenyAccess {
			return nil, nil, nil, errors.New("windows sandbox: invalid retained elevated grant handle")
		}
		granted, accessErr := handleGrantedAccess(win.Handle(handle.NativeHandle()))
		if accessErr != nil || granted&(win.READ_CONTROL|win.WRITE_DAC) != win.READ_CONTROL|win.WRITE_DAC {
			return nil, nil, nil, errors.Join(errors.New("windows sandbox: elevated grant handle lacks ACL authority"), accessErr)
		}
		if handle.Exact() {
			object, duplicateErr := duplicateBoundWin32ACLObject(win.Handle(handle.NativeHandle()), handle.Target(), false)
			if duplicateErr != nil {
				return nil, nil, nil, duplicateErr
			}
			exactObjects = append(exactObjects, object)
			snapshot, snapshotErr := object.snapshot()
			if snapshotErr != nil {
				return nil, nil, nil, snapshotErr
			}
			reference := policyBrokerReference(uintptr(object.handle), object.target, snapshot.identity, brokerScopeExact, effective)
			if err := rejectAmbientRestrictedCodeAuthority(snapshot.aces, reference); err != nil {
				return nil, nil, nil, err
			}
			refs = append(refs, reference)
			continue
		}
		tree, treeErr := EnumerateRetainedACLTree(handle)
		if treeErr != nil {
			return nil, nil, nil, fmt.Errorf("enumerate retained elevated grant tree: %w", treeErr)
		}
		trees = append(trees, tree)
		for _, raw := range tree.objects {
			object, ok := raw.(*win32ACLObject)
			if !ok {
				return nil, nil, nil, errors.New("windows sandbox: retained elevated grant tree returned a non-Windows object")
			}
			snapshot, snapshotErr := object.snapshot()
			if snapshotErr != nil {
				return nil, nil, nil, snapshotErr
			}
			reference := policyBrokerReference(uintptr(object.handle), object.target, snapshot.identity, brokerScopeTree, effective)
			if snapshot.identity.Kind == ACLObjectFile {
				reference.Scope = brokerScopeExact
				if snapshot.identity.LinkCount > 1 {
					reference.Access, reference.Denied = brokerAccessNone, brokerAccessReadWrite
					narrowings = append(narrowings, "denied multi-link grant object "+object.target)
				}
			}
			if err := rejectAmbientRestrictedCodeAuthority(snapshot.aces, reference); err != nil {
				return nil, nil, nil, err
			}
			refs = append(refs, reference)
		}
	}
	if len(refs) == 0 || len(refs) > maxBrokerObjects {
		return nil, nil, nil, errors.New("windows sandbox: retained elevated grant object set is invalid")
	}
	slices.SortFunc(refs, func(a, b brokerObjectReference) int { return winpath.Compare(a.Path, b.Path) })
	return refs, closeAll, narrowings, nil
}

func rejectAmbientRestrictedCodeAuthority(aces [][]byte, reference brokerObjectReference) error {
	if reference.Denied == brokerAccessNone {
		return nil
	}
	want := restrictedCodeSID().binary()
	for _, ace := range aces {
		mask, sidOffset, allowed, err := allowedACESIDOffset(ace)
		if err != nil {
			return fmt.Errorf("windows sandbox: inspect ambient Restricted Code authority on %q: %w", reference.Path, err)
		}
		if !allowed || len(ace) < sidOffset+len(want) || !slices.Equal(ace[sidOffset:sidOffset+len(want)], want) {
			continue
		}
		if restrictedCodeMaskConflicts(mask, reference.Denied, reference.Kind) {
			return fmt.Errorf("windows sandbox: ambient Restricted Code ACE widens denied authority on %q", reference.Path)
		}
	}
	return nil
}

func allowedACESIDOffset(ace []byte) (mask uint32, sidOffset int, allowed bool, err error) {
	if len(ace) < 8 || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) {
		return 0, 0, false, errors.New("malformed DACL ACE")
	}
	mask = binary.LittleEndian.Uint32(ace[4:8])
	switch ace[0] {
	case win.ACCESS_ALLOWED_ACE_TYPE, 9: // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		return mask, 8, true, nil
	case 4: // ACCESS_ALLOWED_COMPOUND_ACE_TYPE
		if len(ace) < 12 {
			return 0, 0, false, errors.New("malformed compound allow ACE")
		}
		return mask, 12, true, nil
	case 5, 11: // ACCESS_ALLOWED_OBJECT[_CALLBACK]_ACE_TYPE
		if len(ace) < 12 {
			return 0, 0, false, errors.New("malformed object allow ACE")
		}
		offset := 12
		flags := binary.LittleEndian.Uint32(ace[8:12])
		if flags&1 != 0 {
			offset += 16
		}
		if flags&2 != 0 {
			offset += 16
		}
		if offset > len(ace) {
			return 0, 0, false, errors.New("malformed object allow ACE")
		}
		return mask, offset, true, nil
	default:
		return mask, 0, false, nil
	}
}

func restrictedCodeMaskConflicts(mask uint32, denied brokerObjectAccess, kind brokerObjectKind) bool {
	const (
		genericRead     = uint32(0x80000000)
		genericWrite    = uint32(0x40000000)
		genericExecute  = uint32(0x20000000)
		genericAll      = uint32(0x10000000)
		writeDAC        = uint32(0x00040000)
		writeOwner      = uint32(0x00080000)
		readData        = uint32(0x00000001)
		readEA          = uint32(0x00000008)
		execute         = uint32(0x00000020)
		readAttributes  = uint32(0x00000080)
		writeData       = uint32(0x00000002)
		appendData      = uint32(0x00000004)
		writeEA         = uint32(0x00000010)
		deleteChild     = uint32(0x00000040)
		writeAttributes = uint32(0x00000100)
		deleteObject    = uint32(0x00010000)
	)
	if mask&(genericAll|writeDAC|writeOwner) != 0 {
		return true
	}
	if denied&brokerAccessRead != 0 &&
		mask&(genericRead|genericExecute|readData|readEA|execute|readAttributes) != 0 {
		return true
	}
	writeMask := genericWrite | writeData | appendData | writeEA | writeAttributes | deleteObject
	if kind == brokerObjectDirectory {
		writeMask |= deleteChild
	}
	return denied&brokerAccessWrite != 0 && mask&writeMask != 0
}

func policyBrokerReference(handle uintptr, path string, identity ACLObjectIdentity, scope brokerObjectScope, effective policy.Effective) brokerObjectReference {
	access := policy.ResolveFS(effective.FS, path)
	allowed := brokerAccessNone
	if access&policy.ReadAccess != 0 {
		allowed |= brokerAccessRead
	}
	if access&policy.WriteAccess != 0 {
		allowed |= brokerAccessWrite
	}
	denied := brokerAccessReadWrite &^ allowed
	kind := brokerObjectFile
	if identity.Kind == ACLObjectDirectory {
		kind = brokerObjectDirectory
	}
	return brokerObjectReference{
		Handle: uint64(handle), Path: path, VolumeSerial: identity.VolumeSerial,
		FileID: identity.FileID, Kind: kind, Access: allowed, Denied: denied, Scope: scope,
	}
}

func validateBrokerTokenHandle(raw uint64, config elevatedBrokerLeaseConfig, account brokerAccountKind) (win.Token, error) {
	if raw == 0 {
		return 0, errors.New("windows sandbox: broker returned an empty token handle")
	}
	token := win.Token(raw)
	restricted, err := token.IsRestricted()
	if err != nil || !restricted {
		return 0, errors.Join(errors.New("windows sandbox: broker token is not restricted"), err)
	}
	tokenType, err := tokenUint32Information(token, win.TokenType)
	if err != nil || tokenType != win.TokenPrimary {
		return 0, errors.Join(errors.New("windows sandbox: broker token is not primary"), err)
	}
	user, err := token.GetTokenUser()
	expected := config.OfflineSID
	if account == brokerAccountOnline {
		expected = config.OnlineSID
	}
	if err != nil || user == nil || user.User.Sid == nil || !equalSIDText(user.User.Sid.String(), expected) {
		return 0, errors.Join(errors.New("windows sandbox: broker token account mismatch"), err)
	}
	installation, err := InstallationSID(config.InstallationID)
	if err != nil {
		return 0, err
	}
	installationSID, err := win.StringToSid(installation.String())
	if err != nil {
		return 0, err
	}
	restricting, err := readTokenGroups(token, win.TokenRestrictedSids)
	if err != nil || !exactBrokerRestrictingSIDSet(restricting.groups, installationSID) {
		return 0, errors.Join(errors.New("windows sandbox: broker token restricting SID set mismatch"), err)
	}
	privileges, err := tokenPrivilegeList(token)
	if err != nil {
		return 0, err
	}
	var traverse win.LUID
	if err := win.LookupPrivilegeValue(nil, win.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &traverse); err != nil {
		return 0, err
	}
	for _, privilege := range privileges {
		if privilege.Luid != traverse {
			return 0, errors.New("windows sandbox: broker token retained an unexpected privilege")
		}
	}
	return token, nil
}

func exactBrokerRestrictingSIDSet(groups []win.SIDAndAttributes, installation *win.SID) bool {
	if len(groups) != 3 || installation == nil {
		return false
	}
	restrictedCode, err := win.StringToSid(restrictedCodeSID().String())
	if err != nil {
		return false
	}
	installationCount, restrictedCodeCount, executionCount := 0, 0, 0
	for _, group := range groups {
		if group.Sid == nil || !group.Sid.IsValid() {
			return false
		}
		switch {
		case win.EqualSid(group.Sid, installation):
			installationCount++
		case win.EqualSid(group.Sid, restrictedCode):
			restrictedCodeCount++
		case validBrokerExecutionRestrictingSIDText(group.Sid.String()):
			executionCount++
		default:
			return false
		}
	}
	return installationCount == 1 && restrictedCodeCount == 1 && executionCount == 1
}

func validBrokerExecutionRestrictingSIDText(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 12 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "32" {
		return false
	}
	for _, part := range parts[4:] {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
