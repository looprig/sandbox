//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
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
	IssueRestrictedToken(ACLLeaseID, brokerAccountKind) (uint64, error)
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

func acquireBrokerBackedElevatedLease(ctx context.Context, config elevatedBrokerLeaseConfig, effective policy.Effective, deps elevatedBrokerLeaseDependencies) (_ *brokerBackedElevatedLease, err error) {
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
	defer func() { err = errors.Join(err, closeObjects()) }()

	session, err := deps.connect(ctx, config.PipeName, config.HostPath)
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
	if err != nil || generation == 0 || (config.Generation != 0 && generation != config.Generation) {
		return fail(errors.Join(errors.New("windows sandbox: broker generation does not match verified setup"), err))
	}
	id, err := session.client.AcquireLease(objects)
	if err != nil {
		return fail(fmt.Errorf("acquire Windows broker ACL lease: %w", err))
	}
	if id == (ACLLeaseID{}) {
		return fail(errors.New("windows sandbox: broker returned an empty ACL lease"))
	}
	return &brokerBackedElevatedLease{
		client: session.client, close: session.close, id: id, config: config,
		validate:   deps.token,
		narrowings: append([]string(nil), narrowings...),
	}, nil
}

// Narrowings returns immutable compiler facts such as deny-only multi-link
// objects. The backend uses these facts to avoid claiming LevelFull.
func (lease *brokerBackedElevatedLease) Narrowings() []string {
	if lease == nil {
		return nil
	}
	return append([]string(nil), lease.narrowings...)
}

// IssueToken is the only token operation and is intentionally per spawn.
func (lease *brokerBackedElevatedLease) IssueToken(account brokerAccountKind) (win.Token, error) {
	if lease == nil || lease.client == nil || lease.id == (ACLLeaseID{}) ||
		(account != brokerAccountOffline && account != brokerAccountOnline) || lease.validate == nil {
		return 0, errors.New("windows sandbox: invalid restricted-token lease request")
	}
	raw, err := lease.client.IssueRestrictedToken(lease.id, account)
	if err != nil {
		return 0, err
	}
	token, err := lease.validate(raw, lease.config, account)
	if err != nil {
		if raw != 0 {
			_ = win.CloseHandle(win.Handle(raw))
		}
		return 0, fmt.Errorf("validate broker duplicated token: %w", err)
	}
	return token, nil
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
			refs = append(refs, policyBrokerReference(handle.NativeHandle(), handle.Target(), snapshot.identity, brokerScopeExact, effective))
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
	if err != nil || len(restricting.groups) != 2 || !sidInGroups(restricting.groups, installationSID) {
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
