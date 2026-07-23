//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	win "golang.org/x/sys/windows"
)

type fakeElevatedLeaseClient struct {
	generation   uint64
	lease        ACLLeaseID
	token        uint64
	acquireCalls int
	issueCalls   int
	releaseCalls int
	err          error
}

func (client *fakeElevatedLeaseClient) Status() (uint64, error) {
	return client.generation, client.err
}
func (client *fakeElevatedLeaseClient) AcquireLease(objects []brokerObjectReference) (ACLLeaseID, error) {
	client.acquireCalls++
	if len(objects) != 1 {
		return ACLLeaseID{}, errors.New("unexpected objects")
	}
	return client.lease, client.err
}
func (client *fakeElevatedLeaseClient) IssueRestrictedToken(ACLLeaseID, brokerAccountKind) (brokerIssuedToken, error) {
	client.issueCalls++
	return brokerIssuedToken{Handle: client.token, Desktop: `Sandbox-77\Default`}, client.err
}
func (client *fakeElevatedLeaseClient) ReleaseLease(ACLLeaseID) error {
	client.releaseCalls++
	return client.err
}

func testElevatedLeaseConfig() elevatedBrokerLeaseConfig {
	return elevatedBrokerLeaseConfig{
		InstallationID: "install", PipeName: `\\.\pipe\broker`,
		HostPath:   `C:\ProgramData\Looprig\slots\1\sandbox-host.exe`,
		OfflineSID: "S-1-5-21-1", OnlineSID: "S-1-5-21-2",
		Generation: 7, RuntimeBaselineReady: true,
	}
}

func testElevatedLeasePolicy() policy.Effective {
	return policy.Effective{
		FS:               []policy.FSEntry{{Path: `C:\work`, Access: policy.AllAccess}},
		RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
	}
}

func testBrokerLeaseObject() brokerObjectReference {
	return brokerObjectReference{
		Handle: 3, Path: `C:\work`, VolumeSerial: 4, FileID: [16]byte{5},
		Kind: brokerObjectDirectory, Access: brokerAccessReadWrite, Scope: brokerScopeTree,
	}
}

func TestBrokerBackedElevatedLeaseAcquiresBeforeTokenAndReleasesOnce(t *testing.T) {
	id := ACLLeaseID{9}
	client := &fakeElevatedLeaseClient{generation: 7, lease: id, token: 77}
	closed := 0
	validated := 0
	deps := elevatedBrokerLeaseDependencies{
		connect: func(context.Context, string, string) (elevatedBrokerLeaseSession, error) {
			return elevatedBrokerLeaseSession{client: client, close: func() error { closed++; return nil }}, nil
		},
		objects: func(policy.Effective) ([]brokerObjectReference, func() error, []string, error) {
			return []brokerObjectReference{testBrokerLeaseObject()}, func() error { return nil }, []string{"narrowed"}, nil
		},
		token: func(raw uint64, _ elevatedBrokerLeaseConfig, account brokerAccountKind) (win.Token, error) {
			validated++
			if raw != 77 || account != brokerAccountOffline || client.acquireCalls != 1 {
				return 0, errors.New("token issued before ACL lease")
			}
			return win.Token(raw), nil
		},
	}
	factory, err := acquireBrokerBackedElevatedLease(context.Background(), testElevatedLeaseConfig(), testElevatedLeasePolicy(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if got := factory.Narrowings(); len(got) != 1 || got[0] != "narrowed" {
		t.Fatalf("narrowings = %v", got)
	}
	execution, err := factory.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execution.IssueToken(brokerAccountOffline); err != nil {
		t.Fatal(err)
	}
	if validated != 1 || client.issueCalls != 1 {
		t.Fatalf("validated=%d issue=%d", validated, client.issueCalls)
	}
	if err := execution.Release(); err != nil {
		t.Fatal(err)
	}
	if err := execution.Release(); err != nil {
		t.Fatal(err)
	}
	if client.releaseCalls != 1 || closed != 1 {
		t.Fatalf("release=%d close=%d", client.releaseCalls, closed)
	}
	if err := factory.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerBackedElevatedLeaseGenerationMismatchClosesWithoutAcquire(t *testing.T) {
	client := &fakeElevatedLeaseClient{generation: 8, lease: ACLLeaseID{9}}
	closed := 0
	deps := elevatedBrokerLeaseDependencies{
		connect: func(context.Context, string, string) (elevatedBrokerLeaseSession, error) {
			return elevatedBrokerLeaseSession{client: client, close: func() error { closed++; return nil }}, nil
		},
		objects: func(policy.Effective) ([]brokerObjectReference, func() error, []string, error) {
			return []brokerObjectReference{testBrokerLeaseObject()}, func() error { return nil }, nil, nil
		},
		token: validateBrokerTokenHandle,
	}
	factory, err := acquireBrokerBackedElevatedLease(context.Background(), testElevatedLeaseConfig(), testElevatedLeasePolicy(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Acquire(context.Background()); err == nil {
		t.Fatal("generation mismatch accepted")
	}
	if client.acquireCalls != 0 || client.releaseCalls != 0 || closed != 1 {
		t.Fatalf("acquire=%d release=%d close=%d", client.acquireCalls, client.releaseCalls, closed)
	}
}

func TestElevatedRuntimeVocabularyFailsClosed(t *testing.T) {
	p := testElevatedLeasePolicy()
	p.RuntimeBaselines = []string{"attacker.baseline"}
	if err := validateElevatedRuntimeVocabulary(p); err == nil {
		t.Fatal("unknown runtime baseline accepted")
	}
	p = testElevatedLeasePolicy()
	p.FS[0].Access = policy.ExecAccess
	if err := validateElevatedRuntimeVocabulary(p); err == nil {
		t.Fatal("execute without read accepted")
	}
}

func TestCompileElevatedBrokerObjectsPinsExactIdentityAndPolicy(t *testing.T) {
	target := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(target, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	effective := policy.Effective{
		FS: []policy.FSEntry{{
			Path: target, Access: policy.ReadAccess | policy.ExecAccess,
			Denied: policy.WriteAccess, Exact: true,
		}},
		RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
	}
	objects, closeObjects, narrowings, err := compileElevatedBrokerObjects(effective)
	if err != nil {
		t.Fatal(err)
	}
	defer closeObjects()
	if len(narrowings) != 0 || len(objects) != 1 {
		t.Fatalf("objects=%d narrowings=%v", len(objects), narrowings)
	}
	object := objects[0]
	if object.Kind != brokerObjectFile || object.Scope != brokerScopeExact ||
		object.Access != brokerAccessRead || object.Denied != brokerAccessWrite ||
		object.Handle == 0 || object.VolumeSerial == 0 || object.FileID == ([16]byte{}) {
		t.Fatalf("object = %#v", object)
	}
}

func TestElevatedGrantLeaseRetainsValidatedHandleAndComposesBaseObjects(t *testing.T) {
	basePath := filepath.Join(t.TempDir(), "base.txt")
	grantPath := filepath.Join(t.TempDir(), "grant.txt")
	for _, path := range []string{basePath, grantPath} {
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	baseEffective := policy.Effective{
		FS:               []policy.FSEntry{{Path: basePath, Access: policy.ReadAccess | policy.ExecAccess, Exact: true}},
		RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
	}
	baseObjects, closeBase, _, err := compileElevatedBrokerObjects(baseEffective)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBase()
	base := &brokerBackedElevatedLeaseFactory{objects: baseObjects}

	binding, err := policy.CapturePathBinding(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquireACLPathHandle(&binding, binding.CanonicalPath, true)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetAccess(policy.WriteAccess)
	effective := policy.Effective{
		FS: []policy.FSEntry{
			{Path: basePath, Access: policy.ReadAccess | policy.ExecAccess, Exact: true},
			{Path: grantPath, Access: policy.WriteAccess, Exact: true},
		},
		RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
	}
	deps := elevatedBrokerLeaseDependencies{
		connect: func(context.Context, string, string) (elevatedBrokerLeaseSession, error) {
			return elevatedBrokerLeaseSession{}, errors.New("not used")
		},
		token: validateBrokerTokenHandle,
	}
	factory, err := acquireBrokerBackedElevatedGrantLease(context.Background(), testElevatedLeaseConfig(), effective, base, []*policy.PathHandle{handle}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if len(factory.objects) != 2 {
		t.Fatalf("composed objects = %d, want base + grant", len(factory.objects))
	}
	var grant brokerObjectReference
	for _, object := range factory.objects {
		if strings.EqualFold(object.Path, grantPath) {
			grant = object
		}
	}
	if grant.Handle == 0 || grant.Handle == uint64(handle.NativeHandle()) || grant.Access&brokerAccessWrite == 0 {
		t.Fatalf("grant object did not retain independent validated authority: %#v", grant)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := handleGrantedAccess(win.Handle(grant.Handle)); err != nil {
		t.Fatalf("grant authority died with borrowed validation handle: %v", err)
	}
	if err := factory.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := handleGrantedAccess(win.Handle(grant.Handle)); err == nil {
		t.Fatal("grant authority survived factory release")
	}
}

func TestBrokerReferenceAuthorizesOnlyDeclaredAxesAndScope(t *testing.T) {
	sid, err := InstallationSID("policy-test")
	if err != nil {
		t.Fatal(err)
	}
	reference := testBrokerLeaseObject()
	reference.Access = brokerAccessRead
	read := encodeACE(sid, ACLObjectDirectory, ACLACE{Type: ACEAllow, Access: ACLRead, Inheritable: true})
	write := encodeACE(sid, ACLObjectDirectory, ACLACE{Type: ACEAllow, Access: ACLWrite, Inheritable: true})
	nonInherited := encodeACE(sid, ACLObjectDirectory, ACLACE{Type: ACEAllow, Access: ACLRead})
	if !brokerReferenceAuthorizesACE(reference, read, sid, ACLObjectDirectory) {
		t.Fatal("declared inherited read axis rejected")
	}
	if brokerReferenceAuthorizesACE(reference, write, sid, ACLObjectDirectory) {
		t.Fatal("undeclared write axis accepted")
	}
	if brokerReferenceAuthorizesACE(reference, nonInherited, sid, ACLObjectDirectory) {
		t.Fatal("scope mismatch accepted")
	}
}

func TestElevatedObjectsRejectAmbientRestrictedCodeAuthorityOnDeniedAxes(t *testing.T) {
	restrictedCode := restrictedCodeSID()
	reference := testBrokerLeaseObject()
	reference.Access = brokerAccessRead
	reference.Denied = brokerAccessWrite

	read := encodeACE(restrictedCode, ACLObjectDirectory, ACLACE{Type: ACEAllow, Access: ACLRead})
	if err := rejectAmbientRestrictedCodeAuthority([][]byte{read}, reference); err != nil {
		t.Fatalf("ambient authority within the declared read axis rejected: %v", err)
	}
	write := encodeACE(restrictedCode, ACLObjectDirectory, ACLACE{Type: ACEAllow, Access: ACLWrite})
	if err := rejectAmbientRestrictedCodeAuthority([][]byte{write}, reference); err == nil {
		t.Fatal("ambient Restricted Code write authority widened a read-only root")
	}
	full := append([]byte(nil), read...)
	binary.LittleEndian.PutUint32(full[4:8], 0x10000000) // GENERIC_ALL
	if err := rejectAmbientRestrictedCodeAuthority([][]byte{full}, reference); err == nil {
		t.Fatal("ambient Restricted Code generic-all authority was accepted")
	}
	if err := rejectAmbientRestrictedCodeAuthority([][]byte{{0, 0, 1, 0}}, reference); err == nil {
		t.Fatal("malformed ambient ACE was accepted")
	}
}

func TestExactBrokerRestrictingSIDSetRequiresRuntimeInstallationAndExecution(t *testing.T) {
	installation, err := InstallationSID("restricting-set")
	if err != nil {
		t.Fatal(err)
	}
	execution := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "execution")
	parse := func(text string) *win.SID {
		t.Helper()
		sid, err := win.StringToSid(text)
		if err != nil {
			t.Fatal(err)
		}
		return sid
	}
	installationSID := parse(installation.String())
	groups := []win.SIDAndAttributes{
		{Sid: parse(restrictedCodeSID().String())},
		{Sid: installationSID},
		{Sid: parse(execution.String())},
	}
	if !exactBrokerRestrictingSIDSet(groups, installationSID) {
		t.Fatal("exact required broker restricting SID set rejected")
	}
	groups[0] = win.SIDAndAttributes{Sid: parse(execution.String())}
	if exactBrokerRestrictingSIDSet(groups, installationSID) {
		t.Fatal("set without Restricted Code SID accepted")
	}
	groups = append(groups, win.SIDAndAttributes{Sid: parse("S-1-1-0")})
	if exactBrokerRestrictingSIDSet(groups, installationSID) {
		t.Fatal("restricting SID superset accepted")
	}
}
