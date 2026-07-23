//go:build windows

package windows

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
func (client *fakeElevatedLeaseClient) IssueRestrictedToken(ACLLeaseID, brokerAccountKind) (uint64, error) {
	client.issueCalls++
	return client.token, client.err
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
	lease, err := acquireBrokerBackedElevatedLease(context.Background(), testElevatedLeaseConfig(), testElevatedLeasePolicy(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if got := lease.Narrowings(); len(got) != 1 || got[0] != "narrowed" {
		t.Fatalf("narrowings = %v", got)
	}
	if _, err := lease.IssueToken(brokerAccountOffline); err != nil {
		t.Fatal(err)
	}
	if validated != 1 || client.issueCalls != 1 {
		t.Fatalf("validated=%d issue=%d", validated, client.issueCalls)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if client.releaseCalls != 1 || closed != 1 {
		t.Fatalf("release=%d close=%d", client.releaseCalls, closed)
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
	if _, err := acquireBrokerBackedElevatedLease(context.Background(), testElevatedLeaseConfig(), testElevatedLeasePolicy(), deps); err == nil {
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
