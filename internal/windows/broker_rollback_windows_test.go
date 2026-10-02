//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestAbsentBrokerRollbackTargetIsResolvedByIdentity(t *testing.T) {
	installation, err := InstallationSID("rollback-installation")
	if err != nil {
		t.Fatal(err)
	}
	mutation := brokerACLMutation{
		Object: ACLObjectIdentity{VolumeSerial: 1, FileID: [16]byte{2}, Kind: ACLObjectFile, LinkCount: 1},
		SID:    installation, Path: `C:\work\gone.txt`,
		ACE: encodeACE(installation, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead}),
	}
	absent := []error{
		fmt.Errorf("open ACL target: %w", win.STATUS_OBJECT_NAME_NOT_FOUND),
		fmt.Errorf("open ACL target: %w", win.STATUS_OBJECT_PATH_NOT_FOUND),
		fmt.Errorf("open ACL target: %w", win.STATUS_DELETE_PENDING),
		fmt.Errorf("open ACL target: %w", win.ERROR_FILE_NOT_FOUND),
		fmt.Errorf("open ACL target: %w", win.ERROR_PATH_NOT_FOUND),
	}
	for _, openErr := range absent {
		t.Run(openErr.Error(), func(t *testing.T) {
			deleted := func(string, ACLObjectIdentity) (bool, error) { return false, nil }
			if err := resolveAbsentBrokerRollbackTarget(mutation, openErr, deleted); err != nil {
				t.Fatalf("deleted object's rollback = %v, want already rolled back", err)
			}
			moved := func(string, ACLObjectIdentity) (bool, error) { return true, nil }
			if err := resolveAbsentBrokerRollbackTarget(mutation, openErr, moved); !errors.Is(err, ErrRestrictedTargetChanged) {
				t.Fatalf("moved object's rollback = %v, want ErrRestrictedTargetChanged", err)
			}
			lookupErr := errors.New("injected identity lookup failure")
			undecided := func(string, ACLObjectIdentity) (bool, error) { return false, lookupErr }
			if err := resolveAbsentBrokerRollbackTarget(mutation, openErr, undecided); !errors.Is(err, lookupErr) {
				t.Fatalf("undecidable rollback = %v, want the lookup failure", err)
			}
		})
	}
	for _, other := range []error{
		fmt.Errorf("open ACL target: %w", win.STATUS_ACCESS_DENIED),
		fmt.Errorf("open ACL target: %w", win.ERROR_ACCESS_DENIED),
		fmt.Errorf("open ACL target: %w", win.ERROR_SHARING_VIOLATION),
	} {
		called := false
		exists := func(string, ACLObjectIdentity) (bool, error) { called = true; return false, nil }
		if err := resolveAbsentBrokerRollbackTarget(mutation, other, exists); !errors.Is(err, other) || called {
			t.Fatalf("%v: rollback = %v (lookup called %v), want the open error unchanged", other, err, called)
		}
	}
}

// TestBrokerRollbackOfDeletedAndMovedObjects needs no privilege: the broker
// mechanism is driven against a file in the test's own temporary directory.
func TestBrokerRollbackOfDeletedAndMovedObjects(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "leased.txt")
	if !canonicalBrokerPath(target) {
		t.Skipf("temporary directory %q is not a canonical broker path", target)
	}
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	object, err := openWin32ACLObject(target, false, false)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := object.snapshot()
	_ = object.close()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := InstallationSID("rollback-live-installation")
	if err != nil {
		t.Fatal(err)
	}
	mutation := brokerACLMutation{
		Object: snapshot.identity, SID: installation, Path: target,
		ACE: encodeACE(installation, ACLObjectFile, ACLACE{Type: ACEAllow, Access: ACLRead}),
	}
	if exists, err := brokerObjectExistsByIdentity(target, snapshot.identity); err != nil || !exists {
		t.Fatalf("live object exists = %v, %v", exists, err)
	}

	moved := filepath.Join(dir, "moved.txt")
	if err := os.Rename(target, moved); err != nil {
		t.Fatal(err)
	}
	if exists, err := brokerObjectExistsByIdentity(target, snapshot.identity); err != nil || !exists {
		t.Fatalf("renamed object exists = %v, %v", exists, err)
	}
	if err := (win32BrokerACLMechanism{}).Rollback(mutation); !errors.Is(err, ErrRestrictedTargetChanged) {
		t.Fatalf("rollback of a renamed object = %v, want ErrRestrictedTargetChanged", err)
	}

	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
	if exists, err := brokerObjectExistsByIdentity(target, snapshot.identity); err != nil || exists {
		t.Fatalf("deleted object exists = %v, %v", exists, err)
	}
	if err := (win32BrokerACLMechanism{}).Rollback(mutation); err != nil {
		t.Fatalf("rollback of a deleted object = %v, want already rolled back", err)
	}
}
