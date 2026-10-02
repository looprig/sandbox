//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// brokerLeaseJournalName is the broker's durable lease journal beneath the
// protected state root (loadBrokerRuntimeConfigWithVerifier derives the same
// path for the service).
const brokerLeaseJournalName = "broker-leases.journal"

// SetupResidueError is Remove's report of what it could not clean (design
// §12: removal "reports any residual object"). Every installation-owned
// object Remove could remove has been removed when it is returned; the
// protected state root, including the lease journal that still names the
// residue, is deliberately KEPT, so a later Remove retries exactly those
// leases instead of forgetting them. Problems carries one
// SetupProblemLeaseRecoveryPending entry per object (Path) whose lease ACE
// is still applied, or one for the journal itself when it cannot be read.
type SetupResidueError struct {
	Problems []SetupProblem
}

func (err *SetupResidueError) Error() string {
	if err == nil || len(err.Problems) == 0 {
		return "sandbox: Windows removal left residue"
	}
	paths := make([]string, 0, len(err.Problems))
	for _, problem := range err.Problems {
		if problem.Path != "" {
			paths = append(paths, problem.Path)
		}
	}
	return fmt.Sprintf("sandbox: Windows removal left %d unreconciled ACL lease object(s); the state root and its lease journal were kept for a retry: %s",
		len(err.Problems), strings.Join(paths, ", "))
}

// stopBrokerServiceForRemoval stops the manifest-owned broker before any
// other dependency is touched. Order matters (review M14): removing the
// offline firewall rules first opened a window in which a still-running
// broker could issue offline-account tokens with no outbound block, and a
// running broker would also race the remover's own lease reconciliation.
// Stopping it also lets the service loop retire every lease its live
// connections still hold (each connection's Disconnect), so what remains in
// the journal afterwards is exactly what the remover must reconcile.
func stopBrokerServiceForRemoval(api serviceAPI, name, manifestIdentity string) error {
	if api == nil || name == "" || manifestIdentity == "" {
		return errServiceOwnershipMismatch
	}
	record, err := api.Lookup(name)
	if errors.Is(err, errServiceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.Owned || record.Spec.Name != name || record.Identity != manifestIdentity {
		return errServiceOwnershipMismatch
	}
	return api.Stop(name)
}

// reconcileInstalledBrokerLeases is removal's production lease reconciler.
// The broker is stopped (stopBrokerServiceForRemoval) before this runs, so
// the elevated remover owns the journal: it opens the existing
// SYSTEM/Administrators-only file without rewriting its protection, verifies
// that protection, and rolls back every unreleased lease with the broker's own
// ACL mechanism. A missing journal means no lease was ever journaled.
func reconcileInstalledBrokerLeases(setup validatedSetup) ([]SetupProblem, error) {
	path := filepath.Join(setup.stateRoot, brokerLeaseJournalName)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	protection, err := inspectCredentialFileProtection(path)
	if err != nil || !protection.valid() {
		return nil, errors.Join(errors.New("windows sandbox: lease journal ACL is not protected"), err)
	}
	// #nosec G304 -- path is derived from the validated, manifest-owned state
	// root, and its protection was verified above.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	store, err := newProtectedBrokerLeaseJournalStore(&osBrokerJournalFile{path: path, file: file})
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	defer store.Close()
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		return nil, err
	}
	return reconcileJournaledBrokerLeases(journal, win32BrokerACLMechanism{})
}

// reconcileJournaledBrokerLeases rolls back every unreleased lease in journal
// (mutations in reverse application order, exactly as windowsBroker.rollback
// does), durably records Released for each one it fully cleaned, and returns
// one problem per mutation it could not roll back. It never stops early: one
// stuck object must not hide the rest. Leases are visited in identity order so
// the report is deterministic.
//
// A residue entry describes an ACE that is still applied. For a lease
// journaled by a current broker that ACE names only the lease's one-shot SID,
// which no future token can carry, so it is inert. For a lease journaled by a
// broker from before the H10 fix it may name the persistent installation SID,
// which a reinstall with the same InstallationID would re-derive; that is why
// such residue is reported rather than dropped, and why the journal is kept.
func reconcileJournaledBrokerLeases(journal *brokerLeaseJournal, acl brokerACLMechanism) ([]SetupProblem, error) {
	if journal == nil || acl == nil {
		return nil, errors.New("windows sandbox: incomplete removal lease reconciler")
	}
	recovered, err := journal.recover()
	if err != nil {
		return nil, fmt.Errorf("read broker lease journal for removal: %w", err)
	}
	ids := make([]ACLLeaseID, 0, len(recovered))
	for id := range recovered {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(left, right ACLLeaseID) int { return slices.Compare(left[:], right[:]) })
	var problems []SetupProblem
	for _, id := range ids {
		record := recovered[id]
		clean := true
		for index := len(record.Mutations) - 1; index >= 0; index-- {
			mutation := record.Mutations[index]
			if rollbackErr := acl.Rollback(mutation); rollbackErr != nil {
				clean = false
				problems = append(problems, SetupProblem{
					Code: SetupProblemLeaseRecoveryPending, Resource: "broker-lease", Path: mutation.Path,
					Detail: removalResidueDetail(mutation),
				})
			}
		}
		if !clean {
			continue
		}
		lease := &brokerLease{id: id, binding: record.Binding, restricting: record.SID}
		if err := journal.appendAndFlush(brokerLeaseEvent{Kind: brokerLeaseEventReleased, LeaseID: lease.id,
			Nonce: lease.binding.Nonce, PID: lease.binding.PID, Created: lease.binding.CreationTime, SID: lease.restricting}); err != nil {
			// Rolled back but not recorded: a retry repeats an idempotent
			// rollback, so this is reported only because the journal will
			// still name the lease.
			problems = append(problems, SetupProblem{
				Code: SetupProblemLeaseRecoveryPending, Resource: "broker-lease-journal", Path: brokerLeaseJournalName,
				Detail: "a reconciled lease could not be recorded as released",
			})
		}
	}
	return problems, nil
}

func removalResidueDetail(mutation brokerACLMutation) string {
	if mutation.SID.kind == sidKindInstallation {
		return "a pre-H10 installation-SID ACE is still applied; a reinstall with the same installation identity would re-activate it"
	}
	return "a lease ACE is still applied; it names a one-shot SID no future token carries"
}
