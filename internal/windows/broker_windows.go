//go:build windows

package windows

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	errBrokerLeaseReplay      = errors.New("windows sandbox: broker lease request replayed")
	errBrokerLeaseUnavailable = errors.New("windows sandbox: broker lease is unavailable")
	// errBrokerLeaseRecoveryPending reports that at least one lease could not
	// be rolled back and is quarantined (design §13). New leases and tokens are
	// refused until a retry rolls it back.
	errBrokerLeaseRecoveryPending = errors.New("windows sandbox: broker lease recovery is pending")
)

type brokerConnection interface {
	LeaseBinding() brokerLeaseBinding
	ValidateIdentity() error
	// AuthorizeObject must impersonate the authenticated pipe client and prove
	// that client could change this exact retained object's DACL.
	AuthorizeObject(brokerObjectReference) (brokerAuthorizedObject, error)
}

type brokerAuthorizedObject struct {
	Reference       brokerObjectReference
	Identity        ACLObjectIdentity
	AuthorityHandle uint64
	Release         func() error
}

type brokerACLMutation struct {
	Object              ACLObjectIdentity
	SID                 SID
	ACE                 []byte
	BaselineOccurrences uint32
	Path                string
	Handle              uint64
}

type brokerACLMechanism interface {
	Plan(brokerAuthorizedObject, []SID) ([]brokerACLMutation, error)
	Apply(brokerACLMutation) error
	Rollback(brokerACLMutation) error
}

type brokerRestrictedToken interface {
	DuplicateTo(brokerLeaseBinding) (uint64, error)
	Close() error
}

type brokerRestrictedTokenIssuer interface {
	IssueRestricted(brokerAccountKind, SID, SID) (brokerRestrictedToken, error)
}

// brokerDesktopContext is authority derived entirely by the broker after it
// has authenticated the connection and validated the lease/account. It
// deliberately contains no caller-selected name or security descriptor.
type brokerDesktopContext struct {
	LeaseID      ACLLeaseID
	Binding      brokerLeaseBinding
	Installation SID
	Restricting  SID
	Account      brokerAccountKind
}

type brokerManagedDesktop struct {
	Name  string
	close func() error
}

func (desktop *brokerManagedDesktop) Close() error {
	if desktop == nil || desktop.close == nil {
		return nil
	}
	err := desktop.close()
	if err == nil {
		desktop.close = nil
	}
	return err
}

type brokerDesktopManager interface {
	Create(brokerDesktopContext) (brokerManagedDesktop, error)
}

type brokerIssuedToken struct {
	Handle  uint64
	Desktop string
}

type brokerLease struct {
	id          ACLLeaseID
	binding     brokerLeaseBinding
	restricting SID
	mutations   []brokerACLMutation
	tokenIssued bool
	desktop     *brokerManagedDesktop
}

// brokerClientLiveness is the optional half of brokerClientProcess that lets
// reconcile tell a dead client from a live one. The production process
// (pipe_windows.go) answers from the retained, SYNCHRONIZE-capable process
// handle, so a recycled PID can never make a dead binding look alive.
type brokerClientLiveness interface {
	Exited() (bool, error)
}

type windowsBroker struct {
	// mu guards every map and counter below. It is held for bookkeeping and
	// for retirement, but deliberately NOT across a lease's projection: an
	// acquire may perform thousands of fsynced journal writes and impersonated
	// opens, and holding mu for all of it stalled every other client's status,
	// release and token request (review L8). An in-progress acquire is instead
	// registered in acquiring under mu, projected without it, and published
	// into leases (or aborted) under mu again.
	mu sync.Mutex
	// aclMu serializes every DACL read-modify-write the broker performs
	// (acl.Plan/Apply/Rollback). Concurrent acquires, releases and reconciles
	// may touch the same object, and an unserialized snapshot -> setDACL pair
	// from one could overwrite the other's freshly inserted ACE: losing an
	// allow only fails closed, but losing a carveout's deny would widen. Lock
	// order is mu -> aclMu -> the journal store's own mutex; aclMu is never
	// held while mu is being acquired.
	aclMu           sync.Mutex
	installationSID SID
	sids            *OneShotSIDGenerator
	leaseEntropy    io.Reader
	journal         *brokerLeaseJournal
	acl             brokerACLMechanism
	tokens          brokerRestrictedTokenIssuer
	desktops        brokerDesktopManager
	leases          map[ACLLeaseID]*brokerLease
	// acquiring holds leases whose Reserved record is durable but whose
	// projection is still running outside mu. Each is owned exclusively by its
	// acquiring goroutine: reconcile, Disconnect and status never touch one,
	// and that goroutine itself publishes it into leases or aborts it.
	acquiring map[ACLLeaseID]*brokerLease
	// quarantined holds leases whose rollback or release record failed. Each
	// keeps its journal record (Released is never written for it), its SID is
	// never reissued (the one-shot generator retires every SID it hands out),
	// and while any remain the broker refuses new leases and tokens. Status,
	// reconcile requests and every service start retry them.
	quarantined    map[ACLLeaseID]*brokerLease
	acquiredNonces map[[brokerNonceSize]byte]struct{}
	generation     uint64
}

func newWindowsBroker(installationSID SID, sids *OneShotSIDGenerator, journal *brokerLeaseJournal, acl brokerACLMechanism, tokens brokerRestrictedTokenIssuer, desktops brokerDesktopManager, leaseEntropy io.Reader) (*windowsBroker, error) {
	if installationSID.kind != sidKindInstallation || !installationSID.isModuleTrustee() || sids == nil || journal == nil || acl == nil || tokens == nil || desktops == nil {
		return nil, errors.New("windows sandbox: incomplete broker dependencies")
	}
	if leaseEntropy == nil {
		leaseEntropy = rand.Reader
	}
	broker := &windowsBroker{installationSID: installationSID, sids: sids, leaseEntropy: leaseEntropy, journal: journal, acl: acl, tokens: tokens, desktops: desktops,
		leases: make(map[ACLLeaseID]*brokerLease), acquiring: make(map[ACLLeaseID]*brokerLease),
		quarantined: make(map[ACLLeaseID]*brokerLease), acquiredNonces: make(map[[brokerNonceSize]byte]struct{})}
	// Reconciliation is a constructor invariant: no status or token operation
	// can be served by an instance that has not resolved its durable cleanup
	// log. A lease that cannot be rolled back yet is resolved by quarantine,
	// not by refusing to start: a fatal error here would put the service in an
	// SCM restart loop that can never clear (design §13). An unreadable journal
	// is still fatal, because then no lease can be accounted for at all. No
	// connection exists yet, so every journaled lease is an orphan of a
	// previous service instance and reconcile rolls all of them back.
	if err := broker.reconcile(); err != nil && !errors.Is(err, errBrokerLeaseRecoveryPending) {
		return nil, fmt.Errorf("reconcile broker leases at startup: %w", err)
	}
	// Compaction follows reconciliation so the rewritten journal carries only
	// what is still owed (review M14). Its failure is not fatal: the journal it
	// would have replaced is intact and still authoritative, and the next
	// Released record past the threshold retries it.
	_ = broker.journal.compact()
	return broker, nil
}

// Handle is deliberately closed over the five Task 13 operations. Codec
// validation is repeated because callers may construct frames without decoding.
func (broker *windowsBroker) Handle(connection brokerConnection, request brokerFrame) brokerFrame {
	response := brokerFrame{Kind: request.Kind, Direction: brokerResponse, Nonce: request.Nonce, LeaseID: request.LeaseID}
	if broker == nil || connection == nil || validateBrokerFrame(request) != nil || request.Direction != brokerRequest {
		response.Result = brokerResultInvalidRequest
		return response
	}
	binding := connection.LeaseBinding()
	if request.Nonce != binding.Nonce || connection.ValidateIdentity() != nil {
		response.Result = brokerResultUnauthorized
		return response
	}

	var err error
	if request.Kind == brokerMessageAcquireLease {
		// acquire manages mu itself so that its projection runs unlocked.
		response.LeaseID, err = broker.acquire(connection, request.Objects)
	} else {
		err = broker.handleLocked(binding, request, &response)
	}
	response.Result = brokerResultForError(err)
	if response.Result != brokerResultOK {
		response.TokenHandle = 0
		response.Desktop = ""
		if request.Kind == brokerMessageAcquireLease {
			response.LeaseID = [brokerLeaseIDSize]byte{}
		}
	}
	return response
}

func (broker *windowsBroker) handleLocked(binding brokerLeaseBinding, request brokerFrame, response *brokerFrame) error {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	var err error
	switch request.Kind {
	case brokerMessageStatus:
		err = broker.retryQuarantined()
		broker.generation++
		response.Generation = broker.generation
	case brokerMessageReleaseLease:
		err = broker.release(binding, ACLLeaseID(request.LeaseID))
	case brokerMessageIssueRestrictedToken:
		issued := brokerIssuedToken{}
		issued, err = broker.issueToken(binding, ACLLeaseID(request.LeaseID), request.Account)
		response.TokenHandle, response.Desktop = issued.Handle, issued.Desktop
	case brokerMessageReconcile:
		// Any authenticated client may ask, so the request is scoped to leases
		// whose owner is provably gone; see reconcile.
		err = broker.reconcile()
		broker.generation++
		response.Generation = broker.generation
	default:
		err = errBrokerFrameMalformed
	}
	return err
}

// acquire projects one lease in three phases. Reservation (quarantine and
// replay checks, identity, one-shot SID, the durable Reserved record) and
// publication (the durable Active record, the move into leases) run under mu;
// the projection between them, which is where every impersonated open and
// every per-mutation fsync happens, does not, so other connections' status,
// release and token requests are served meanwhile.
func (broker *windowsBroker) acquire(connection brokerConnection, references []brokerObjectReference) (ACLLeaseID, error) {
	broker.mu.Lock()
	lease, err := broker.reserve(connection.LeaseBinding())
	broker.mu.Unlock()
	if err != nil {
		return ACLLeaseID{}, err
	}

	projectErr := broker.project(connection, lease, references)

	broker.mu.Lock()
	defer broker.mu.Unlock()
	delete(broker.acquiring, lease.id)
	if projectErr == nil {
		projectErr = connection.ValidateIdentity()
	}
	if projectErr == nil {
		projectErr = broker.writeEvent(lease, brokerLeaseEventActive, 0, brokerACLMutation{})
	}
	if projectErr != nil {
		return ACLLeaseID{}, broker.abort(lease, projectErr)
	}
	broker.leases[lease.id] = lease
	return lease.id, nil
}

// reserve must be called with mu held. On success the lease is durably
// Reserved and registered in acquiring, which both keeps reconcile away from
// it and keeps nextLeaseID from handing its identity out twice.
func (broker *windowsBroker) reserve(binding brokerLeaseBinding) (*brokerLease, error) {
	if len(broker.quarantined) != 0 {
		return nil, errBrokerLeaseRecoveryPending
	}
	if _, replayed := broker.acquiredNonces[binding.Nonce]; replayed {
		return nil, errBrokerLeaseReplay
	}
	broker.acquiredNonces[binding.Nonce] = struct{}{}
	leaseID, err := broker.nextLeaseID()
	if err != nil {
		return nil, err
	}
	restricting, err := broker.sids.Next()
	if err != nil {
		return nil, err
	}
	lease := &brokerLease{id: leaseID, binding: binding, restricting: restricting}
	if err := broker.writeEvent(lease, brokerLeaseEventReserved, 0, brokerACLMutation{}); err != nil {
		return nil, err
	}
	broker.acquiring[leaseID] = lease
	return lease, nil
}

// project runs WITHOUT mu. The lease is owned exclusively by the calling
// goroutine (see acquiring), so its mutations slice needs no lock; every DACL
// read-modify-write is serialized by aclMu and every journal append by the
// journal store. A failure is returned for acquire to abort under mu.
//
// Only the lease's own one-shot restricting SID is ever projected onto a user
// object (design §9.2, review H10). The persistent installation SID stays in
// the issued token's restricting list, where it reaches the protected runner
// and the installation-owned state objects whose DACLs setup wrote, but it is
// never a trustee in a user object's DACL: it is deterministic and re-derived
// from the InstallationID on every reinstall, so an ACE naming it would be
// shared by every concurrent lease (each would pass the other's restricting
// check), and one left behind by a crash or a removal would stay live for
// every future token of that installation. A full-restricted token's second
// access check grants what any one of its restricting SIDs is allowed (less
// any deny naming one of them), so the lease SID's own allow ACE is what lets
// the lease's token in, and nothing projected for this lease is visible to a
// token that does not carry this one-shot SID.
func (broker *windowsBroker) project(connection brokerConnection, lease *brokerLease, references []brokerObjectReference) error {
	seenObjects := make(map[ACLObjectIdentity]struct{}, len(references))
	// Distinct leases never share a trustee now, so a byte-identical ACE
	// collision between two leases is impossible by construction. A duplicate
	// within one lease is still a malformed plan and is refused here, which
	// keeps rollback's one-occurrence-above-baseline arithmetic exact.
	seenMutations := make(map[string]struct{})
	for _, reference := range references {
		if err := connection.ValidateIdentity(); err != nil {
			return err
		}
		authorized, err := connection.AuthorizeObject(reference)
		if err != nil || !sameBrokerObject(reference, authorized) {
			if authorized.Release != nil {
				_ = authorized.Release()
			}
			return errors.Join(errBrokerClientUnauthorized, err)
		}
		if _, duplicate := seenObjects[authorized.Identity]; duplicate {
			if authorized.Release != nil {
				_ = authorized.Release()
			}
			return errBrokerClientUnauthorized
		}
		seenObjects[authorized.Identity] = struct{}{}
		broker.aclMu.Lock()
		mutations, err := broker.acl.Plan(authorized, []SID{lease.restricting})
		broker.aclMu.Unlock()
		if authorized.Release != nil {
			err = errors.Join(err, authorized.Release())
		}
		if err != nil {
			return err
		}
		if len(mutations) == 0 {
			return errors.New("windows sandbox: ACL plan contained no mutations")
		}
		for _, mutation := range mutations {
			if !broker.allowedMutation(mutation, authorized, lease.restricting) {
				return errBrokerClientUnauthorized
			}
			signature := fmt.Sprintf("%#v/%s/%x", mutation.Object, mutation.SID.String(), mutation.ACE)
			if _, duplicate := seenMutations[signature]; duplicate {
				return errBrokerClientUnauthorized
			}
			seenMutations[signature] = struct{}{}
			mutationID := uint32(len(lease.mutations))
			if err := broker.writeEvent(lease, brokerLeaseEventMutationPrepared, mutationID, mutation); err != nil {
				return err
			}
			// Record ownership before Apply: rollback must include a mutation even
			// when the mechanism reports an ambiguous post-write error.
			lease.mutations = append(lease.mutations, cloneBrokerMutation(mutation))
			broker.aclMu.Lock()
			err := broker.acl.Apply(mutation)
			broker.aclMu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (broker *windowsBroker) issueToken(binding brokerLeaseBinding, id ACLLeaseID, account brokerAccountKind) (brokerIssuedToken, error) {
	lease := broker.leases[id]
	if lease == nil {
		return brokerIssuedToken{}, errBrokerLeaseUnavailable
	}
	if !sameBrokerBinding(lease.binding, binding) || lease.tokenIssued || (account != brokerAccountOffline && account != brokerAccountOnline) {
		return brokerIssuedToken{}, errBrokerClientUnauthorized
	}
	if len(broker.quarantined) != 0 {
		return brokerIssuedToken{}, errBrokerLeaseRecoveryPending
	}
	// The token's restricting list is [Restricted Code, installation, lease]:
	// the installation SID admits the protected runner and installation-owned
	// runtime objects, the lease SID admits exactly this lease's projected
	// objects, and nothing admits another lease's.
	token, err := broker.tokens.IssueRestricted(account, broker.installationSID, lease.restricting)
	if err != nil {
		return brokerIssuedToken{}, err
	}
	desktop, desktopErr := broker.desktops.Create(brokerDesktopContext{
		LeaseID: id, Binding: binding, Installation: broker.installationSID,
		Restricting: lease.restricting, Account: account,
	})
	if desktopErr != nil || desktop.close == nil || !validBrokerDesktopName(desktop.Name) {
		closeErr := token.Close()
		if desktop.close != nil {
			closeErr = errors.Join(closeErr, desktop.Close())
		}
		if desktopErr == nil {
			desktopErr = errors.New("windows sandbox: desktop manager returned an invalid desktop")
		}
		return brokerIssuedToken{}, errors.Join(desktopErr, closeErr)
	}
	handle, duplicateErr := token.DuplicateTo(binding)
	closeErr := token.Close()
	if duplicateErr != nil || closeErr != nil || handle == 0 {
		return brokerIssuedToken{}, errors.Join(duplicateErr, closeErr, desktop.Close(), func() error {
			if handle == 0 {
				return errors.New("windows sandbox: invalid duplicated restricted token handle")
			}
			return nil
		}())
	}
	lease.tokenIssued = true
	lease.desktop = &desktop
	return brokerIssuedToken{Handle: handle, Desktop: desktop.Name}, nil
}

func (broker *windowsBroker) release(binding brokerLeaseBinding, id ACLLeaseID) error {
	lease := broker.leases[id]
	if lease == nil {
		return errBrokerLeaseUnavailable
	}
	if !sameBrokerBinding(lease.binding, binding) {
		return errBrokerClientUnauthorized
	}
	return broker.retire(lease)
}

// reconcile must be called with mu held. It rolls back every journaled lease
// whose owner is provably gone and leaves every other one alone:
//
//   - a lease in acquiring belongs to a goroutine that is projecting it right
//     now and is never touched;
//   - a lease in leases belongs to a connection; it is rolled back only when
//     that connection's client process has exited (its retained process
//     handle is signalled). A live, authenticated client's leases are never
//     rolled back by a different connection's reconcile request (review M14);
//     its own Disconnect, or this rule once it dies, retires them;
//   - a quarantined lease is retried;
//   - a lease in the journal and in none of those maps is an orphan of a
//     previous service instance (no connection survives a restart) and is
//     rolled back.
//
// It continues past a lease that cannot be rolled back, quarantining it.
// Passes repeat while any lease is released; with only one-shot SIDs on user
// objects there are no cross-lease identical ACEs to unwind in order, but a
// pass may still free an object a later pass needs (a desktop, a journal
// record), and the loop stops as soon as a pass releases nothing.
func (broker *windowsBroker) reconcile() error {
	recovered, err := broker.journal.recover()
	if err != nil {
		return err
	}
	pending := make(map[ACLLeaseID]*brokerLease, len(recovered))
	for id, record := range recovered {
		if broker.acquiring[id] != nil {
			continue
		}
		if lease := broker.leases[id]; lease != nil {
			if brokerBindingAlive(lease.binding) {
				continue
			}
			pending[id] = lease
			continue
		}
		lease := broker.quarantined[id]
		if lease == nil {
			lease = &brokerLease{id: id, binding: record.Binding, restricting: record.SID, mutations: record.Mutations}
		}
		pending[id] = lease
	}
	// A quarantined lease absent from the journal already has a durable
	// Released record (an ambiguous write that in fact landed), so its
	// rollback had succeeded and nothing remains to retry.
	for id := range broker.quarantined {
		if _, journaled := recovered[id]; !journaled {
			delete(broker.quarantined, id)
		}
	}
	return broker.retireUntilStable(pending)
}

// brokerBindingAlive reports whether a lease's client is still running. Only
// a client whose retained process handle proves it exited counts as dead; a
// process that cannot answer, or whose answer cannot be read, is treated as
// alive, because rolling back a live client's lease would revoke the
// authority its running sandbox was granted. Such a lease is retired by its
// connection's own Disconnect when the pipe closes.
func brokerBindingAlive(binding brokerLeaseBinding) bool {
	liveness, ok := binding.Process.(brokerClientLiveness)
	if !ok {
		return true
	}
	exited, err := liveness.Exited()
	return err != nil || !exited
}

// retryQuarantined retries only the in-memory quarantine. It is cheap enough
// for every status request, which every execution makes before acquiring.
func (broker *windowsBroker) retryQuarantined() error {
	if len(broker.quarantined) == 0 {
		return nil
	}
	pending := make(map[ACLLeaseID]*brokerLease, len(broker.quarantined))
	for id, lease := range broker.quarantined {
		pending[id] = lease
	}
	return broker.retireUntilStable(pending)
}

func (broker *windowsBroker) retireUntilStable(pending map[ACLLeaseID]*brokerLease) error {
	for len(pending) != 0 {
		released := false
		for id, lease := range pending {
			if broker.retire(lease) == nil {
				delete(pending, id)
				released = true
			}
		}
		if !released {
			break
		}
	}
	if len(broker.quarantined) != 0 {
		return fmt.Errorf("%w: %d lease(s) retained for retry", errBrokerLeaseRecoveryPending, len(broker.quarantined))
	}
	return nil
}

// retire must be called with mu held. It rolls a lease back and durably
// records its release. Any failure moves the lease to quarantine instead of
// leaving it in the live set: the broker keeps serving status and release,
// refuses new work, and retries. A successful release may trigger journal
// compaction (review M14); a compaction failure never fails the release.
func (broker *windowsBroker) retire(lease *brokerLease) error {
	err := broker.rollback(lease)
	if err == nil {
		err = broker.writeEvent(lease, brokerLeaseEventReleased, 0, brokerACLMutation{})
	}
	delete(broker.leases, lease.id)
	if err != nil {
		broker.quarantined[lease.id] = lease
		return errors.Join(errBrokerLeaseRecoveryPending, err)
	}
	delete(broker.quarantined, lease.id)
	_ = broker.journal.compactIfLarge()
	return nil
}

// Disconnect is the service-loop hook for pipe EOF, watchdog notification, or
// parent-process death. It releases every lease bound to the exact held-process
// identity; a PID alone is intentionally insufficient cleanup authority.
func (broker *windowsBroker) Disconnect(binding brokerLeaseBinding) error {
	if broker == nil {
		return nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	var result error
	for id, lease := range broker.leases {
		if !sameBrokerBinding(lease.binding, binding) {
			continue
		}
		if err := broker.retire(lease); err != nil {
			result = errors.Join(result, fmt.Errorf("lease %x: %w", id[:], err))
		}
	}
	return result
}

func (broker *windowsBroker) abort(lease *brokerLease, cause error) error {
	return errors.Join(cause, broker.retire(lease))
}

func (broker *windowsBroker) rollback(lease *brokerLease) error {
	var result error
	if lease.desktop != nil {
		if err := lease.desktop.Close(); err != nil {
			result = errors.Join(result, err)
		} else {
			lease.desktop = nil
		}
	}
	for index := len(lease.mutations) - 1; index >= 0; index-- {
		broker.aclMu.Lock()
		err := broker.acl.Rollback(lease.mutations[index])
		broker.aclMu.Unlock()
		result = errors.Join(result, err)
	}
	return result
}

func (broker *windowsBroker) writeEvent(lease *brokerLease, kind brokerLeaseEventKind, mutationID uint32, mutation brokerACLMutation) error {
	return broker.journal.appendAndFlush(brokerLeaseEvent{Kind: kind, LeaseID: lease.id, Nonce: lease.binding.Nonce, PID: lease.binding.PID, Created: lease.binding.CreationTime, SID: lease.restricting, Trustee: mutation.SID, MutationID: mutationID, Object: mutation.Object, ACE: append([]byte(nil), mutation.ACE...), Baseline: mutation.BaselineOccurrences, Path: mutation.Path})
}

func (broker *windowsBroker) nextLeaseID() (ACLLeaseID, error) {
	for attempts := 0; attempts < 4; attempts++ {
		var id ACLLeaseID
		if _, err := io.ReadFull(broker.leaseEntropy, id[:]); err != nil {
			return ACLLeaseID{}, fmt.Errorf("generate broker lease identity: %w", err)
		}
		if id != (ACLLeaseID{}) && broker.leases[id] == nil && broker.acquiring[id] == nil && broker.quarantined[id] == nil {
			return id, nil
		}
	}
	return ACLLeaseID{}, errors.New("windows sandbox: lease identity collision")
}

// allowedMutation admits exactly the lease's own one-shot SID as the trustee.
// The installation SID is deliberately not admitted: it is never projected
// onto a user object (see project).
func (broker *windowsBroker) allowedMutation(mutation brokerACLMutation, authorized brokerAuthorizedObject, restricting SID) bool {
	return mutation.Object == authorized.Identity && mutation.Path == authorized.Reference.Path && canonicalBrokerPath(mutation.Path) &&
		mutation.SID == restricting && mutation.SID != broker.installationSID &&
		brokerReferenceAuthorizesACE(authorized.Reference, mutation.ACE, mutation.SID, authorized.Identity.Kind)
}

func brokerReferenceAuthorizesACE(reference brokerObjectReference, ace []byte, sid SID, kind ACLObjectKind) bool {
	if !brokerAllowACEForSID(ace, sid, kind) {
		return false
	}
	inheritable := reference.Scope == brokerScopeTree
	for _, candidate := range []struct {
		kind   ACEType
		access brokerObjectAccess
	}{
		{ACEAllow, reference.Access},
		{ACEDeny, reference.Denied},
	} {
		axes := []ACLAccess{}
		if candidate.access&brokerAccessRead != 0 {
			axes = append(axes, ACLRead, ACLExecute)
		}
		if candidate.access&brokerAccessWrite != 0 {
			axes = append(axes, ACLWrite)
		}
		for _, axis := range axes {
			if bytes.Equal(ace, encodeACE(sid, kind, ACLACE{Type: candidate.kind, Access: axis, Inheritable: inheritable})) {
				return true
			}
		}
	}
	return false
}

func brokerAllowACEForSID(ace []byte, sid SID, kind ACLObjectKind) bool {
	if len(ace) < 8 || (ace[0] != 0 && ace[0] != 1) || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) || !bytes.Equal(ace[8:], sid.binary()) {
		return false
	}
	for _, aceType := range []ACEType{ACEAllow, ACEDeny} {
		for _, access := range []ACLAccess{ACLRead, ACLExecute, ACLWrite} {
			if bytes.Equal(ace, encodeACE(sid, kind, ACLACE{Type: aceType, Access: access})) {
				return true
			}
			if kind == ACLObjectDirectory && bytes.Equal(ace, encodeACE(sid, kind, ACLACE{Type: aceType, Access: access, Inheritable: true})) {
				return true
			}
		}
	}
	return false
}

func sameBrokerObject(reference brokerObjectReference, authorized brokerAuthorizedObject) bool {
	return authorized.Reference == reference && authorized.Identity.valid() && authorized.Identity.VolumeSerial == reference.VolumeSerial && authorized.Identity.FileID == reference.FileID &&
		((reference.Kind == brokerObjectFile && authorized.Identity.Kind == ACLObjectFile &&
			(authorized.Identity.LinkCount == 1 || (reference.Access == brokerAccessNone && reference.Denied != brokerAccessNone))) ||
			(reference.Kind == brokerObjectDirectory && authorized.Identity.Kind == ACLObjectDirectory))
}

func sameBrokerBinding(left, right brokerLeaseBinding) bool {
	return left.Nonce == right.Nonce && left.PID == right.PID && left.CreationTime == right.CreationTime && left.Process == right.Process
}

func cloneBrokerMutation(mutation brokerACLMutation) brokerACLMutation {
	mutation.ACE = append([]byte(nil), mutation.ACE...)
	return mutation
}

func brokerResultForError(err error) brokerResult {
	switch {
	case err == nil:
		return brokerResultOK
	case errors.Is(err, errBrokerLeaseUnavailable):
		return brokerResultLeaseNotFound
	case errors.Is(err, errBrokerClientUnauthorized), errors.Is(err, errBrokerClientChanged), errors.Is(err, errBrokerLeaseReplay):
		return brokerResultUnauthorized
	case errors.Is(err, errBrokerFrameMalformed):
		return brokerResultInvalidRequest
	case errors.Is(err, errBrokerLeaseRecoveryPending):
		return brokerResultRecoveryPending
	default:
		return brokerResultUnavailable
	}
}
