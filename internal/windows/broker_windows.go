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
)

type brokerConnection interface {
	LeaseBinding() brokerLeaseBinding
	ValidateIdentity() error
	// AuthorizeObject must impersonate the authenticated pipe client and prove
	// that client could change this exact retained object's DACL.
	AuthorizeObject(brokerObjectReference) (brokerAuthorizedObject, error)
}

type brokerAuthorizedObject struct {
	Reference brokerObjectReference
	Identity  ACLObjectIdentity
}

type brokerACLMutation struct {
	Object              ACLObjectIdentity
	SID                 SID
	ACE                 []byte
	BaselineOccurrences uint32
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

type brokerLease struct {
	id          ACLLeaseID
	binding     brokerLeaseBinding
	restricting SID
	mutations   []brokerACLMutation
	tokenIssued bool
}

type windowsBroker struct {
	mu              sync.Mutex
	installationSID SID
	sids            *OneShotSIDGenerator
	leaseEntropy    io.Reader
	journal         *brokerLeaseJournal
	acl             brokerACLMechanism
	tokens          brokerRestrictedTokenIssuer
	leases          map[ACLLeaseID]*brokerLease
	acquiredNonces  map[[brokerNonceSize]byte]struct{}
	generation      uint64
}

func newWindowsBroker(installationSID SID, sids *OneShotSIDGenerator, journal *brokerLeaseJournal, acl brokerACLMechanism, tokens brokerRestrictedTokenIssuer, leaseEntropy io.Reader) (*windowsBroker, error) {
	if installationSID.kind != sidKindInstallation || !installationSID.isModuleTrustee() || sids == nil || journal == nil || acl == nil || tokens == nil {
		return nil, errors.New("windows sandbox: incomplete broker dependencies")
	}
	if leaseEntropy == nil {
		leaseEntropy = rand.Reader
	}
	broker := &windowsBroker{installationSID: installationSID, sids: sids, leaseEntropy: leaseEntropy, journal: journal, acl: acl, tokens: tokens, leases: make(map[ACLLeaseID]*brokerLease), acquiredNonces: make(map[[brokerNonceSize]byte]struct{})}
	// Reconciliation is a constructor invariant: no status or token operation
	// can be served by an instance that has not resolved its durable cleanup log.
	if err := broker.reconcile(); err != nil {
		return nil, fmt.Errorf("reconcile broker leases at startup: %w", err)
	}
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

	broker.mu.Lock()
	defer broker.mu.Unlock()
	var err error
	switch request.Kind {
	case brokerMessageStatus:
		broker.generation++
		response.Generation = broker.generation
	case brokerMessageAcquireLease:
		response.LeaseID, err = broker.acquire(connection, request.Objects)
	case brokerMessageReleaseLease:
		err = broker.release(binding, ACLLeaseID(request.LeaseID))
	case brokerMessageIssueRestrictedToken:
		response.TokenHandle, err = broker.issueToken(binding, ACLLeaseID(request.LeaseID), request.Account)
	case brokerMessageReconcile:
		err = broker.reconcile()
		broker.generation++
		response.Generation = broker.generation
	default:
		err = errBrokerFrameMalformed
	}
	response.Result = brokerResultForError(err)
	if response.Result != brokerResultOK {
		response.TokenHandle = 0
		if request.Kind == brokerMessageAcquireLease {
			response.LeaseID = [brokerLeaseIDSize]byte{}
		}
	}
	return response
}

func (broker *windowsBroker) acquire(connection brokerConnection, references []brokerObjectReference) (ACLLeaseID, error) {
	binding := connection.LeaseBinding()
	if _, replayed := broker.acquiredNonces[binding.Nonce]; replayed {
		return ACLLeaseID{}, errBrokerLeaseReplay
	}
	broker.acquiredNonces[binding.Nonce] = struct{}{}
	leaseID, err := broker.nextLeaseID()
	if err != nil {
		return ACLLeaseID{}, err
	}
	restricting, err := broker.sids.Next()
	if err != nil {
		return ACLLeaseID{}, err
	}
	lease := &brokerLease{id: leaseID, binding: binding, restricting: restricting}
	if err := broker.writeEvent(lease, brokerLeaseEventReserved, 0, brokerACLMutation{}); err != nil {
		return ACLLeaseID{}, err
	}

	seenObjects := make(map[ACLObjectIdentity]struct{}, len(references))
	seenMutations := make(map[string]struct{})
	for _, reference := range references {
		if err := connection.ValidateIdentity(); err != nil {
			return ACLLeaseID{}, broker.abort(lease, err)
		}
		authorized, err := connection.AuthorizeObject(reference)
		if err != nil || !sameBrokerObject(reference, authorized) {
			return ACLLeaseID{}, broker.abort(lease, errors.Join(errBrokerClientUnauthorized, err))
		}
		if _, duplicate := seenObjects[authorized.Identity]; duplicate {
			return ACLLeaseID{}, broker.abort(lease, errBrokerClientUnauthorized)
		}
		seenObjects[authorized.Identity] = struct{}{}
		mutations, err := broker.acl.Plan(authorized, []SID{broker.installationSID, restricting})
		if err != nil {
			return ACLLeaseID{}, broker.abort(lease, err)
		}
		if len(mutations) == 0 {
			return ACLLeaseID{}, broker.abort(lease, errors.New("windows sandbox: ACL plan contained no mutations"))
		}
		for _, mutation := range mutations {
			if !broker.allowedMutation(mutation, authorized.Identity, restricting) {
				return ACLLeaseID{}, broker.abort(lease, errBrokerClientUnauthorized)
			}
			signature := fmt.Sprintf("%#v/%s/%x", mutation.Object, mutation.SID.String(), mutation.ACE)
			if _, duplicate := seenMutations[signature]; duplicate {
				return ACLLeaseID{}, broker.abort(lease, errBrokerClientUnauthorized)
			}
			seenMutations[signature] = struct{}{}
			mutationID := uint32(len(lease.mutations))
			if err := broker.writeEvent(lease, brokerLeaseEventMutationPrepared, mutationID, mutation); err != nil {
				return ACLLeaseID{}, broker.abort(lease, err)
			}
			// Record ownership before Apply: rollback must include a mutation even
			// when the mechanism reports an ambiguous post-write error.
			lease.mutations = append(lease.mutations, cloneBrokerMutation(mutation))
			if err := broker.acl.Apply(mutation); err != nil {
				return ACLLeaseID{}, broker.abort(lease, err)
			}
		}
	}
	if err := connection.ValidateIdentity(); err != nil {
		return ACLLeaseID{}, broker.abort(lease, err)
	}
	if err := broker.writeEvent(lease, brokerLeaseEventActive, 0, brokerACLMutation{}); err != nil {
		return ACLLeaseID{}, broker.abort(lease, err)
	}
	broker.leases[leaseID] = lease
	return leaseID, nil
}

func (broker *windowsBroker) issueToken(binding brokerLeaseBinding, id ACLLeaseID, account brokerAccountKind) (uint64, error) {
	lease := broker.leases[id]
	if lease == nil {
		return 0, errBrokerLeaseUnavailable
	}
	if !sameBrokerBinding(lease.binding, binding) || lease.tokenIssued || (account != brokerAccountOffline && account != brokerAccountOnline) {
		return 0, errBrokerClientUnauthorized
	}
	token, err := broker.tokens.IssueRestricted(account, broker.installationSID, lease.restricting)
	if err != nil {
		return 0, err
	}
	handle, duplicateErr := token.DuplicateTo(binding)
	closeErr := token.Close()
	if duplicateErr != nil || closeErr != nil || handle == 0 {
		return 0, errors.Join(duplicateErr, closeErr, func() error {
			if handle == 0 {
				return errors.New("windows sandbox: invalid duplicated restricted token handle")
			}
			return nil
		}())
	}
	lease.tokenIssued = true
	return handle, nil
}

func (broker *windowsBroker) release(binding brokerLeaseBinding, id ACLLeaseID) error {
	lease := broker.leases[id]
	if lease == nil {
		return errBrokerLeaseUnavailable
	}
	if !sameBrokerBinding(lease.binding, binding) {
		return errBrokerClientUnauthorized
	}
	if err := broker.rollback(lease); err != nil {
		return err
	}
	if err := broker.writeEvent(lease, brokerLeaseEventReleased, 0, brokerACLMutation{}); err != nil {
		return err
	}
	delete(broker.leases, id)
	return nil
}

func (broker *windowsBroker) reconcile() error {
	recovered, err := broker.journal.recover()
	if err != nil {
		return err
	}
	for id, record := range recovered {
		lease := &brokerLease{id: id, binding: record.Binding, restricting: record.SID, mutations: record.Mutations}
		if err := broker.rollback(lease); err != nil {
			return err
		}
		if err := broker.writeEvent(lease, brokerLeaseEventReleased, 0, brokerACLMutation{}); err != nil {
			return err
		}
		delete(broker.leases, id)
	}
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
		if err := broker.rollback(lease); err != nil {
			result = errors.Join(result, err)
			continue
		}
		if err := broker.writeEvent(lease, brokerLeaseEventReleased, 0, brokerACLMutation{}); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(broker.leases, id)
	}
	return result
}

func (broker *windowsBroker) abort(lease *brokerLease, cause error) error {
	rollbackErr := broker.rollback(lease)
	if rollbackErr == nil {
		rollbackErr = broker.writeEvent(lease, brokerLeaseEventReleased, 0, brokerACLMutation{})
	}
	return errors.Join(cause, rollbackErr)
}

func (broker *windowsBroker) rollback(lease *brokerLease) error {
	var result error
	for index := len(lease.mutations) - 1; index >= 0; index-- {
		result = errors.Join(result, broker.acl.Rollback(lease.mutations[index]))
	}
	return result
}

func (broker *windowsBroker) writeEvent(lease *brokerLease, kind brokerLeaseEventKind, mutationID uint32, mutation brokerACLMutation) error {
	return broker.journal.appendAndFlush(brokerLeaseEvent{Kind: kind, LeaseID: lease.id, Nonce: lease.binding.Nonce, PID: lease.binding.PID, Created: lease.binding.CreationTime, SID: lease.restricting, Trustee: mutation.SID, MutationID: mutationID, Object: mutation.Object, ACE: append([]byte(nil), mutation.ACE...), Baseline: mutation.BaselineOccurrences})
}

func (broker *windowsBroker) nextLeaseID() (ACLLeaseID, error) {
	for attempts := 0; attempts < 4; attempts++ {
		var id ACLLeaseID
		if _, err := io.ReadFull(broker.leaseEntropy, id[:]); err != nil {
			return ACLLeaseID{}, fmt.Errorf("generate broker lease identity: %w", err)
		}
		if id != (ACLLeaseID{}) && broker.leases[id] == nil {
			return id, nil
		}
	}
	return ACLLeaseID{}, errors.New("windows sandbox: lease identity collision")
}

func (broker *windowsBroker) allowedMutation(mutation brokerACLMutation, object ACLObjectIdentity, restricting SID) bool {
	return mutation.Object == object && (mutation.SID == broker.installationSID || mutation.SID == restricting) && brokerAllowACEForSID(mutation.ACE, mutation.SID, object.Kind)
}

func brokerAllowACEForSID(ace []byte, sid SID, kind ACLObjectKind) bool {
	if len(ace) < 8 || ace[0] != 0 || int(binary.LittleEndian.Uint16(ace[2:4])) != len(ace) || !bytes.Equal(ace[8:], sid.binary()) {
		return false
	}
	for _, access := range []ACLAccess{ACLRead, ACLExecute, ACLWrite} {
		if bytes.Equal(ace, encodeACE(sid, kind, ACLACE{Type: ACEAllow, Access: access})) {
			return true
		}
		if kind == ACLObjectDirectory && bytes.Equal(ace, encodeACE(sid, kind, ACLACE{Type: ACEAllow, Access: access, Inheritable: true})) {
			return true
		}
	}
	return false
}

func sameBrokerObject(reference brokerObjectReference, authorized brokerAuthorizedObject) bool {
	return authorized.Reference == reference && authorized.Identity.valid() && authorized.Identity.VolumeSerial == reference.VolumeSerial && authorized.Identity.FileID == reference.FileID && ((reference.Kind == brokerObjectFile && authorized.Identity.Kind == ACLObjectFile) || (reference.Kind == brokerObjectDirectory && authorized.Identity.Kind == ACLObjectDirectory))
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
	default:
		return brokerResultUnavailable
	}
}
