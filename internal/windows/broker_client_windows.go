//go:build windows

package windows

import "errors"

type brokerFrameTransport interface {
	RoundTrip(brokerFrame) (brokerFrame, error)
}

// brokerClient exposes only Task 13 operations. It does not offer a generic
// frame method, raw-token request, arbitrary ACL operation, or process launch.
type brokerClient struct {
	transport brokerFrameTransport
	nonce     [brokerNonceSize]byte
}

func newBrokerClient(transport brokerFrameTransport, nonce [brokerNonceSize]byte) (*brokerClient, error) {
	if transport == nil || nonce == ([brokerNonceSize]byte{}) {
		return nil, errors.New("windows sandbox: authenticated broker transport is required")
	}
	return &brokerClient{transport: transport, nonce: nonce}, nil
}

func (client *brokerClient) Status() (uint64, error) {
	response, err := client.call(brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: client.nonce})
	return response.Generation, err
}

func (client *brokerClient) AcquireLease(objects []brokerObjectReference) (ACLLeaseID, error) {
	response, err := client.call(brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: client.nonce, Objects: append([]brokerObjectReference(nil), objects...)})
	return ACLLeaseID(response.LeaseID), err
}

func (client *brokerClient) ReleaseLease(id ACLLeaseID) error {
	_, err := client.call(brokerFrame{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: client.nonce, LeaseID: [brokerLeaseIDSize]byte(id)})
	return err
}

func (client *brokerClient) IssueRestrictedToken(id ACLLeaseID, account brokerAccountKind) (uint64, error) {
	response, err := client.call(brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: client.nonce, LeaseID: [brokerLeaseIDSize]byte(id), Account: account})
	return response.TokenHandle, err
}

func (client *brokerClient) Reconcile() (uint64, error) {
	response, err := client.call(brokerFrame{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: client.nonce})
	return response.Generation, err
}

func (client *brokerClient) call(request brokerFrame) (brokerFrame, error) {
	if client == nil || client.transport == nil || validateBrokerFrame(request) != nil {
		return brokerFrame{}, errors.New("windows sandbox: invalid broker client request")
	}
	response, err := client.transport.RoundTrip(request)
	if err != nil {
		return brokerFrame{}, err
	}
	if validateBrokerFrame(response) != nil || response.Direction != brokerResponse || response.Kind != request.Kind || response.Nonce != client.nonce || response.LeaseID != request.LeaseID && request.Kind != brokerMessageAcquireLease {
		return brokerFrame{}, errors.New("windows sandbox: mismatched broker response")
	}
	if response.Result != brokerResultOK {
		return response, brokerClientResultError{result: response.Result}
	}
	return response, nil
}

type brokerClientResultError struct{ result brokerResult }

func (err brokerClientResultError) Error() string { return "windows sandbox: broker request failed" }
