//go:build windows

package windows

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const brokerGreetingSize = 8 + 2 + 2 + brokerNonceSize

var brokerGreetingMagic = [8]byte{'L', 'S', 'B', 'R', 'O', 'K', 'E', 'R'}

type brokerFrameTransport interface {
	RoundTrip(brokerFrame) (brokerFrame, error)
}

// brokerClient exposes only Task 13 operations. It does not offer a generic
// frame method, raw-token request, arbitrary ACL operation, or process launch.
type brokerClient struct {
	transport brokerFrameTransport
	nonce     [brokerNonceSize]byte
}

// writeBrokerGreeting transfers the service-selected connection nonce only
// after the server has authenticated the kernel-reported pipe client. It is
// deliberately not a broker frame: no unauthenticated request can choose or
// reflect the nonce.
func writeBrokerGreeting(writer io.Writer, nonce [brokerNonceSize]byte) error {
	if writer == nil || nonce == ([brokerNonceSize]byte{}) {
		return errors.New("windows sandbox: invalid broker greeting")
	}
	var greeting [brokerGreetingSize]byte
	copy(greeting[:8], brokerGreetingMagic[:])
	binary.LittleEndian.PutUint16(greeting[8:10], brokerProtocolVersion)
	copy(greeting[12:], nonce[:])
	if err := writeBrokerFrame(writer, greeting[:]); err != nil {
		return fmt.Errorf("write authenticated broker greeting: %w", err)
	}
	return nil
}

func readBrokerGreeting(reader io.Reader) ([brokerNonceSize]byte, error) {
	var nonce [brokerNonceSize]byte
	if reader == nil {
		return nonce, errors.New("windows sandbox: authenticated broker greeting is required")
	}
	var greeting [brokerGreetingSize]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil {
		return nonce, fmt.Errorf("read authenticated broker greeting: %w", err)
	}
	if !bytes.Equal(greeting[:8], brokerGreetingMagic[:]) ||
		binary.LittleEndian.Uint16(greeting[8:10]) != brokerProtocolVersion ||
		binary.LittleEndian.Uint16(greeting[10:12]) != 0 {
		return nonce, errors.New("windows sandbox: invalid broker greeting")
	}
	copy(nonce[:], greeting[12:])
	if nonce == ([brokerNonceSize]byte{}) {
		return nonce, errors.New("windows sandbox: empty broker greeting nonce")
	}
	return nonce, nil
}

func newBrokerClientFromAuthenticatedStream(stream brokerFrameStream) (*brokerClient, *pipeBrokerFrameTransport, error) {
	if stream == nil {
		return nil, nil, errors.New("windows sandbox: authenticated broker stream is required")
	}
	nonce, err := readBrokerGreeting(stream)
	if err != nil {
		_ = stream.Close()
		return nil, nil, err
	}
	transport := &pipeBrokerFrameTransport{stream: stream}
	client, err := newBrokerClient(transport, nonce)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return client, transport, nil
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
