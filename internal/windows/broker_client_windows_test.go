//go:build windows

package windows

import (
	"errors"
	"testing"
)

type brokerTestTransport struct {
	requests []brokerFrame
	respond  func(brokerFrame) (brokerFrame, error)
}

func (transport *brokerTestTransport) RoundTrip(request brokerFrame) (brokerFrame, error) {
	transport.requests = append(transport.requests, request)
	return transport.respond(request)
}

func TestBrokerClientExposesExactOperationFrames(t *testing.T) {
	var nonce [brokerNonceSize]byte
	nonce[0] = 1
	leaseID := ACLLeaseID{2}
	transport := &brokerTestTransport{respond: func(request brokerFrame) (brokerFrame, error) {
		response := brokerFrame{Kind: request.Kind, Direction: brokerResponse, Nonce: request.Nonce, LeaseID: request.LeaseID, Result: brokerResultOK}
		switch request.Kind {
		case brokerMessageStatus, brokerMessageReconcile:
			response.Generation = 4
		case brokerMessageAcquireLease:
			response.LeaseID = [brokerLeaseIDSize]byte(leaseID)
		case brokerMessageIssueRestrictedToken:
			response.TokenHandle = 81
		}
		return response, nil
	}}
	client, err := newBrokerClient(transport, nonce)
	if err != nil {
		t.Fatal(err)
	}
	var fileID [16]byte
	fileID[0] = 3
	object := brokerObjectReference{Handle: 9, Path: `C:\input.txt`, VolumeSerial: 1, FileID: fileID, Kind: brokerObjectFile}
	if generation, err := client.Status(); err != nil || generation != 4 {
		t.Fatalf("status = %d, %v", generation, err)
	}
	if id, err := client.AcquireLease([]brokerObjectReference{object}); err != nil || id != leaseID {
		t.Fatalf("acquire = %v, %v", id, err)
	}
	if handle, err := client.IssueRestrictedToken(leaseID, brokerAccountOffline); err != nil || handle != 81 {
		t.Fatalf("token = %d, %v", handle, err)
	}
	if err := client.ReleaseLease(leaseID); err != nil {
		t.Fatal(err)
	}
	if generation, err := client.Reconcile(); err != nil || generation != 4 {
		t.Fatalf("reconcile = %d, %v", generation, err)
	}
	wantKinds := []brokerMessageKind{brokerMessageStatus, brokerMessageAcquireLease, brokerMessageIssueRestrictedToken, brokerMessageReleaseLease, brokerMessageReconcile}
	if len(transport.requests) != len(wantKinds) {
		t.Fatalf("requests = %#v", transport.requests)
	}
	for index, request := range transport.requests {
		if request.Kind != wantKinds[index] || request.Direction != brokerRequest || request.Nonce != nonce {
			t.Fatalf("request %d = %#v", index, request)
		}
	}
}

func TestBrokerClientRejectsMismatchedOrFailureResponses(t *testing.T) {
	var nonce [brokerNonceSize]byte
	nonce[0] = 1
	tests := []struct {
		name    string
		respond func(brokerFrame) (brokerFrame, error)
	}{
		{name: "transport", respond: func(brokerFrame) (brokerFrame, error) { return brokerFrame{}, errors.New("closed") }},
		{name: "nonce", respond: func(request brokerFrame) (brokerFrame, error) {
			request.Direction = brokerResponse
			request.Nonce[0]++
			return request, nil
		}},
		{name: "kind", respond: func(request brokerFrame) (brokerFrame, error) {
			return brokerFrame{Kind: brokerMessageReconcile, Direction: brokerResponse, Nonce: request.Nonce, Generation: 1}, nil
		}},
		{name: "broker failure", respond: func(request brokerFrame) (brokerFrame, error) {
			return brokerFrame{Kind: request.Kind, Direction: brokerResponse, Nonce: request.Nonce, Result: brokerResultUnauthorized}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newBrokerClient(&brokerTestTransport{respond: test.respond}, nonce)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Status(); err == nil {
				t.Fatal("response accepted")
			}
		})
	}
}
