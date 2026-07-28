package windows

import (
	"bytes"
	"testing"
)

func FuzzBrokerFrame(f *testing.F) {
	seeds := []brokerFrame{
		{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: testBrokerNonce()},
		{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: testBrokerNonce(), Objects: []brokerObjectReference{testBrokerObject()}},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: testBrokerNonce(), LeaseID: [16]byte{1}, Account: brokerAccountOnline},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: testBrokerNonce(), LeaseID: [16]byte{1}, TokenHandle: 7, Desktop: `Sandbox-7\Default`, Result: brokerResultOK},
	}
	for _, seed := range seeds {
		encoded, err := encodeBrokerFrame(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxBrokerFrameSize+4 {
			t.Skip()
		}
		frame, err := decodeBrokerFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		encoded, err := encodeBrokerFrame(frame)
		if err != nil {
			t.Fatalf("accepted frame cannot be encoded: %v", err)
		}
		decoded, err := decodeBrokerFrame(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("encoded accepted frame cannot be decoded: %v", err)
		}
		if decoded.Kind != frame.Kind || decoded.Direction != frame.Direction || decoded.Nonce != frame.Nonce {
			t.Fatal("stable fields changed after round trip")
		}
	})
}
