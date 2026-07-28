package windows

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBrokerProtocolRoundTripOperations(t *testing.T) {
	nonce := testBrokerNonce()
	lease := [brokerLeaseIDSize]byte{1, 2, 3}
	object := testBrokerObject()
	tests := []brokerFrame{
		{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: nonce},
		{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: nonce, Objects: []brokerObjectReference{object}},
		{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: nonce, LeaseID: lease},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: nonce, LeaseID: lease, Account: brokerAccountOffline},
		{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: nonce},
		{Kind: brokerMessageStatus, Direction: brokerResponse, Nonce: nonce, Result: brokerResultOK, Generation: 4},
		{Kind: brokerMessageAcquireLease, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, Result: brokerResultOK},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 72, Desktop: `Sandbox-72\Default`, Result: brokerResultOK},
	}
	for _, original := range tests {
		encoded, err := encodeBrokerFrame(original)
		if err != nil {
			t.Fatalf("encode kind %d: %v", original.Kind, err)
		}
		decoded, err := decodeBrokerFrame(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("decode kind %d: %v", original.Kind, err)
		}
		if !reflect.DeepEqual(decoded, original) {
			t.Fatalf("kind %d round trip mismatch\n got: %#v\nwant: %#v", original.Kind, decoded, original)
		}
	}
}

func TestBrokerProtocolRejectsUnknownVersionKindAndEnums(t *testing.T) {
	encoded := mustEncodeBrokerFrame(t, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: testBrokerNonce()})
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(data []byte) { binary.LittleEndian.PutUint16(data[4:6], brokerProtocolVersion+1) }},
		{"kind", func(data []byte) { data[6] = 99 }},
		{"direction", func(data []byte) { data[7] = 99 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), encoded...)
			test.mutate(data)
			if _, err := decodeBrokerFrame(bytes.NewReader(data)); err == nil {
				t.Fatal("invalid enum accepted")
			}
		})
	}
	invalidAccount := brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: testBrokerNonce(), LeaseID: [16]byte{1}, Account: 99}
	if _, err := encodeBrokerFrame(invalidAccount); err == nil {
		t.Fatal("invalid account enum accepted")
	}
}

func TestBrokerProtocolRejectsDuplicateAndUnknownFields(t *testing.T) {
	base := mustEncodeBrokerFrame(t, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: testBrokerNonce()})
	field := append([]byte(nil), base[12:]...)
	duplicate := append(append([]byte(nil), base...), field...)
	binary.LittleEndian.PutUint32(duplicate[:4], uint32(len(duplicate)-4))
	binary.LittleEndian.PutUint16(duplicate[8:10], 2)
	if _, err := decodeBrokerFrame(bytes.NewReader(duplicate)); err == nil || !errors.Is(err, errBrokerFrameMalformed) {
		t.Fatalf("duplicate field error = %v", err)
	}

	unknown := append([]byte(nil), base...)
	binary.LittleEndian.PutUint16(unknown[12:14], 99)
	if _, err := decodeBrokerFrame(bytes.NewReader(unknown)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestBrokerProtocolRejectsMalformedLengthsAndTrailingBytes(t *testing.T) {
	base := mustEncodeBrokerFrame(t, brokerFrame{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: testBrokerNonce()})
	tests := [][]byte{
		base[:len(base)-1],
		append(append([]byte(nil), base...), 0),
		{0xff, 0xff, 0xff, 0x7f},
	}
	for index, data := range tests {
		if index == 1 {
			binary.LittleEndian.PutUint32(data[:4], uint32(len(data)-4))
		}
		if _, err := decodeBrokerFrame(bytes.NewReader(data)); err == nil {
			t.Fatalf("malformed length case %d accepted", index)
		}
	}
}

func TestBrokerProtocolRejectsInvalidUTF16AndPathLimits(t *testing.T) {
	frame := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: testBrokerNonce(), Objects: []brokerObjectReference{testBrokerObject()}}
	encoded := mustEncodeBrokerFrame(t, frame)
	pathBytes := []byte{'C', 0, ':', 0, '\\', 0}
	pathOffset := bytes.Index(encoded, pathBytes)
	if pathOffset < 0 {
		t.Fatal("encoded object path not found")
	}
	binary.LittleEndian.PutUint16(encoded[pathOffset:pathOffset+2], 0xd800)
	if _, err := decodeBrokerFrame(bytes.NewReader(encoded)); err == nil {
		t.Fatal("unpaired UTF-16 surrogate accepted")
	}

	frame.Objects[0].Path = `C:\` + strings.Repeat("x", maxBrokerPathUnits)
	if _, err := encodeBrokerFrame(frame); !errors.Is(err, errBrokerFrameTooLarge) {
		t.Fatalf("oversize path error = %v", err)
	}
}

func TestBrokerProtocolObjectPolicyVocabularyIsClosed(t *testing.T) {
	tests := []func(*brokerObjectReference){
		func(object *brokerObjectReference) { object.Access = 4 },
		func(object *brokerObjectReference) { object.Denied = 4 },
		func(object *brokerObjectReference) { object.Denied = object.Access },
		func(object *brokerObjectReference) { object.Scope = brokerScopeInvalid },
		func(object *brokerObjectReference) { object.Kind, object.Scope = brokerObjectFile, brokerScopeTree },
	}
	for index, mutate := range tests {
		object := testBrokerObject()
		mutate(&object)
		frame := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: testBrokerNonce(), Objects: []brokerObjectReference{object}}
		if _, err := encodeBrokerFrame(frame); err == nil {
			t.Fatalf("invalid broker object policy %d accepted", index)
		}
	}
}

func TestBrokerProtocolRejectsNonCanonicalPathMetadata(t *testing.T) {
	for _, path := range []string{`c:\work\file`, `C:/work/file`, `C:\work\..\file`, `C:\work\\file`, `C:\work\file:stream`, `C:\work\file.`} {
		object := testBrokerObject()
		object.Path = path
		frame := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: testBrokerNonce(), Objects: []brokerObjectReference{object}}
		if _, err := encodeBrokerFrame(frame); err == nil {
			t.Fatalf("non-canonical path %q accepted", path)
		}
	}
}

func TestBrokerProtocolOperationSchemaIsClosed(t *testing.T) {
	nonce := testBrokerNonce()
	lease := [brokerLeaseIDSize]byte{1}
	invalid := []brokerFrame{
		{Kind: brokerMessageStatus, Direction: brokerRequest, Nonce: nonce, LeaseID: lease},
		{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: nonce},
		{Kind: brokerMessageReleaseLease, Direction: brokerRequest, Nonce: nonce},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerRequest, Nonce: nonce, LeaseID: lease},
		{Kind: brokerMessageReconcile, Direction: brokerRequest, Nonce: nonce, TokenHandle: 1},
	}
	for index, frame := range invalid {
		if _, err := encodeBrokerFrame(frame); err == nil {
			t.Fatalf("invalid operation schema %d accepted", index)
		}
	}
}

func TestBrokerProtocolResponseSchemaIsClosed(t *testing.T) {
	nonce := testBrokerNonce()
	lease := [brokerLeaseIDSize]byte{1}
	invalid := []brokerFrame{
		{Kind: brokerMessageStatus, Direction: brokerResponse, Nonce: nonce, TokenHandle: 1},
		{Kind: brokerMessageAcquireLease, Direction: brokerResponse, Nonce: nonce},
		{Kind: brokerMessageAcquireLease, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 1},
		{Kind: brokerMessageReleaseLease, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 1},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 1},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, Desktop: `Sandbox-1\Default`},
		{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 1, Desktop: `WinSta0\Default`},
		{Kind: brokerMessageReconcile, Direction: brokerResponse, Nonce: nonce, LeaseID: lease},
	}
	for index, frame := range invalid {
		if _, err := encodeBrokerFrame(frame); err == nil {
			t.Fatalf("invalid response schema %d accepted", index)
		}
	}
}

func TestBrokerProtocolDesktopNameIsBoundedCanonicalAndOpaque(t *testing.T) {
	nonce := testBrokerNonce()
	lease := [brokerLeaseIDSize]byte{1}
	for _, name := range []string{
		"", `WinSta0\Default`, `winsta0\other`, `one`, `one\two\three`,
		`one/other\two`, `one:\two`, ` one\two`, `one\two `,
		"one\\two\x00", `one\..`, `one\é`,
	} {
		frame := brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 9, Desktop: name}
		if _, err := encodeBrokerFrame(frame); err == nil {
			t.Fatalf("invalid desktop name %q accepted", name)
		}
	}
	oversized := `S\` + strings.Repeat("x", maxBrokerDesktopUnits)
	frame := brokerFrame{Kind: brokerMessageIssueRestrictedToken, Direction: brokerResponse, Nonce: nonce, LeaseID: lease, TokenHandle: 9, Desktop: oversized}
	if _, err := encodeBrokerFrame(frame); err == nil {
		t.Fatal("oversized desktop name accepted")
	}
}

func TestBrokerProtocolCountLimit(t *testing.T) {
	objects := make([]brokerObjectReference, maxBrokerObjects+1)
	for index := range objects {
		objects[index] = testBrokerObject()
	}
	frame := brokerFrame{Kind: brokerMessageAcquireLease, Direction: brokerRequest, Nonce: testBrokerNonce(), Objects: objects}
	if _, err := encodeBrokerFrame(frame); err == nil {
		t.Fatal("object count limit not enforced")
	}
}

func TestEncodeBrokerObjectsEnforcesCountLimitDirectly(t *testing.T) {
	objects := make([]brokerObjectReference, maxBrokerObjects+1)
	for index := range objects {
		objects[index] = testBrokerObject()
	}
	if _, err := encodeBrokerObjects(objects); !errors.Is(err, errBrokerFrameTooLarge) {
		t.Fatalf("direct object encoding error = %v, want frame-too-large", err)
	}
}

func TestEncodeBrokerObjectsEnforcesAggregateFrameLimit(t *testing.T) {
	object := testBrokerObject()
	object.Path = `C:\` + strings.Repeat("x", maxBrokerPathUnits-3)
	objects := make([]brokerObjectReference, 17)
	for index := range objects {
		objects[index] = object
	}
	if _, err := encodeBrokerObjects(objects); !errors.Is(err, errBrokerFrameTooLarge) {
		t.Fatalf("aggregate object encoding error = %v, want frame-too-large", err)
	}
}

func TestWriteBrokerFieldEnforcesWireLengthBoundary(t *testing.T) {
	payload := new(bytes.Buffer)
	if err := writeBrokerField(payload, fieldObjects, make([]byte, maxBrokerFrameSize)); err != nil {
		t.Fatalf("maximum bounded field rejected: %v", err)
	}
	payload.Reset()
	if err := writeBrokerField(payload, fieldObjects, make([]byte, maxBrokerFrameSize+1)); !errors.Is(err, errBrokerFrameTooLarge) {
		t.Fatalf("oversized field error = %v, want frame-too-large", err)
	}
	if payload.Len() != 0 {
		t.Fatalf("oversized field wrote %d bytes before rejection", payload.Len())
	}
}

func mustEncodeBrokerFrame(t *testing.T, frame brokerFrame) []byte {
	t.Helper()
	encoded, err := encodeBrokerFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testBrokerNonce() [brokerNonceSize]byte {
	var nonce [brokerNonceSize]byte
	nonce[0] = 1
	return nonce
}

func testBrokerObject() brokerObjectReference {
	return brokerObjectReference{Handle: 12, Path: `C:\work\file.txt`, VolumeSerial: 9, FileID: [16]byte{4}, Kind: brokerObjectFile, Access: brokerAccessReadWrite, Scope: brokerScopeExact}
}

func TestBrokerObjectAllowsExactDirectoryWithoutInheritance(t *testing.T) {
	object := testBrokerObject()
	object.Kind = brokerObjectDirectory
	object.Scope = brokerScopeExact
	if err := validateBrokerObject(object); err != nil {
		t.Fatalf("exact directory reference rejected: %v", err)
	}
}
