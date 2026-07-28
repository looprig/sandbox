package windows

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	// Version 1 has not shipped. Adding the broker-selected desktop to its
	// token response completes v1 rather than changing a released contract.
	brokerProtocolVersion uint16 = 1
	maxBrokerFrameSize           = 1 << 20
	maxBrokerPathUnits           = 32767
	maxBrokerObjects             = 4096
	maxBrokerDesktopUnits        = 255
	maxBrokerFields              = 8
	brokerNonceSize              = 32
	brokerLeaseIDSize            = 16
	brokerHeaderSize             = 8
)

var (
	errBrokerFrameMalformed = errors.New("windows sandbox: malformed broker frame")
	errBrokerFrameTooLarge  = errors.New("windows sandbox: broker frame exceeds size limit")
	errBrokerVersion        = errors.New("windows sandbox: unsupported broker protocol version")
)

type brokerMessageKind uint8

const (
	brokerMessageInvalid brokerMessageKind = iota
	brokerMessageStatus
	brokerMessageAcquireLease
	brokerMessageReleaseLease
	brokerMessageIssueRestrictedToken
	brokerMessageReconcile
)

func (kind brokerMessageKind) valid() bool {
	return kind >= brokerMessageStatus && kind <= brokerMessageReconcile
}

type brokerDirection uint8

const (
	brokerRequest brokerDirection = iota
	brokerResponse
)

type brokerAccountKind uint8

const (
	brokerAccountUnspecified brokerAccountKind = iota
	brokerAccountOffline
	brokerAccountOnline
)

type brokerObjectKind uint8

const (
	brokerObjectUnknown brokerObjectKind = iota
	brokerObjectFile
	brokerObjectDirectory
)

// brokerObjectAccess is deliberately not a Windows access mask.
type brokerObjectAccess uint8

const (
	brokerAccessNone brokerObjectAccess = iota
	brokerAccessRead
	brokerAccessWrite
	brokerAccessReadWrite
)

type brokerObjectScope uint8

const (
	brokerScopeInvalid brokerObjectScope = iota
	brokerScopeExact
	brokerScopeTree
)

type brokerResult uint16

const (
	brokerResultOK brokerResult = iota
	brokerResultInvalidRequest
	brokerResultUnauthorized
	brokerResultLeaseNotFound
	brokerResultUnavailable
)

// brokerObjectReference transports only a duplicated object handle and the
// metadata needed to check that handle. The path is never authority by itself.
type brokerObjectReference struct {
	Handle       uint64
	Path         string
	VolumeSerial uint64
	FileID       [16]byte
	Kind         brokerObjectKind
	Access       brokerObjectAccess
	Denied       brokerObjectAccess
	Scope        brokerObjectScope
}

// brokerFrame is the complete v1 protocol vocabulary. Operation-specific
// validation keeps the codec closed: adding a field or operation requires a
// protocol version change or an explicitly reviewed compatible extension.
type brokerFrame struct {
	Kind        brokerMessageKind
	Direction   brokerDirection
	Nonce       [brokerNonceSize]byte
	LeaseID     [brokerLeaseIDSize]byte
	Account     brokerAccountKind
	Objects     []brokerObjectReference
	TokenHandle uint64
	Desktop     string
	Result      brokerResult
	Generation  uint64
}

const (
	fieldNonce uint16 = iota + 1
	fieldLeaseID
	fieldAccount
	fieldObjects
	fieldTokenHandle
	fieldResult
	fieldGeneration
	fieldDesktop
)

func encodeBrokerFrame(frame brokerFrame) ([]byte, error) {
	if err := validateBrokerFrame(frame); err != nil {
		return nil, err
	}
	payload := new(bytes.Buffer)
	if err := writeBrokerField(payload, fieldNonce, frame.Nonce[:]); err != nil {
		return nil, err
	}
	if frame.LeaseID != ([brokerLeaseIDSize]byte{}) {
		if err := writeBrokerField(payload, fieldLeaseID, frame.LeaseID[:]); err != nil {
			return nil, err
		}
	}
	if frame.Account != brokerAccountUnspecified {
		if err := writeBrokerField(payload, fieldAccount, []byte{byte(frame.Account)}); err != nil {
			return nil, err
		}
	}
	if len(frame.Objects) != 0 {
		objects, err := encodeBrokerObjects(frame.Objects)
		if err != nil {
			return nil, err
		}
		if err := writeBrokerField(payload, fieldObjects, objects); err != nil {
			return nil, err
		}
	}
	if frame.TokenHandle != 0 {
		if err := writeBrokerField(payload, fieldTokenHandle, uint64Bytes(frame.TokenHandle)); err != nil {
			return nil, err
		}
	}
	if frame.Desktop != "" {
		if err := writeBrokerField(payload, fieldDesktop, encodeBrokerUTF16(frame.Desktop)); err != nil {
			return nil, err
		}
	}
	if frame.Direction == brokerResponse {
		if err := writeBrokerField(payload, fieldResult, uint16Bytes(uint16(frame.Result))); err != nil {
			return nil, err
		}
	}
	if frame.Generation != 0 {
		if err := writeBrokerField(payload, fieldGeneration, uint64Bytes(frame.Generation)); err != nil {
			return nil, err
		}
	}

	frameSize := brokerHeaderSize + payload.Len()
	if frameSize > maxBrokerFrameSize {
		return nil, errBrokerFrameTooLarge
	}
	result := new(bytes.Buffer)
	// #nosec G115 -- frameSize is checked against the 1 MiB protocol maximum above.
	_ = binary.Write(result, binary.LittleEndian, uint32(frameSize))
	_ = binary.Write(result, binary.LittleEndian, brokerProtocolVersion)
	_ = result.WriteByte(byte(frame.Kind))
	_ = result.WriteByte(byte(frame.Direction))
	fieldCount := payloadFieldCount(payload.Bytes())
	if fieldCount > maxBrokerFields {
		return nil, errBrokerFrameMalformed
	}
	// #nosec G115 -- the closed v1 vocabulary is capped at maxBrokerFields.
	_ = binary.Write(result, binary.LittleEndian, uint16(fieldCount))
	_ = binary.Write(result, binary.LittleEndian, uint16(0))
	_, _ = result.Write(payload.Bytes())
	return result.Bytes(), nil
}

func writeBrokerField(payload *bytes.Buffer, id uint16, value []byte) error {
	remaining := maxBrokerFrameSize - brokerHeaderSize - payload.Len()
	if remaining < 6 || len(value) > remaining-6 {
		return errBrokerFrameTooLarge
	}
	_ = binary.Write(payload, binary.LittleEndian, id)
	// #nosec G115 -- value is explicitly capped at the remaining frame capacity above.
	_ = binary.Write(payload, binary.LittleEndian, uint32(len(value)))
	_, _ = payload.Write(value)
	return nil
}

func validateBrokerFieldCount(count int) error {
	if count < 0 || count > maxBrokerFields {
		return errBrokerFrameMalformed
	}
	return nil
}

func brokerUTF16BytesMayFit(value string, maxUnits int) bool {
	if maxUnits < 0 || maxUnits > maxBrokerPathUnits || !utf8.ValidString(value) {
		return false
	}
	// A valid UTF-8 encoding uses at most three bytes per UTF-16 code unit:
	// three-byte BMP runes use one unit, while four-byte runes use two.
	return len(value) <= maxUnits*3
}

func decodeBrokerFrame(reader io.Reader) (brokerFrame, error) {
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return brokerFrame{}, fmt.Errorf("%w: read length: %v", errBrokerFrameMalformed, err)
	}
	if length < brokerHeaderSize || length > maxBrokerFrameSize {
		return brokerFrame{}, errBrokerFrameTooLarge
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return brokerFrame{}, fmt.Errorf("%w: truncated body", errBrokerFrameMalformed)
	}
	return decodeBrokerFrameBody(data)
}

func decodeBrokerFrameBody(data []byte) (brokerFrame, error) {
	if len(data) < brokerHeaderSize {
		return brokerFrame{}, errBrokerFrameMalformed
	}
	version := binary.LittleEndian.Uint16(data[0:2])
	if version != brokerProtocolVersion {
		return brokerFrame{}, errBrokerVersion
	}
	frame := brokerFrame{Kind: brokerMessageKind(data[2]), Direction: brokerDirection(data[3])}
	if !frame.Kind.valid() || frame.Direction > brokerResponse || binary.LittleEndian.Uint16(data[6:8]) != 0 {
		return brokerFrame{}, errBrokerFrameMalformed
	}
	fieldCount := int(binary.LittleEndian.Uint16(data[4:6]))
	if err := validateBrokerFieldCount(fieldCount); err != nil {
		return brokerFrame{}, err
	}
	offset := brokerHeaderSize
	seen := make(map[uint16]struct{}, fieldCount)
	for index := 0; index < fieldCount; index++ {
		if len(data)-offset < 6 {
			return brokerFrame{}, errBrokerFrameMalformed
		}
		id := binary.LittleEndian.Uint16(data[offset : offset+2])
		size := int(binary.LittleEndian.Uint32(data[offset+2 : offset+6]))
		offset += 6
		if _, duplicate := seen[id]; duplicate {
			return brokerFrame{}, fmt.Errorf("%w: duplicate field %d", errBrokerFrameMalformed, id)
		}
		seen[id] = struct{}{}
		if size < 0 || size > len(data)-offset {
			return brokerFrame{}, errBrokerFrameMalformed
		}
		value := data[offset : offset+size]
		offset += size
		if err := decodeBrokerField(&frame, id, value); err != nil {
			return brokerFrame{}, err
		}
	}
	if offset != len(data) {
		return brokerFrame{}, fmt.Errorf("%w: trailing bytes", errBrokerFrameMalformed)
	}
	if err := validateBrokerFrame(frame); err != nil {
		return brokerFrame{}, err
	}
	return frame, nil
}

func decodeBrokerField(frame *brokerFrame, id uint16, value []byte) error {
	switch id {
	case fieldNonce:
		if len(value) != brokerNonceSize {
			return errBrokerFrameMalformed
		}
		copy(frame.Nonce[:], value)
	case fieldLeaseID:
		if len(value) != brokerLeaseIDSize {
			return errBrokerFrameMalformed
		}
		copy(frame.LeaseID[:], value)
	case fieldAccount:
		if len(value) != 1 {
			return errBrokerFrameMalformed
		}
		frame.Account = brokerAccountKind(value[0])
	case fieldObjects:
		objects, err := decodeBrokerObjects(value)
		if err != nil {
			return err
		}
		frame.Objects = objects
	case fieldTokenHandle:
		if len(value) != 8 {
			return errBrokerFrameMalformed
		}
		frame.TokenHandle = binary.LittleEndian.Uint64(value)
	case fieldResult:
		if len(value) != 2 {
			return errBrokerFrameMalformed
		}
		frame.Result = brokerResult(binary.LittleEndian.Uint16(value))
	case fieldGeneration:
		if len(value) != 8 {
			return errBrokerFrameMalformed
		}
		frame.Generation = binary.LittleEndian.Uint64(value)
	case fieldDesktop:
		units, err := decodeBrokerUTF16(value, maxBrokerDesktopUnits)
		if err != nil {
			return err
		}
		frame.Desktop = string(utf16.Decode(units))
	default:
		return fmt.Errorf("%w: unknown field %d", errBrokerFrameMalformed, id)
	}
	return nil
}

func validateBrokerFrame(frame brokerFrame) error {
	if !frame.Kind.valid() || frame.Direction > brokerResponse || frame.Nonce == ([brokerNonceSize]byte{}) {
		return errBrokerFrameMalformed
	}
	if frame.Account > brokerAccountOnline || frame.Result > brokerResultUnavailable || len(frame.Objects) > maxBrokerObjects {
		return errBrokerFrameMalformed
	}
	for _, object := range frame.Objects {
		if err := validateBrokerObject(object); err != nil {
			return err
		}
	}
	hasLease := frame.LeaseID != ([brokerLeaseIDSize]byte{})
	if frame.Direction == brokerRequest {
		if frame.Result != brokerResultOK || frame.TokenHandle != 0 || frame.Desktop != "" || frame.Generation != 0 {
			return errBrokerFrameMalformed
		}
		switch frame.Kind {
		case brokerMessageStatus, brokerMessageReconcile:
			if hasLease || frame.Account != brokerAccountUnspecified || len(frame.Objects) != 0 {
				return errBrokerFrameMalformed
			}
		case brokerMessageAcquireLease:
			if hasLease || frame.Account != brokerAccountUnspecified || len(frame.Objects) == 0 {
				return errBrokerFrameMalformed
			}
		case brokerMessageReleaseLease:
			if !hasLease || frame.Account != brokerAccountUnspecified || len(frame.Objects) != 0 {
				return errBrokerFrameMalformed
			}
		case brokerMessageIssueRestrictedToken:
			if !hasLease || (frame.Account != brokerAccountOffline && frame.Account != brokerAccountOnline) || len(frame.Objects) != 0 {
				return errBrokerFrameMalformed
			}
		}
	} else {
		if len(frame.Objects) != 0 || frame.Account != brokerAccountUnspecified {
			return errBrokerFrameMalformed
		}
		switch frame.Kind {
		case brokerMessageStatus:
			if hasLease || frame.TokenHandle != 0 || frame.Desktop != "" {
				return errBrokerFrameMalformed
			}
		case brokerMessageAcquireLease:
			if frame.TokenHandle != 0 || frame.Desktop != "" || frame.Generation != 0 || (frame.Result == brokerResultOK) != hasLease {
				return errBrokerFrameMalformed
			}
		case brokerMessageReleaseLease:
			if !hasLease || frame.TokenHandle != 0 || frame.Desktop != "" || frame.Generation != 0 {
				return errBrokerFrameMalformed
			}
		case brokerMessageIssueRestrictedToken:
			hasTokenAndDesktop := frame.TokenHandle != 0 && validBrokerDesktopName(frame.Desktop)
			if !hasLease || frame.Generation != 0 || (frame.Result == brokerResultOK) != hasTokenAndDesktop ||
				(frame.Result != brokerResultOK && (frame.TokenHandle != 0 || frame.Desktop != "")) {
				return errBrokerFrameMalformed
			}
		case brokerMessageReconcile:
			if hasLease || frame.TokenHandle != 0 || frame.Desktop != "" {
				return errBrokerFrameMalformed
			}
		}
	}
	return nil
}

func validBrokerDesktopName(value string) bool {
	if value == "" || !brokerUTF16BytesMayFit(value, maxBrokerDesktopUnits) || strings.EqualFold(value, `WinSta0\Default`) {
		return false
	}
	units := utf16.Encode([]rune(value))
	if len(units) == 0 || len(units) > maxBrokerDesktopUnits {
		return false
	}
	parts := strings.Split(value, `\`)
	if len(parts) != 2 || strings.EqualFold(parts[0], "WinSta0") {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
				(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}
	return true
}

func encodeBrokerUTF16(value string) []byte {
	units := utf16.Encode([]rune(value))
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return encoded
}

func decodeBrokerUTF16(value []byte, maxUnits int) ([]uint16, error) {
	if len(value) == 0 || len(value)%2 != 0 || len(value)/2 > maxUnits {
		return nil, errBrokerFrameMalformed
	}
	units := make([]uint16, len(value)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(value[index*2:])
	}
	if !validUTF16(units) {
		return nil, errBrokerFrameMalformed
	}
	return units, nil
}

func validateBrokerObject(object brokerObjectReference) error {
	if object.Handle == 0 || (object.Kind != brokerObjectFile && object.Kind != brokerObjectDirectory) || object.VolumeSerial == 0 || object.FileID == ([16]byte{}) {
		return errBrokerFrameMalformed
	}
	if object.Access > brokerAccessReadWrite || object.Denied > brokerAccessReadWrite ||
		(object.Access == brokerAccessNone && object.Denied == brokerAccessNone) ||
		object.Access&object.Denied != 0 ||
		(object.Kind == brokerObjectFile && object.Scope != brokerScopeExact) ||
		(object.Kind == brokerObjectDirectory && object.Scope != brokerScopeExact && object.Scope != brokerScopeTree) {
		return errBrokerFrameMalformed
	}
	if !utf8.ValidString(object.Path) {
		return errBrokerFrameMalformed
	}
	if !brokerUTF16BytesMayFit(object.Path, maxBrokerPathUnits) {
		return errBrokerFrameTooLarge
	}
	if !canonicalBrokerPath(object.Path) {
		return errBrokerFrameMalformed
	}
	units := utf16.Encode([]rune(object.Path))
	if len(units) > maxBrokerPathUnits {
		return errBrokerFrameTooLarge
	}
	for _, unit := range units {
		if unit == 0 {
			return errBrokerFrameMalformed
		}
	}
	return nil
}

func canonicalBrokerPath(path string) bool {
	if len(path) < 3 || path[0] < 'A' || path[0] > 'Z' || path[1:3] != `:\` || strings.Contains(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return false
	}
	if len(path) == 3 {
		return true
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" || component == "." || component == ".." || strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") || strings.Contains(component, ":") {
			return false
		}
	}
	return true
}

func encodeBrokerObjects(objects []brokerObjectReference) ([]byte, error) {
	if len(objects) > maxBrokerObjects {
		return nil, errBrokerFrameTooLarge
	}
	buffer := new(bytes.Buffer)
	// #nosec G115 -- object count is explicitly capped at maxBrokerObjects above.
	_ = binary.Write(buffer, binary.LittleEndian, uint16(len(objects)))
	for _, object := range objects {
		if err := validateBrokerObject(object); err != nil {
			return nil, err
		}
		units := utf16.Encode([]rune(object.Path))
		encodedObjectSize := 38 + len(units)*2
		if encodedObjectSize > maxBrokerFrameSize-buffer.Len() {
			return nil, errBrokerFrameTooLarge
		}
		_ = binary.Write(buffer, binary.LittleEndian, object.Handle)
		_ = binary.Write(buffer, binary.LittleEndian, object.VolumeSerial)
		_, _ = buffer.Write(object.FileID[:])
		_ = buffer.WriteByte(byte(object.Kind))
		_ = buffer.WriteByte(byte(object.Access))
		_ = buffer.WriteByte(byte(object.Denied))
		_ = buffer.WriteByte(byte(object.Scope))
		// #nosec G115 -- validateBrokerObject caps the encoded path at maxBrokerPathUnits.
		_ = binary.Write(buffer, binary.LittleEndian, uint16(len(units)))
		for _, unit := range units {
			_ = binary.Write(buffer, binary.LittleEndian, unit)
		}
	}
	return buffer.Bytes(), nil
}

func decodeBrokerObjects(data []byte) ([]brokerObjectReference, error) {
	if len(data) < 2 {
		return nil, errBrokerFrameMalformed
	}
	count := int(binary.LittleEndian.Uint16(data[:2]))
	if count == 0 || count > maxBrokerObjects {
		return nil, errBrokerFrameMalformed
	}
	offset := 2
	objects := make([]brokerObjectReference, 0, count)
	for range count {
		if len(data)-offset < 38 {
			return nil, errBrokerFrameMalformed
		}
		object := brokerObjectReference{
			Handle:       binary.LittleEndian.Uint64(data[offset : offset+8]),
			VolumeSerial: binary.LittleEndian.Uint64(data[offset+8 : offset+16]),
			Kind:         brokerObjectKind(data[offset+32]),
			Access:       brokerObjectAccess(data[offset+33]),
			Denied:       brokerObjectAccess(data[offset+34]),
			Scope:        brokerObjectScope(data[offset+35]),
		}
		copy(object.FileID[:], data[offset+16:offset+32])
		unitsCount := int(binary.LittleEndian.Uint16(data[offset+36 : offset+38]))
		offset += 38
		if unitsCount == 0 || unitsCount > maxBrokerPathUnits || unitsCount > (len(data)-offset)/2 {
			return nil, errBrokerFrameMalformed
		}
		units := make([]uint16, unitsCount)
		for index := range units {
			units[index] = binary.LittleEndian.Uint16(data[offset+index*2 : offset+index*2+2])
		}
		offset += unitsCount * 2
		if !validUTF16(units) {
			return nil, errBrokerFrameMalformed
		}
		object.Path = string(utf16.Decode(units))
		if err := validateBrokerObject(object); err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	if offset != len(data) {
		return nil, errBrokerFrameMalformed
	}
	return objects, nil
}

func validUTF16(units []uint16) bool {
	for index := 0; index < len(units); index++ {
		switch {
		case units[index] >= 0xd800 && units[index] <= 0xdbff:
			if index+1 >= len(units) || units[index+1] < 0xdc00 || units[index+1] > 0xdfff {
				return false
			}
			index++
		case units[index] >= 0xdc00 && units[index] <= 0xdfff:
			return false
		case units[index] == 0:
			return false
		}
	}
	return true
}

func payloadFieldCount(payload []byte) int {
	count := 0
	for offset := 0; offset < len(payload); count++ {
		size := int(binary.LittleEndian.Uint32(payload[offset+2 : offset+6]))
		offset += 6 + size
	}
	return count
}

func uint16Bytes(value uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], value)
	return b[:]
}
func uint64Bytes(value uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], value)
	return b[:]
}
