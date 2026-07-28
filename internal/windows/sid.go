package windows

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
)

// These domains are part of the persisted SID ABI. Changing one strands ACEs
// created by an older binary and therefore requires a migration, not a refactor.
const (
	installationSIDDomain = "looprig.windows.sid.v1/installation"
	executorSIDDomain     = "looprig.windows.sid.v1/executor"
	oneShotSIDDomain      = "looprig.windows.sid.v1/one-shot"
	sidEntropyBytes       = sha256.Size
)

var ErrSIDReuse = errors.New("sandbox: one-shot Windows SID entropy reused")

type sidKind uint8

const (
	sidKindUnknown sidKind = iota
	sidKindInstallation
	sidKindExecutor
	sidKindOneShot
	sidKindRestrictedCode
)

// SID is a module-issued private Windows trustee SID. Its representation
// and role are intentionally closed so callers cannot convert arbitrary text
// into a principal accepted by the token or ACL boundary.
type SID struct {
	text string
	kind sidKind
}

func (sid SID) String() string { return sid.text }

// InstallationSID deterministically names installation-owned runtime objects.
func InstallationSID(installationID string) (SID, error) {
	if installationID == "" {
		return SID{}, errors.New("sandbox: empty Windows installation identity")
	}
	if _, err := checkedSIDHashFieldLength("installation identity", uint64(len(installationID))); err != nil {
		return SID{}, err
	}
	return deriveModuleTrusteeSID(sidKindInstallation, installationSIDDomain, installationID), nil
}

// ExecutorSID deterministically names one executor within an installation.
func ExecutorSID(installationID, executorID string) (SID, error) {
	if installationID == "" || executorID == "" {
		return SID{}, errors.New("sandbox: empty Windows executor identity")
	}
	if _, err := checkedSIDHashFieldLength("installation identity", uint64(len(installationID))); err != nil {
		return SID{}, err
	}
	if _, err := checkedSIDHashFieldLength("executor identity", uint64(len(executorID))); err != nil {
		return SID{}, err
	}
	return deriveModuleTrusteeSID(sidKindExecutor, executorSIDDomain, installationID, executorID), nil
}

func checkedSIDHashFieldLength(field string, length uint64) (uint32, error) {
	if length > math.MaxUint32 {
		return 0, fmt.Errorf("sandbox: Windows %s exceeds %d bytes", field, uint64(math.MaxUint32))
	}
	return uint32(length), nil
}

func deriveModuleTrusteeSID(kind sidKind, domain string, fields ...string) SID {
	return moduleTrusteeSID(kind, moduleTrusteeName(domain, fields...))
}

func moduleTrusteeName(domain string, fields ...string) string {
	hash := sha256.New()
	writeHashField(hash, []byte(domain))
	for _, field := range fields {
		writeHashField(hash, []byte(field))
	}
	return "looprig.windows.trustee/" + hex.EncodeToString(hash.Sum(nil))
}

func writeHashField(writer io.Writer, value []byte) {
	var length [4]byte
	fieldLength, err := checkedSIDHashFieldLength("SID hash field", uint64(len(value)))
	if err != nil {
		// Public variable fields are validated before derivation, while the
		// remaining domain and entropy fields have fixed sizes.
		panic(err)
	}
	binary.LittleEndian.PutUint32(length[:], fieldLength)
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func moduleTrusteeSID(kind sidKind, name string) SID {
	// This is the documented DeriveCapabilitySidsFromName group-SID algorithm:
	// SHA-256 of the uppercased UTF-16LE capability name under the NT-authority
	// S-1-5-32 namespace. Unlike the paired S-1-15 capability SID, Windows
	// accepts this group SID in CreateRestrictedToken's restricting list.
	encodedName := utf16.Encode([]rune(strings.ToUpper(name)))
	hash := sha256.New()
	var codeUnit [2]byte
	for _, value := range encodedName {
		binary.LittleEndian.PutUint16(codeUnit[:], value)
		_, _ = hash.Write(codeUnit[:])
	}
	digest := hash.Sum(nil)
	var builder strings.Builder
	builder.WriteString("S-1-5-32")
	for offset := 0; offset < sha256.Size; offset += 4 {
		builder.WriteByte('-')
		builder.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(digest[offset:offset+4])), 10))
	}
	return SID{text: builder.String(), kind: kind}
}

// SIDRetirementStore atomically retires a SID before it is issued. It returns
// true only for the first retirement. Task 10 provides the durable journal-
// backed implementation; callers must never implement this as check-then-put.
type SIDRetirementStore interface {
	RetireSID(SID) (retired bool, err error)
}

// OneShotSIDGenerator creates grant SIDs from injected cryptographic entropy.
// Never-reuse authority belongs to the injected atomic retirement store, not
// this process, so separate generators and process restarts cannot race reuse.
type OneShotSIDGenerator struct {
	mu     sync.Mutex
	source io.Reader
	store  SIDRetirementStore
}

func NewOneShotSIDGenerator(source io.Reader, store SIDRetirementStore) (*OneShotSIDGenerator, error) {
	if store == nil {
		return nil, errors.New("sandbox: one-shot SID retirement store is required")
	}
	if source == nil {
		source = rand.Reader
	}
	return &OneShotSIDGenerator{source: source, store: store}, nil
}

func (generator *OneShotSIDGenerator) Next() (SID, error) {
	if generator == nil {
		return SID{}, errors.New("sandbox: nil one-shot SID generator")
	}
	generator.mu.Lock()
	defer generator.mu.Unlock()

	entropy := make([]byte, sidEntropyBytes)
	if _, err := io.ReadFull(generator.source, entropy); err != nil {
		return SID{}, fmt.Errorf("generate one-shot Windows SID: %w", err)
	}
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, string(entropy))
	retired, err := generator.store.RetireSID(sid)
	if err != nil {
		return SID{}, fmt.Errorf("retire one-shot Windows SID: %w", err)
	}
	if !retired {
		return SID{}, ErrSIDReuse
	}
	return sid, nil
}

func (sid SID) binary() []byte {
	if sid.kind == sidKindRestrictedCode && sid.text == "S-1-5-12" {
		return []byte{1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0}
	}
	parts := strings.Split(sid.text, "-")
	if len(parts) != 12 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "32" {
		return nil
	}
	result := make([]byte, 8+9*4)
	result[0] = 1
	result[1] = 9
	result[7] = 5
	binary.LittleEndian.PutUint32(result[8:12], 32)
	for index, part := range parts[4:] {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil
		}
		binary.LittleEndian.PutUint32(result[12+index*4:16+index*4], uint32(value))
	}
	return result
}

func (sid SID) isModuleTrustee() bool {
	switch sid.kind {
	case sidKindInstallation, sidKindExecutor, sidKindOneShot:
		return len(sid.binary()) == 8+9*4
	default:
		return false
	}
}

func (sid SID) isRestrictedTierTrustee() bool {
	return (sid.kind == sidKindExecutor || sid.kind == sidKindOneShot) && sid.isModuleTrustee()
}
