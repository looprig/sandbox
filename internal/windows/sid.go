package windows

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
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
)

// SID is a module-issued private Windows capability SID. Its representation
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
	return deriveCapabilitySID(sidKindInstallation, installationSIDDomain, installationID), nil
}

// ExecutorSID deterministically names one executor within an installation.
func ExecutorSID(installationID, executorID string) (SID, error) {
	if installationID == "" || executorID == "" {
		return SID{}, errors.New("sandbox: empty Windows executor identity")
	}
	return deriveCapabilitySID(sidKindExecutor, executorSIDDomain, installationID, executorID), nil
}

func deriveCapabilitySID(kind sidKind, domain string, fields ...string) SID {
	hash := sha256.New()
	writeHashField(hash, []byte(domain))
	for _, field := range fields {
		writeHashField(hash, []byte(field))
	}
	return capabilitySID(kind, hash.Sum(nil))
}

func writeHashField(writer io.Writer, value []byte) {
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

func capabilitySID(kind sidKind, digest []byte) SID {
	var builder strings.Builder
	// CreateRestrictedToken rejects synthetic S-1-15 capability-authority SIDs
	// that were not derived by Windows, even though ConvertStringSidToSid and
	// IsValidSid accept their structure. A private NT-authority SID with four
	// digest subauthorities is accepted both as an ACL principal and as a
	// restricting SID. The 128-bit suffix keeps collision resistance while
	// staying in the conventional S-1-5-21 token-compatible shape.
	builder.WriteString("S-1-5-21")
	for offset := 0; offset < 16; offset += 4 {
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
	sid := deriveCapabilitySID(sidKindOneShot, oneShotSIDDomain, string(entropy))
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
	parts := strings.Split(sid.text, "-")
	if len(parts) != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return nil
	}
	result := make([]byte, 8+5*4)
	result[0] = 1
	result[1] = 5
	result[7] = 5
	binary.LittleEndian.PutUint32(result[8:12], 21)
	for index, part := range parts[4:] {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil
		}
		binary.LittleEndian.PutUint32(result[12+index*4:16+index*4], uint32(value))
	}
	return result
}

func (sid SID) isPrivateCapability() bool {
	switch sid.kind {
	case sidKindInstallation, sidKindExecutor, sidKindOneShot:
		return len(sid.binary()) == 8+5*4
	default:
		return false
	}
}

func (sid SID) isRestrictedTierCapability() bool {
	return (sid.kind == sidKindExecutor || sid.kind == sidKindOneShot) && sid.isPrivateCapability()
}
