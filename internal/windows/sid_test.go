package windows

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
)

type memorySIDRetirementState struct {
	mu      sync.Mutex
	retired map[SID]struct{}
}

type memorySIDRetirementStore struct{ state *memorySIDRetirementState }

func (store memorySIDRetirementStore) RetireSID(sid SID) (bool, error) {
	store.state.mu.Lock()
	defer store.state.mu.Unlock()
	if _, exists := store.state.retired[sid]; exists {
		return false, nil
	}
	store.state.retired[sid] = struct{}{}
	return true, nil
}

func newMemorySIDRetirementStore() memorySIDRetirementStore {
	return memorySIDRetirementStore{state: &memorySIDRetirementState{retired: make(map[SID]struct{})}}
}

func TestSIDNamespacesAreDeterministicAndSeparated(t *testing.T) {
	installation, err := InstallationSID("install-a")
	if err != nil {
		t.Fatal(err)
	}
	again, err := InstallationSID("install-a")
	if err != nil {
		t.Fatal(err)
	}
	executor, err := ExecutorSID("install-a", "executor-a")
	if err != nil {
		t.Fatal(err)
	}
	if installation != again {
		t.Fatalf("installation SID is not deterministic: %q != %q", installation, again)
	}
	const wantInstallation = "S-1-5-32-906244842-2273296446-3503414478-3616732795-3278140985-13462797-1442982838-532462144"
	if installation.String() != wantInstallation {
		t.Fatalf("installation SID ABI changed: %q, want %q", installation, wantInstallation)
	}
	const wantExecutor = "S-1-5-32-2643307060-2313275912-3271447813-3792834996-3327059363-867895806-1381925209-3506755460"
	if executor.String() != wantExecutor {
		t.Fatalf("executor SID ABI changed: %q, want %q", executor, wantExecutor)
	}
	if installation == executor {
		t.Fatalf("domain-separated SIDs collided: %q", installation)
	}
	if got := installation.String(); len(got) < len("S-1-5-32-") || got[:len("S-1-5-32-")] != "S-1-5-32-" {
		t.Fatalf("installation SID = %q, want token-compatible private namespace", got)
	}
	if !installation.isModuleTrustee() || (SID{text: "S-1-5-12", kind: sidKindExecutor}).isModuleTrustee() {
		t.Fatal("module trustee validation accepted the wrong SID shape")
	}
	if _, err := InstallationSID(""); err == nil {
		t.Fatal("empty installation identity accepted")
	}
	if _, err := ExecutorSID("install-a", ""); err == nil {
		t.Fatal("empty executor identity accepted")
	}
}

func TestSIDHashFieldLengthBoundary(t *testing.T) {
	got, err := checkedSIDHashFieldLength("executor identity", math.MaxUint32)
	if err != nil {
		t.Fatalf("exact maximum rejected: %v", err)
	}
	if got != math.MaxUint32 {
		t.Fatalf("exact maximum = %d, want %d", got, uint32(math.MaxUint32))
	}

	_, err = checkedSIDHashFieldLength("executor identity", uint64(math.MaxUint32)+1)
	if err == nil {
		t.Fatal("identity larger than the persisted field accepted")
	}
	if got := err.Error(); !strings.Contains(got, "Windows executor identity") ||
		!strings.Contains(got, "4294967295 bytes") {
		t.Fatalf("oversized identity error = %q, want field and limit", got)
	}
}

func TestOneShotSIDUsesInjectedEntropyAndNeverReuses(t *testing.T) {
	entropy := bytes.Repeat([]byte{0x5a}, sidEntropyBytes*2)
	store := newMemorySIDRetirementStore()
	generator, err := NewOneShotSIDGenerator(bytes.NewReader(entropy), store)
	if err != nil {
		t.Fatal(err)
	}
	first, err := generator.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generator.Next(); !errors.Is(err, ErrSIDReuse) {
		t.Fatalf("repeated entropy error = %v, want ErrSIDReuse", err)
	}
	if first.String() == "" {
		t.Fatal("empty one-shot SID")
	}

	short, err := NewOneShotSIDGenerator(bytes.NewReader(make([]byte, sidEntropyBytes-1)), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := short.Next(); err == nil {
		t.Fatal("short entropy source accepted")
	}
	if _, err := NewOneShotSIDGenerator(bytes.NewReader(make([]byte, sidEntropyBytes)), nil); err == nil {
		t.Fatal("one-shot generator without retirement store constructed")
	}
}

func TestOneShotSIDRetirementIsAtomicAcrossGenerators(t *testing.T) {
	store := newMemorySIDRetirementStore()
	entropy := bytes.Repeat([]byte{0x3c}, sidEntropyBytes)
	left, _ := NewOneShotSIDGenerator(bytes.NewReader(entropy), store)
	right, _ := NewOneShotSIDGenerator(bytes.NewReader(entropy), store)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, generator := range []*OneShotSIDGenerator{left, right} {
		go func(generator *OneShotSIDGenerator) {
			<-start
			_, err := generator.Next()
			results <- err
		}(generator)
	}
	close(start)
	var successes, collisions int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrSIDReuse):
			collisions++
		default:
			t.Fatalf("issuance error = %v", err)
		}
	}
	if successes != 1 || collisions != 1 {
		t.Fatalf("successes/collisions = %d/%d, want 1/1", successes, collisions)
	}
}

func TestOneShotSIDRetirementSurvivesStoreReopen(t *testing.T) {
	state := &memorySIDRetirementState{retired: make(map[SID]struct{})}
	entropy := bytes.Repeat([]byte{0xa5}, sidEntropyBytes)
	first, err := NewOneShotSIDGenerator(bytes.NewReader(entropy), memorySIDRetirementStore{state: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Next(); err != nil {
		t.Fatal(err)
	}

	// A second generator and reopened store wrapper share one atomic authority.
	// Task 10 supplies the durable implementation of this interface.
	second, err := NewOneShotSIDGenerator(bytes.NewReader(entropy), memorySIDRetirementStore{state: state})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Next(); !errors.Is(err, ErrSIDReuse) {
		t.Fatalf("shared/reopened store collision = %v, want ErrSIDReuse", err)
	}
}

func TestSIDBinaryRoundTripsStableShape(t *testing.T) {
	sid, err := ExecutorSID("install", "executor")
	if err != nil {
		t.Fatal(err)
	}
	binary := sid.binary()
	if len(binary) != 8+9*4 || binary[0] != 1 || binary[1] != 9 {
		t.Fatalf("binary SID shape = %x", binary)
	}
	if got := binary[8:12]; !bytes.Equal(got, []byte{32, 0, 0, 0}) {
		t.Fatalf("private namespace subauthority = %x, want 32", got)
	}
	binary[0] = 0
	if sid.binary()[0] != 1 {
		t.Fatal("binary SID storage was mutable through caller")
	}
}
