package windows

import (
	"bytes"
	"errors"
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
	const wantInstallation = "S-1-5-21-2604559594-2853295540-4076106329-3836222237"
	if installation.String() != wantInstallation {
		t.Fatalf("installation SID ABI changed: %q, want %q", installation, wantInstallation)
	}
	if installation == executor {
		t.Fatalf("domain-separated SIDs collided: %q", installation)
	}
	if got := installation.String(); len(got) < len("S-1-5-21-") || got[:len("S-1-5-21-")] != "S-1-5-21-" {
		t.Fatalf("installation SID = %q, want token-compatible private namespace", got)
	}
	if !installation.isPrivateCapability() || (SID{text: "S-1-5-12", kind: sidKindExecutor}).isPrivateCapability() {
		t.Fatal("private capability validation accepted the wrong SID shape")
	}
	if _, err := InstallationSID(""); err == nil {
		t.Fatal("empty installation identity accepted")
	}
	if _, err := ExecutorSID("install-a", ""); err == nil {
		t.Fatal("empty executor identity accepted")
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
	if len(binary) != 8+5*4 || binary[0] != 1 || binary[1] != 5 {
		t.Fatalf("binary SID shape = %x", binary)
	}
	if got := binary[8:12]; !bytes.Equal(got, []byte{21, 0, 0, 0}) {
		t.Fatalf("private namespace subauthority = %x, want 21", got)
	}
	binary[0] = 0
	if sid.binary()[0] != 1 {
		t.Fatal("binary SID storage was mutable through caller")
	}
}
