package exec

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
)

type scriptedZeroProver struct {
	mu     sync.Mutex
	proofs []error
	closed atomic.Int32
}

func (p *scriptedZeroProver) terminateAndWait() (error, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proofs) == 0 {
		return nil, errors.New("persistent completion failure")
	}
	err := p.proofs[0]
	p.proofs = p.proofs[1:]
	return nil, err
}

func (p *scriptedZeroProver) close() { p.closed.Add(1) }

type captureQuarantine struct {
	count atomic.Int32
	item  *quarantinedSpawn
}

func (q *captureQuarantine) quarantine(item *quarantinedSpawn) {
	q.count.Add(1)
	q.item = item
}

func TestQuarantinedSpawnReleasesOnlyAfterLaterZeroProof(t *testing.T) {
	proofErr := errors.New("completion port unavailable")
	prover := &scriptedZeroProver{proofs: []error{proofErr, nil}}
	var released atomic.Int32
	spawn := newQuarantinedSpawn(prover, nil, nil)
	spawn.spawnCleanup = []func() error{func() error { released.Add(1); return nil }}

	if _, err := spawn.reapOnce(); !errors.Is(err, proofErr) {
		t.Fatalf("first reap error = %v, want %v", err, proofErr)
	}
	if released.Load() != 0 || prover.closed.Load() != 0 {
		t.Fatal("resources released without ACTIVE_PROCESS_ZERO proof")
	}
	if done, err := spawn.reapOnce(); !done || err != nil {
		t.Fatalf("second reap = (%v, %v), want (true, nil)", done, err)
	}
	if released.Load() != 1 || prover.closed.Load() != 1 {
		t.Fatalf("release counts = cleanup %d Job %d, want 1 each", released.Load(), prover.closed.Load())
	}
}

func TestQuarantinedSpawnPersistentFailureRetainsIndefinitely(t *testing.T) {
	prover := &scriptedZeroProver{}
	var released atomic.Int32
	spawn := newQuarantinedSpawn(prover, nil, nil)
	spawn.spawnCleanup = []func() error{func() error { released.Add(1); return nil }}

	for i := 0; i < 100; i++ {
		if done, err := spawn.reapOnce(); done || err == nil {
			t.Fatalf("reap %d = (%v, %v), want retained failure", i, done, err)
		}
	}
	if released.Load() != 0 || prover.closed.Load() != 0 {
		t.Fatal("persistent proof failure released quarantined resources")
	}
}

func TestSpawnQuarantineTransferIsRaceSafeAndIdempotent(t *testing.T) {
	prover := &scriptedZeroProver{}
	spawn := newQuarantinedSpawn(prover, nil, nil)
	sink := &captureQuarantine{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spawn.transferTo(sink)
		}()
	}
	wg.Wait()
	if sink.count.Load() != 1 || sink.item != spawn {
		t.Fatalf("quarantine transfers = %d, want exactly one", sink.count.Load())
	}
}

func TestQuarantinedSpawnReportsTerminateErrorAfterSuccessfulZeroProof(t *testing.T) {
	terminateErr := errors.New("terminate failed")
	prover := zeroProverFunc(func() (error, error) { return terminateErr, nil })
	var released atomic.Int32
	spawn := newQuarantinedSpawn(prover, nil, nil)
	spawn.spawnCleanup = []func() error{func() error { released.Add(1); return nil }}

	done, err := spawn.reapOnce()
	if !done || !errors.Is(err, terminateErr) {
		t.Fatalf("reap = (%v, %v), want successful proof with terminate error", done, err)
	}
	if released.Load() != 1 {
		t.Fatal("successful zero proof did not release resources")
	}
}

func TestExecutorQuarantineRetainsLeaseAndSpawnBackingUntilZeroProof(t *testing.T) {
	executor := &Executor{lifecycle: newExecutorLifecycle()}
	lease, err := executor.beginExecution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	proofErr := errors.New("zero not yet proven")
	prover := &scriptedZeroProver{proofs: []error{proofErr, nil}}
	cmd := exec.Command("retained-command")
	var cleanup, transientSpec, proxy atomic.Int32
	var orderMu sync.Mutex
	var order []string
	record := func(name string) {
		orderMu.Lock()
		order = append(order, name)
		orderMu.Unlock()
	}
	spawn := newQuarantinedSpawn(prover, cmd, lease)
	spawn.spawnCleanup = []func() error{func() error { cleanup.Add(1); record("spawn cleanup"); return nil }}
	spawn.afterExecution = []func() error{
		func() error { transientSpec.Add(1); record("transient spec"); return nil },
		func() error { proxy.Add(1); record("proxy"); return nil },
	}
	stopClose := lease.stopClose
	lease.stopClose = func() bool { stopped := stopClose(); record("lease"); return stopped }
	sink := &captureQuarantine{}
	spawn.transferTo(sink)

	closed := make(chan struct{})
	executor.lifecycle.beginClose()
	go func() { executor.lifecycle.wait(); close(closed) }()
	if _, err := sink.item.reapOnce(); !errors.Is(err, proofErr) {
		t.Fatalf("first reap error = %v, want %v", err, proofErr)
	}
	select {
	case <-closed:
		t.Fatal("executor close completed while quarantined execution was unproven")
	default:
	}
	if sink.item.cmd != cmd || cleanup.Load() != 0 || transientSpec.Load() != 0 || proxy.Load() != 0 {
		t.Fatal("quarantine did not retain complete spawn ownership")
	}

	if done, err := sink.item.reapOnce(); !done || err != nil {
		t.Fatalf("second reap = (%v, %v), want completed proof", done, err)
	}
	<-closed
	if cleanup.Load() != 1 || transientSpec.Load() != 1 || proxy.Load() != 1 {
		t.Fatalf("release counts = cleanup %d spec %d proxy %d, want one each", cleanup.Load(), transientSpec.Load(), proxy.Load())
	}
	if got, want := order, []string{"spawn cleanup", "lease", "transient spec", "proxy"}; !slices.Equal(got, want) {
		t.Fatalf("release order = %v, want %v", got, want)
	}
}

type zeroProverFunc func() (error, error)

func (f zeroProverFunc) terminateAndWait() (error, error) { return f() }
func (zeroProverFunc) close()                             {}

type integrationProcessTree struct {
	mu      sync.Mutex
	results [][2]error
	record  func(string)
}

func (*integrationProcessTree) start(*exec.Cmd) error { return nil }
func (tree *integrationProcessTree) terminateAndWait() (error, error) {
	tree.mu.Lock()
	defer tree.mu.Unlock()
	result := tree.results[0]
	tree.results = tree.results[1:]
	return result[0], result[1]
}
func (tree *integrationProcessTree) close() { tree.record("job close") }

func TestExecutorRunQuarantineBlocksSetCloseAndAggregatesDelayedErrors(t *testing.T) {
	proofErr := errors.New("initial zero proof failed")
	terminateErr := errors.New("later terminate failed")
	specErr := errors.New("transient spec cleanup failed")
	var orderMu sync.Mutex
	var order []string
	record := func(value string) { orderMu.Lock(); order = append(order, value); orderMu.Unlock() }
	tree := &integrationProcessTree{
		results: [][2]error{{nil, proofErr}, {terminateErr, nil}},
		record:  record,
	}
	lifecycle := newExecutorLifecycle()
	sink := &captureQuarantine{}
	executor := &Executor{
		lifecycle:   lifecycle,
		quarantine:  sink,
		processTree: func(*exec.Cmd, processTreeOptions) (processTreeBoundary, error) { return tree, nil },
		spec:        enforce.Spec{Release: func() error { record("base spec"); return nil }},
	}
	set := &ExecutorSet{
		ownedRoot: t.TempDir(), executors: map[string]*Executor{"test": executor},
		lifecycle: lifecycle, closeDone: make(chan struct{}),
	}
	lease, err := executor.beginExecution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stopClose := lease.stopClose
	lease.stopClose = func() bool { stopped := stopClose(); record("finish execution"); return stopped }
	snapshot := snapshot{spec: enforce.Spec{Wrap: func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
		return []string{"not-started"}, nil, func() { record("spawn cleanup") }
	}}}
	_, _, runErr := executor.run(lease, "", []string{"ignored"}, snapshot, func() { record("observer") },
		func() error { record("transient spec"); return specErr },
		func() error { record("proxy release"); return nil },
	)
	if !errors.Is(runErr, proofErr) || sink.item == nil {
		t.Fatalf("run error = %v, quarantine = %v", runErr, sink.item)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- set.Close() }()
	select {
	case err := <-closeResult:
		t.Fatalf("ExecutorSet.Close returned before later zero proof: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if done, err := sink.item.reapOnce(); !done || !errors.Is(err, terminateErr) || !errors.Is(err, specErr) {
		t.Fatalf("later reap = (%v, %v), want both delayed errors", done, err)
	}
	closeErr := <-closeResult
	if !errors.Is(closeErr, terminateErr) || !errors.Is(closeErr, specErr) {
		t.Fatalf("ExecutorSet.Close error = %v, want delayed errors", closeErr)
	}
	if slices.Contains(order, "observer") {
		t.Fatal("observer ran after an initially failed zero proof")
	}
	want := []string{"job close", "spawn cleanup", "finish execution", "transient spec", "proxy release", "base spec"}
	if !slices.Equal(order, want) {
		t.Fatalf("release order = %v, want %v", order, want)
	}
}

func TestExecutorRunObservesDenialAfterZeroProofBeforeProxyRelease(t *testing.T) {
	var observed atomic.Bool
	tree := &integrationProcessTree{results: [][2]error{{nil, nil}}, record: func(string) {}}
	lifecycle := newExecutorLifecycle()
	executor := &Executor{
		lifecycle:   lifecycle,
		quarantine:  &captureQuarantine{},
		processTree: func(*exec.Cmd, processTreeOptions) (processTreeBoundary, error) { return tree, nil },
	}
	lease, err := executor.beginExecution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshot{spec: enforce.Spec{Wrap: func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
		return []string{"not-started"}, nil, nil
	}}}
	_, _, _ = executor.run(lease, "", []string{"ignored"}, snapshot,
		func() { observed.Store(true) },
		func() error {
			if !observed.Load() {
				t.Error("proxy released before denial observation")
			}
			return nil
		},
	)
}

func TestExecutorRunEarlySetupFailurePreservesTransientReleaseError(t *testing.T) {
	releaseErr := errors.New("transient release failed")
	lifecycle := newExecutorLifecycle()
	executor := &Executor{lifecycle: lifecycle, quarantine: &captureQuarantine{}}
	lease, err := executor.beginExecution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := snapshot{spec: enforce.Spec{Wrap: func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
		return nil, nil, nil
	}}}

	_, code, runErr := executor.run(lease, "", []string{"ignored"}, snapshot, nil,
		func() error { return releaseErr },
	)
	if code != -1 {
		t.Fatalf("exit code = %d, want -1", code)
	}
	if !errors.Is(runErr, releaseErr) || !strings.Contains(runErr.Error(), "backend produced an empty argv") {
		t.Fatalf("run error = %v, want setup and transient release errors", runErr)
	}
	closed := make(chan struct{})
	go func() {
		lifecycle.wait()
		lifecycle.waitCleanup()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("early setup failure did not release lifecycle barriers")
	}
}
