//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	sandboxnetwork "github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

// elevatedRunnerLaunchFunc's final func() error parameter retires BOTH the
// per-execution broker lease and the compiled elevated Spec's active-launch
// registration (see elevatedBackend.Compile's active sync.WaitGroup below);
// it is idempotent and must be called exactly once across the whole launch,
// whether synchronously on an early failure, synchronously after this
// function obtains exact authority-empty proof for a later failure, or
// eventually by the returned Execution's Wait.
type elevatedRunnerLaunchFunc func(enforce.LaunchRequest, elevatedSetupSnapshot, brokerIssuedToken, policy.Limits, func() error) (enforce.Execution, error)

// elevatedSetupSnapshot is the compiler's immutable, already-verified view of
// the installed tier. Individual mechanism checks remain explicit so a future
// addition cannot accidentally become healthy merely because the manifest is
// ready.
type elevatedSetupSnapshot struct {
	Ready                bool
	InstallationID       string
	OwnerSID             string
	HostPath             string
	HostSHA256           string
	Protocol             uint16
	AccountsReady        bool
	CredentialsReady     bool
	FirewallReady        bool
	RuntimeBaselineReady bool
	RunnerHashVerified   bool
	PrivateDesktopReady  bool
	JobReadbackReady     bool
	HandleListReady      bool
	ProxyPorts           []uint16
	PipeName             string
	OfflineSID           string
	OnlineSID            string
}

type elevatedExecutionLease interface {
	IssueToken(brokerAccountKind) (brokerIssuedToken, error)
	Release() error
}

type elevatedLease interface {
	Acquire(context.Context) (elevatedExecutionLease, error)
	Narrowings() []string
	Release() error
}

type elevatedCompileDependencies struct {
	inspect func(Config, policy.Effective) (elevatedSetupSnapshot, error)
	acquire func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error)
	reserve func(elevatedSetupSnapshot) (*proxyPortReservation, error)
	launch  elevatedRunnerLaunchFunc
}

type elevatedBackend struct {
	config Config
	deps   elevatedCompileDependencies
}

type elevatedSpecGrantAuthority struct {
	mu      sync.Mutex
	base    policy.Effective
	lease   elevatedLease
	borrows int
	closing bool
}

func newElevatedSpecGrantAuthority(base policy.Effective, lease elevatedLease) *elevatedSpecGrantAuthority {
	return &elevatedSpecGrantAuthority{base: policy.Clone(base), lease: lease}
}

func (authority *elevatedSpecGrantAuthority) borrow(base policy.Effective) (elevatedLease, func() error, error) {
	if authority == nil {
		return nil, nil, errors.New("windows sandbox: elevated base authority is missing")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.closing || authority.lease == nil || !reflect.DeepEqual(authority.base, base) {
		return nil, nil, errors.New("windows sandbox: elevated base authority is released or belongs to another executor")
	}
	authority.borrows++
	var once sync.Once
	var releaseErr error
	release := func() error {
		once.Do(func() {
			authority.mu.Lock()
			authority.borrows--
			var retired elevatedLease
			if authority.closing && authority.borrows == 0 {
				retired, authority.lease = authority.lease, nil
			}
			authority.mu.Unlock()
			if retired != nil {
				releaseErr = retired.Release()
			}
		})
		return releaseErr
	}
	return authority.lease, release, nil
}

func (authority *elevatedSpecGrantAuthority) retire() error {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	authority.closing = true
	var retired elevatedLease
	if authority.borrows == 0 {
		retired, authority.lease = authority.lease, nil
	}
	authority.mu.Unlock()
	if retired != nil {
		return retired.Release()
	}
	return nil
}

// AcquireGrantPathHandle ensures the executor validates an elevated grant with
// the exact ACL-authority handle the broker compiler will retain. No pathname
// reopen is permitted after this boundary.
func (*elevatedBackend) AcquireGrantPathHandle(binding *policy.PathBinding, target string, exact bool) (*policy.PathHandle, error) {
	return policy.AcquireACLPathHandle(binding, target, exact)
}

// SupportsGrantClass is the side-effect-free preflight used by the executor
// before consuming a signed token. Compile remains the authoritative check.
func (*elevatedBackend) SupportsGrantClass(class string) bool {
	switch class {
	case "command.start.v1",
		"network.proxy-target.v1",
		"filesystem.path.read.v1",
		"filesystem.path.write.v1",
		"filesystem.tree.read.v1",
		"filesystem.tree.write.v1":
		return true
	default:
		return false
	}
}

func newElevatedBackend(config Config) enforce.Backend {
	return &elevatedBackend{config: config, deps: elevatedCompileDependencies{
		inspect: inspectElevatedSetup,
		acquire: acquireElevatedLease,
		reserve: reserveElevatedProxyPorts,
		launch:  executeElevatedRunner,
	}}
}

type elevatedInstallationVerifier interface {
	Verify(path string, expectation installedPathExpectation) error
}

type elevatedDependencyHealth struct {
	Accounts, Credentials, Firewall, RuntimeBaseline bool
	// The three launch mechanisms below are verified again, fail closed, at
	// every launch; what inspection can honestly establish beforehand is
	// narrower, and each field says exactly what (review L8). They used to
	// be hard-coded true.
	//
	// PrivateDesktop: the manifest-owned broker service, the only principal
	// that creates the per-lease window station and desktop, is running with
	// its pinned configuration. No desktop exists before a token is issued.
	PrivateDesktop bool
	// JobReadback: this host just created a sandboxed, kill-on-close Job and
	// read every installed limit back (NewJob's own read-back).
	JobReadback bool
	// HandleList: this host just built a PROC_THREAD_ATTRIBUTE_LIST, the
	// prerequisite of the explicit handle list every launch installs.
	HandleList bool
}

type elevatedDependencyHealthInspector interface {
	Inspect(context.Context, string, setupManifest, policy.Effective) (elevatedDependencyHealth, error)
}

type productionElevatedDependencyInspector struct{}

func (productionElevatedDependencyInspector) Inspect(ctx context.Context, stateRoot string, manifest setupManifest, _ policy.Effective) (elevatedDependencyHealth, error) {
	setup := validatedSetup{
		config: SetupConfig{
			InstallationID: manifest.InstallationID, StateRoot: stateRoot,
			ProxyPorts: append([]uint16(nil), manifest.ProxyPorts...),
		},
		stateRoot: stateRoot, ownerSID: manifest.OwnerSID,
	}
	sandboxSID, err := InstallationSID(manifest.InstallationID)
	if err != nil {
		return elevatedDependencyHealth{}, err
	}
	setup.sandboxSID = sandboxSID.String()
	readiness, err := productionSetupDependencyInspector().Inspect(ctx, setup, manifest)
	if err != nil {
		return elevatedDependencyHealth{}, err
	}
	return elevatedDependencyHealth{
		Accounts:    readiness.accounts && readiness.service,
		Credentials: readiness.credentials,
		// A proxy port held by THIS process is this host's own reserved
		// listener (ReserveEgressProxy), not a foreign squatter; without
		// excluding it, every Compile after a reservation saw its own
		// listener and reported the installation stale (review L8).
		Firewall: readiness.firewallEffective && readiness.firewallUnchanged &&
			len(foreignProxyPortOwners(readiness.portPID, win.GetCurrentProcessId())) == 0,
		RuntimeBaseline: readiness.runtimeBaseline,
		PrivateDesktop:  readiness.service,
		JobReadback:     probeElevatedJobReadback() == nil,
		HandleList:      probeElevatedHandleList() == nil,
	}, nil
}

// probeElevatedJobReadback creates and closes one sandboxed Job with a
// process limit, which NewJob installs and reads back (kill-on-close, no
// breakaway, UI restrictions, the limit itself) before returning it.
func probeElevatedJobReadback() error {
	job, err := NewJob(JobOptions{Sandboxed: true, MaxProcesses: 1})
	if err != nil {
		return err
	}
	if !job.ResourceLimitsInstalled() {
		return errors.Join(errors.New("windows sandbox: probe Job limits were not read back"), job.Close())
	}
	return job.Close()
}

// probeElevatedHandleList builds and frees one PROC_THREAD_ATTRIBUTE_LIST.
func probeElevatedHandleList() error {
	attributes, err := win.NewProcThreadAttributeList(1)
	if err != nil {
		return err
	}
	attributes.Delete()
	return nil
}

// installedBrokerPipeName derives the broker's pipe from the installation's
// service name; it is never read from the environment or the manifest.
func installedBrokerPipeName(installationID string) (string, error) {
	names, err := deriveInstallationPrincipalNames(installationID)
	if err != nil {
		return "", err
	}
	return `\\.\pipe\looprig-sandbox-` + strings.TrimPrefix(names.Service, "lsb-svc-"), nil
}

func inspectElevatedSetup(config Config, effective policy.Effective) (elevatedSetupSnapshot, error) {
	return inspectElevatedSetupWith(config, effective, realBrokerInstallPathVerifier{}, productionElevatedDependencyInspector{})
}

func inspectElevatedSetupWith(config Config, effective policy.Effective, verifier elevatedInstallationVerifier, dependencies elevatedDependencyHealthInspector) (elevatedSetupSnapshot, error) {
	if verifier == nil || dependencies == nil {
		return elevatedSetupSnapshot{}, errors.New("sandbox: incomplete Windows elevated setup inspector")
	}
	if strings.TrimSpace(config.StateRoot) == "" {
		return elevatedSetupSnapshot{}, ErrSetupRequired
	}
	stateRoot, err := validateElevatedStateRoot(config.StateRoot)
	if err != nil {
		return elevatedSetupSnapshot{}, err
	}
	manifestPath := filepath.Join(stateRoot, readyManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return elevatedSetupSnapshot{}, ErrSetupRequired
		}
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: read ready manifest: %v", ErrSetupStale, err)
	}
	manifest, err := decodeSetupManifest(data)
	if err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: decode ready manifest: %v", ErrSetupStale, err)
	}
	if manifest.State != setupStateReady || manifest.Protocol != brokerProtocolVersion ||
		manifest.InstallationID == "" || manifest.OwnerSID == "" {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: ready manifest identity or protocol mismatch", ErrSetupStale)
	}
	sandboxSID, err := InstallationSID(manifest.InstallationID)
	if err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: invalid installation identity: %v", ErrSetupStale, err)
	}
	expectation := installedPathExpectation{ownerSID: manifest.OwnerSID, sandboxSID: sandboxSID.String()}
	directoryExpectation := expectation
	directoryExpectation.directory = true
	if err := validateInstalledHostPath(stateRoot, manifest.HostPath); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	programData, err := filepath.Abs(os.Getenv("ProgramData"))
	if err != nil || programData == "." {
		return elevatedSetupSnapshot{}, errors.New("sandbox: ProgramData is unavailable")
	}
	if err := rejectExistingSetupReparse(programData, stateRoot); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	if err := verifier.Verify(stateRoot, directoryExpectation); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify state-root protection: %v", ErrSetupStale, err)
	}
	if err := verifier.Verify(filepath.Join(stateRoot, "slots"), directoryExpectation); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify slots protection: %v", ErrSetupStale, err)
	}
	if err := verifier.Verify(filepath.Dir(manifest.HostPath), directoryExpectation); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify generation protection: %v", ErrSetupStale, err)
	}
	owner, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil || owner == nil || owner.User.Sid == nil || !equalSIDText(owner.User.Sid.String(), manifest.OwnerSID) {
		return elevatedSetupSnapshot{}, errors.Join(ErrSetupStale, errors.New("sandbox: ready manifest owner does not match the caller"), err)
	}
	if err := verifier.Verify(manifestPath, expectation); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify ready manifest protection: %v", ErrSetupStale, err)
	}
	if err := verifier.Verify(manifest.HostPath, expectation); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify installed runner protection: %v", ErrSetupStale, err)
	}
	digest, err := hashFile(manifest.HostPath)
	if err != nil || !strings.EqualFold(digest, manifest.HostSHA256) {
		return elevatedSetupSnapshot{}, errors.Join(ErrSetupStale, errors.New("sandbox: installed runner hash does not match the ready manifest"), err)
	}
	health, err := dependencies.Inspect(context.Background(), stateRoot, manifest, policy.Clone(effective))
	if err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: inspect installed dependencies: %v", ErrSetupStale, err)
	}
	pipeName, err := installedBrokerPipeName(manifest.InstallationID)
	if err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: derive broker endpoint: %v", ErrSetupStale, err)
	}
	return elevatedSetupSnapshot{
		Ready: true, InstallationID: manifest.InstallationID,
		OwnerSID: manifest.OwnerSID,
		HostPath: filepath.Clean(manifest.HostPath), HostSHA256: strings.ToLower(digest),
		Protocol: manifest.Protocol, AccountsReady: health.Accounts,
		CredentialsReady: health.Credentials, FirewallReady: health.Firewall,
		RuntimeBaselineReady: health.RuntimeBaseline, RunnerHashVerified: true,
		// Derived from what inspection established (elevatedDependencyHealth),
		// never assumed: the protected launcher re-verifies the Job and the
		// handle list at every launch, and the broker creates the private
		// desktop per lease and fails token issuance without it.
		PrivateDesktopReady: health.PrivateDesktop, JobReadbackReady: health.JobReadback, HandleListReady: health.HandleList,
		ProxyPorts: append([]uint16(nil), manifest.ProxyPorts...),
		PipeName:   pipeName,
		OfflineSID: manifest.OfflineSID, OnlineSID: manifest.OnlineSID,
	}, nil
}

// ReserveEgressProxy reserves the complete manifest-pinned loopback surface
// before exposing one authenticated endpoint. The immutable setup inspection
// is repeated here because proxy construction is a separate authority boundary
// from policy compilation and must not reuse stale ambient state.
func (backend *elevatedBackend) ReserveEgressProxy(route sandboxnetwork.Route) (*sandboxnetwork.Proxy, func() error, error) {
	if backend == nil || backend.deps.inspect == nil || backend.deps.reserve == nil {
		return nil, nil, errors.New("sandbox: invalid Windows elevated proxy backend")
	}
	if err := route.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validate Windows egress proxy route: %w", err)
	}
	snapshot, err := backend.deps.inspect(backend.config, policy.Effective{})
	if err != nil {
		return nil, nil, fmt.Errorf("inspect elevated installation for egress proxy: %w", err)
	}
	if err := validateElevatedSnapshot(snapshot); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	if snapshot.OwnerSID == "" {
		return nil, nil, fmt.Errorf("%w: verified installation owner is missing", ErrSetupStale)
	}
	if err := validateProxyPorts(snapshot.ProxyPorts); err != nil {
		return nil, nil, fmt.Errorf("%w: invalid verified proxy ports: %v", ErrSetupStale, err)
	}

	reservation, err := backend.deps.reserve(snapshot)
	if err != nil {
		return nil, nil, fmt.Errorf("reserve verified Windows proxy ports: %w", err)
	}
	if reservation == nil {
		return nil, nil, errors.New("sandbox: Windows proxy reservation returned no endpoints")
	}

	ports := append([]uint16(nil), snapshot.ProxyPorts...)
	slices.Sort(ports)
	listener, err := reservation.ClaimProxy(ports[0])
	if err != nil {
		return nil, nil, errors.Join(err, reservation.Close())
	}
	proxy, err := sandboxnetwork.NewProxyWithListener(route, listener)
	if err != nil {
		return nil, nil, errors.Join(err, reservation.Close())
	}
	return proxy, reservation.Close, nil
}

func reserveElevatedProxyPorts(snapshot elevatedSetupSnapshot) (*proxyPortReservation, error) {
	if snapshot.InstallationID == "" || snapshot.OwnerSID == "" {
		return nil, errors.New("sandbox: verified Windows installation identity is incomplete")
	}
	return reserveProxyPorts(
		snapshot.InstallationID,
		append([]uint16(nil), snapshot.ProxyPorts...),
		windowsLoopbackGuardBinder{sockets: exclusiveLoopbackSocketFactory{}},
		protectedInstallationLocker{ownerSID: snapshot.OwnerSID, mutexes: win32NamedMutexAPI{}},
		windowsTCPPortOwner{tables: ipHelperTCPTableAPI{}},
	)
}

func validateElevatedStateRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("sandbox: Windows elevated state root is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil || !filepath.IsAbs(absolute) || filepath.Clean(root) != filepath.Clean(absolute) {
		return "", errors.New("sandbox: Windows elevated state root must be canonical and absolute")
	}
	programData, err := filepath.Abs(os.Getenv("ProgramData"))
	if err != nil || programData == "." {
		return "", errors.New("sandbox: ProgramData is unavailable")
	}
	relative, err := filepath.Rel(programData, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return "", errors.New("sandbox: Windows elevated state root must be beneath ProgramData")
	}
	return filepath.Clean(absolute), nil
}

func acquireElevatedLease(snapshot elevatedSetupSnapshot, effective policy.Effective) (elevatedLease, error) {
	if err := validateElevatedSnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	if len(effective.FS) == 0 || len(effective.RuntimeBaselines) == 0 {
		return nil, fmt.Errorf("%w: elevated ACL policy is incomplete", enforce.ErrUnavailable)
	}
	return acquireBrokerBackedElevatedLease(context.Background(), elevatedBrokerLeaseConfig{
		InstallationID:       snapshot.InstallationID,
		PipeName:             snapshot.PipeName,
		HostPath:             snapshot.HostPath,
		OfflineSID:           snapshot.OfflineSID,
		OnlineSID:            snapshot.OnlineSID,
		RuntimeBaselineReady: snapshot.RuntimeBaselineReady,
	}, policy.Clone(effective), productionElevatedBrokerLeaseDependencies())
}

func (backend *elevatedBackend) Compile(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if backend == nil || backend.deps.inspect == nil || backend.deps.acquire == nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0,
			errors.New("sandbox: invalid Windows elevated backend")
	}
	snapshot, err := backend.deps.inspect(backend.config, policy.Clone(p))
	if err != nil {
		return enforce.Spec{}, elevatedCompileReport(p, elevatedSetupSnapshot{}), profile.LevelNone, 0,
			fmt.Errorf("inspect elevated installation: %w", err)
	}
	if err := validateElevatedSnapshot(snapshot); err != nil {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	// AF_UNIX endpoints are file-backed on Windows and no broker lease
	// projects onto them (unix_sockets.go), so the escape hatch is refused
	// before any broker authority is consumed.
	if unixSocketsRequested(p) {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0, refuseUnixSockets("elevated")
	}
	if p.Net.Open && p.Net.ProxyPort != 0 {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			fmt.Errorf("%w: online Windows policy cannot claim an offline proxy endpoint", enforce.ErrUnavailable)
	}
	// The offline account's firewall rules permit exactly the pinned proxy
	// ports and nothing else, so a narrower-than-open network policy that also
	// asks for loopback, private ranges, DNS or extra ports cannot be enforced.
	// Compiling it anyway would report NetworkBoundary for traffic the rules
	// block, or a boundary the policy did not ask for.
	if !p.Net.Open && (p.Net.Loopback || p.Net.Private || p.Net.DNS || len(p.Net.Ports) != 0) {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			fmt.Errorf("%w: Windows elevated firewall rules cannot express loopback, private-network, DNS or port allowances", enforce.ErrUnavailable)
	}
	if p.Net.ProxyPort != 0 && !slices.Contains(snapshot.ProxyPorts, p.Net.ProxyPort) {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			fmt.Errorf("%w: proxy port is not pinned by the verified installation", enforce.ErrUnavailable)
	}
	lease, err := backend.deps.acquire(snapshot, policy.Clone(p))
	if err != nil {
		if lease != nil {
			err = errors.Join(err, lease.Release())
		}
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0, err
	}
	if lease == nil {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			errors.New("sandbox: elevated compiler returned an empty lease")
	}
	bits := elevatedGuaranteeBits(p)
	if missing := p.RequiredGuarantees &^ bits; missing != 0 {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, bits,
			errors.Join(fmt.Errorf("%w: Windows elevated mode missing guarantees %s", enforce.ErrUnavailable, formatGuaranteeBits(missing)), lease.Release())
	}
	account := brokerAccountOffline
	if p.Net.Open {
		account = brokerAccountOnline
	}
	launch := backend.deps.launch
	if launch == nil {
		launch = executeElevatedRunner
	}
	var releaseOnce sync.Once
	var releaseErr error
	var lifecycleMu sync.Mutex
	var active sync.WaitGroup
	closing := false
	grantAuthority := newElevatedSpecGrantAuthority(p, lease)
	release := func() error {
		releaseOnce.Do(func() {
			lifecycleMu.Lock()
			closing = true
			lifecycleMu.Unlock()
			active.Wait()
			releaseErr = grantAuthority.retire()
		})
		return releaseErr
	}
	spec := enforce.Spec{
		GrantAuthority: grantAuthority,
		Launch: func(request enforce.LaunchRequest) (enforce.Execution, error) {
			if request.Context == nil {
				return nil, errors.New("sandbox: elevated launch context is required")
			}
			if err := request.Context.Err(); err != nil {
				return nil, err
			}
			lifecycleMu.Lock()
			if closing {
				lifecycleMu.Unlock()
				return nil, errors.New("sandbox: elevated specification is released")
			}
			active.Add(1)
			lifecycleMu.Unlock()
			// active.Done is deliberately NOT deferred around this whole call:
			// once launch (below) is invoked, IT owns retiring — synchronously
			// after exact authority-empty proof, or via quarantine — through
			// the combined retire closure built below. Only the two failures
			// below that occur before launch is ever called (lease.Acquire,
			// IssueToken — neither of which can have created any OS-level
			// authority) retire directly here.
			executionLease, err := lease.Acquire(request.Context)
			if err != nil {
				active.Done()
				return nil, fmt.Errorf("acquire per-spawn Windows broker lease: %w", err)
			}
			issued, err := executionLease.IssueToken(account)
			if err != nil {
				active.Done()
				return nil, errors.Join(fmt.Errorf("issue per-spawn restricted token: %w", err), executionLease.Release())
			}
			var retireOnce sync.Once
			var retireErr error
			retire := func() error {
				retireOnce.Do(func() {
					retireErr = executionLease.Release()
					active.Done()
				})
				return retireErr
			}
			return launch(request, snapshot, issued, p.Limits, retire)
		},
		Release: release,
	}
	level := profile.LevelDegraded
	narrowings := lease.Narrowings()
	if elevatedFullLevel(p, bits) && len(narrowings) == 0 {
		level = profile.LevelFull
	}
	report := elevatedCompileReport(p, snapshot)
	for _, narrowing := range narrowings {
		report.Entries = append(report.Entries, profile.ReportEntry{
			Feature: "windows.filesystem.hardlink", Status: "Narrowed", Detail: narrowing,
		})
	}
	return spec, report, level, bits, nil
}

// CompileWithRetainedPathHandles composes immutable base executor objects with
// grant-only objects retained from the executor's ACL-authority validation
// handles. It refuses to report guarantees unless base authority has already
// compiled successfully.
func (backend *elevatedBackend) CompileWithRetainedPathHandles(rawAuthority any, base, p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	authority, ok := rawAuthority.(*elevatedSpecGrantAuthority)
	if backend == nil || len(handles) == 0 || !ok {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0,
			errors.New("windows sandbox: elevated grant compilation requires retained handles and base authority")
	}
	baseLease, releaseBorrow, err := authority.borrow(base)
	if err != nil {
		return enforce.Spec{}, elevatedCompileReport(p, elevatedSetupSnapshot{}), profile.LevelNone, 0,
			err
	}
	clone := *backend
	originalAcquire := backend.deps.acquire
	clone.deps.acquire = func(snapshot elevatedSetupSnapshot, effective policy.Effective) (elevatedLease, error) {
		if originalAcquire == nil {
			_ = releaseBorrow()
			return nil, errors.New("windows sandbox: elevated grant lease acquisition is unavailable")
		}
		lease, acquireErr := acquireElevatedGrantLease(snapshot, effective, baseLease, handles)
		if acquireErr != nil {
			_ = releaseBorrow()
			return nil, acquireErr
		}
		return &borrowedElevatedLease{elevatedLease: lease, releaseBorrow: releaseBorrow}, nil
	}
	spec, report, level, bits, err := clone.Compile(p)
	if err != nil {
		_ = releaseBorrow()
		return spec, report, level, bits, err
	}
	spec.GrantAuthority = nil
	return spec, report, level, bits, nil
}

type borrowedElevatedLease struct {
	elevatedLease
	once          sync.Once
	releaseBorrow func() error
}

func (lease *borrowedElevatedLease) Release() error {
	err := lease.elevatedLease.Release()
	lease.once.Do(func() { err = errors.Join(err, lease.releaseBorrow()) })
	return err
}

func acquireElevatedGrantLease(snapshot elevatedSetupSnapshot, effective policy.Effective, base elevatedLease, handles []*policy.PathHandle) (elevatedLease, error) {
	if err := validateElevatedSnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	if len(effective.FS) == 0 || len(effective.RuntimeBaselines) == 0 {
		return nil, fmt.Errorf("%w: elevated ACL grant policy is incomplete", enforce.ErrUnavailable)
	}
	return acquireBrokerBackedElevatedGrantLease(context.Background(), elevatedBrokerLeaseConfig{
		InstallationID:       snapshot.InstallationID,
		PipeName:             snapshot.PipeName,
		HostPath:             snapshot.HostPath,
		OfflineSID:           snapshot.OfflineSID,
		OnlineSID:            snapshot.OnlineSID,
		RuntimeBaselineReady: snapshot.RuntimeBaselineReady,
	}, policy.Clone(effective), base, handles, productionElevatedBrokerLeaseDependencies())
}

func validateElevatedSnapshot(snapshot elevatedSetupSnapshot) error {
	if !snapshot.Ready || snapshot.InstallationID == "" || snapshot.OwnerSID == "" ||
		snapshot.HostPath == "" || snapshot.HostSHA256 == "" || snapshot.PipeName == "" ||
		snapshot.OfflineSID == "" || snapshot.OnlineSID == "" ||
		snapshot.Protocol != brokerProtocolVersion {
		return errors.New("Windows elevated setup manifest or protocol is not ready")
	}
	checks := []struct {
		ok   bool
		name string
	}{
		{snapshot.AccountsReady, "sandbox accounts"},
		{snapshot.CredentialsReady, "protected credentials"},
		{snapshot.FirewallReady, "firewall posture"},
		{snapshot.RuntimeBaselineReady, "runtime baseline"},
		{snapshot.RunnerHashVerified, "runner hash"},
		{snapshot.PrivateDesktopReady, "private desktop"},
		{snapshot.JobReadbackReady, "Job read-back"},
		{snapshot.HandleListReady, "explicit handle list"},
	}
	for _, check := range checks {
		if !check.ok {
			return fmt.Errorf("%s is not verified", check.name)
		}
	}
	return nil
}

// elevatedLimitsRequested reports whether the policy asks for any Job limit
// the launch path will install. Disabled limits are not installed
// (executeElevatedRunner zeroes them, like the restricted process tree).
func elevatedLimitsRequested(limits policy.Limits) bool {
	return !limits.Disabled && (limits.MaxPIDs > 0 || limits.MaxMemBytes > 0 || limits.MaxCPUPct > 0)
}

func elevatedGuaranteeBits(p policy.Effective) uint64 {
	bits := uint64(profile.GuaranteeProcessBoundary | profile.GuaranteeWriteBoundary |
		profile.GuaranteeReadBoundary)
	// ResourceLimits is a claim that requested limits are installed. It is
	// earned only when limits were requested, because the launch path
	// installs them through NewJob, which reads every one of them back and
	// fails the launch on a mismatch (design §8: "all non-zero requested
	// limits are supported, installed, and read back"). With nothing
	// requested there is nothing to claim (review L8).
	if elevatedLimitsRequested(p.Limits) {
		bits |= profile.GuaranteeResourceLimits
	}
	if !p.Env.Inherit {
		bits |= profile.GuaranteeEnvScrub
	}
	if !p.Net.Open {
		bits |= profile.GuaranteeNetworkBoundary
		if p.Net.ProxyPort != 0 {
			bits |= profile.GuaranteeTargetNetwork
		}
	}
	// AddressNetwork remains route-dependent and is composed by the executor.
	return bits
}

func elevatedFullLevel(p policy.Effective, bits uint64) bool {
	requiredForPolicy := uint64(profile.GuaranteeProcessBoundary | profile.GuaranteeWriteBoundary |
		profile.GuaranteeReadBoundary)
	if elevatedLimitsRequested(p.Limits) {
		requiredForPolicy |= profile.GuaranteeResourceLimits
	}
	if !p.Env.Inherit {
		requiredForPolicy |= profile.GuaranteeEnvScrub
	}
	return requiredForPolicy&^bits == 0 && p.RequiredGuarantees&^bits == 0
}

func elevatedCompileReport(p policy.Effective, snapshot elevatedSetupSnapshot) profile.CompileReport {
	status := func(ok bool) string {
		if ok {
			return "Enforced"
		}
		return "Unavailable"
	}
	firewall := profile.ReportEntry{Feature: "windows.firewall", Status: status(snapshot.FirewallReady),
		Detail: "offline-account outbound rules read back enabled, unchanged and effective on every profile, proxy ports held by no foreign process; loopback and system-service (SMB, WebClient, DNS client) egress are not filtered"}
	if p.Net.Open {
		firewall = profile.ReportEntry{Feature: "windows.firewall", Status: "unenforced",
			Detail: "online account: no firewall rule applies to this profile"}
	}
	limits := profile.ReportEntry{Feature: "windows.resource-limits", Status: "unenforced", Detail: "no resource limits requested; none installed"}
	if elevatedLimitsRequested(p.Limits) {
		limits = profile.ReportEntry{Feature: "windows.resource-limits", Status: status(snapshot.JobReadbackReady),
			Detail: "requested Job limits installed and read back at every launch; the launch fails on a mismatch"}
	}
	entries := []profile.ReportEntry{
		{Feature: "windows.installed-host", Status: status(snapshot.RunnerHashVerified), Detail: "protected installed runner hash and protocol"},
		{Feature: "windows.token", Status: status(snapshot.AccountsReady && snapshot.CredentialsReady), Detail: "broker-issued full restricted account token"},
		{Feature: "windows.filesystem.read", Status: status(snapshot.Ready), Detail: "broker-owned identity-bound ACL lease"},
		{Feature: "windows.filesystem.write", Status: status(snapshot.Ready), Detail: "broker-owned identity-bound ACL lease"},
		firewall,
		{Feature: "windows.job", Status: status(snapshot.JobReadbackReady && snapshot.HandleListReady),
			Detail: "kill-on-close Job with no breakaway and an explicit handle list; probed on this host at compile and verified again at every launch"},
		{Feature: "windows.private-desktop", Status: status(snapshot.PrivateDesktopReady),
			Detail: "protected non-interactive window station and desktop created per lease by the running broker, admitting only the lease's own SID; token issuance fails without it"},
		limits,
	}
	for _, baseline := range p.RuntimeBaselines {
		entries = append(entries, profile.ReportEntry{Feature: baseline, Status: status(snapshot.RuntimeBaselineReady), Detail: "approved installed runtime baseline"})
	}
	return withUnixSocketsReport(profile.CompileReport{Entries: entries}, p)
}
