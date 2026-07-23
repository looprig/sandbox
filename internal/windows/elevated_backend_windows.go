//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	sandboxnetwork "github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

var errElevatedBrokerDesktopAPI = errors.New("sandbox: broker-created private desktop capability is unavailable")

type elevatedRunnerLaunchFunc func(enforce.LaunchRequest, elevatedSetupSnapshot, win.Token, policy.Limits, brokerAccountKind) (int, error)

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

type elevatedLease interface {
	IssueToken(brokerAccountKind) (win.Token, error)
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
		launch:  launchElevatedRunner,
	}}
}

type elevatedInstallationVerifier interface {
	Verify(path, ownerSID string) error
}

type elevatedDependencyHealth struct {
	Accounts, Credentials, Firewall, RuntimeBaseline bool
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
	readiness, err := productionSetupDependencyInspector().Inspect(ctx, setup, manifest)
	if err != nil {
		return elevatedDependencyHealth{}, err
	}
	return elevatedDependencyHealth{
		Accounts:        readiness.accounts && readiness.service,
		Credentials:     readiness.credentials,
		Firewall:        readiness.firewallEffective && readiness.firewallUnchanged && len(readiness.portPID) == 0,
		RuntimeBaseline: readiness.runtimeBaseline,
	}, nil
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
	owner, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil || owner == nil || owner.User.Sid == nil || !equalSIDText(owner.User.Sid.String(), manifest.OwnerSID) {
		return elevatedSetupSnapshot{}, errors.Join(ErrSetupStale, errors.New("sandbox: ready manifest owner does not match the caller"), err)
	}
	if err := verifier.Verify(manifestPath, manifest.OwnerSID); err != nil {
		return elevatedSetupSnapshot{}, fmt.Errorf("%w: verify ready manifest protection: %v", ErrSetupStale, err)
	}
	if err := verifier.Verify(manifest.HostPath, manifest.OwnerSID); err != nil {
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
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
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
		// Job and handle-list properties are verified by the protected launcher.
		// PrivateDesktopReady remains false until the broker protocol can create
		// and ACL the desktop without granting the interactive owner access.
		PrivateDesktopReady: false, JobReadbackReady: true, HandleListReady: true,
		ProxyPorts: append([]uint16(nil), manifest.ProxyPorts...),
		PipeName:   `\\.\pipe\looprig-sandbox-` + strings.TrimPrefix(names.Service, "lsb-svc-"),
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

// acquireElevatedLease cannot safely manufacture the two capabilities that
// the current lower-level APIs do not expose:
//   - the service-selected authenticated connection nonce needed by brokerClient;
//   - a caller-side launcher that consumes the duplicated restricted token into
//     a suspended, Job-assigned, private-desktop installed runner process.
//
// Returning this typed activation error preserves stale-vs-absent setup
// classification and, critically, cannot fall back to the interactive token.
func acquireElevatedLease(snapshot elevatedSetupSnapshot, effective policy.Effective) (elevatedLease, error) {
	if err := validateElevatedSnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSetupStale, err)
	}
	if len(effective.FS) == 0 || len(effective.RuntimeBaselines) == 0 {
		return nil, fmt.Errorf("%w: elevated ACL policy is incomplete", enforce.ErrUnavailable)
	}
	return nil, fmt.Errorf("%w: %w", enforce.ErrUnavailable, errElevatedBrokerDesktopAPI)
}

func launchElevatedRunner(_ enforce.LaunchRequest, _ elevatedSetupSnapshot, token win.Token, _ policy.Limits, _ brokerAccountKind) (int, error) {
	if token != 0 {
		_ = token.Close()
	}
	return -1, fmt.Errorf("%w: %w", enforce.ErrUnavailable, errElevatedBrokerDesktopAPI)
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
	if p.Net.Open && p.Net.ProxyPort != 0 {
		return enforce.Spec{}, elevatedCompileReport(p, snapshot), profile.LevelNone, 0,
			fmt.Errorf("%w: online Windows policy cannot claim an offline proxy endpoint", enforce.ErrUnavailable)
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
		launch = launchElevatedRunner
	}
	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() { releaseErr = lease.Release() })
		return releaseErr
	}
	spec := enforce.Spec{
		Launch: func(request enforce.LaunchRequest) (int, error) {
			if request.Context == nil {
				return -1, errors.New("sandbox: elevated launch context is required")
			}
			if err := request.Context.Err(); err != nil {
				return -1, err
			}
			token, err := lease.IssueToken(account)
			if err != nil {
				return -1, fmt.Errorf("issue per-spawn restricted token: %w", err)
			}
			return launch(request, snapshot, token, p.Limits, account)
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

func elevatedGuaranteeBits(p policy.Effective) uint64 {
	bits := uint64(profile.GuaranteeProcessBoundary | profile.GuaranteeWriteBoundary |
		profile.GuaranteeReadBoundary | profile.GuaranteeResourceLimits)
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
		profile.GuaranteeReadBoundary | profile.GuaranteeResourceLimits)
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
	entries := []profile.ReportEntry{
		{Feature: "windows.installed-host", Status: status(snapshot.RunnerHashVerified), Detail: "protected installed runner hash and protocol"},
		{Feature: "windows.token", Status: status(snapshot.AccountsReady && snapshot.CredentialsReady), Detail: "broker-issued full restricted account token"},
		{Feature: "windows.filesystem.read", Status: status(snapshot.Ready), Detail: "broker-owned identity-bound ACL lease"},
		{Feature: "windows.filesystem.write", Status: status(snapshot.Ready), Detail: "broker-owned identity-bound ACL lease"},
		{Feature: "windows.job", Status: status(snapshot.JobReadbackReady), Detail: "kill-on-close Job with no breakaway"},
		{Feature: "windows.private-desktop", Status: status(snapshot.PrivateDesktopReady), Detail: "protected non-interactive window station and desktop"},
		{Feature: "windows.resource-limits", Status: status(snapshot.JobReadbackReady), Detail: "Job limits validated by read-back"},
	}
	for _, baseline := range p.RuntimeBaselines {
		entries = append(entries, profile.ReportEntry{Feature: baseline, Status: status(snapshot.RuntimeBaselineReady), Detail: "approved installed runtime baseline"})
	}
	return profile.CompileReport{Entries: entries}
}
