//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// elevatedSetupSnapshot is the compiler's immutable, already-verified view of
// the installed tier. Individual mechanism checks remain explicit so a future
// addition cannot accidentally become healthy merely because the manifest is
// ready.
type elevatedSetupSnapshot struct {
	Ready                 bool
	HostPath              string
	HostSHA256            string
	Protocol              uint16
	AccountsReady         bool
	CredentialsReady      bool
	FirewallReady         bool
	RuntimeBaselineReady  bool
	RunnerHashVerified    bool
	PrivateDesktopReady   bool
	JobReadbackReady      bool
	HandleListReady       bool
}

type elevatedLease interface {
	// Wrap creates fresh per-spawn state. Implementations must issue only the
	// restricted account token and must seal argv/cwd before returning.
	Wrap(dir string, argv []string, account brokerAccountKind) ([]string, func(*exec.Cmd) error, func(), error)
	Release() error
}

type elevatedCompileDependencies struct {
	inspect func(Config, policy.Effective) (elevatedSetupSnapshot, error)
	acquire func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error)
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
	}}
}

// inspectElevatedSetup deliberately remains closed until the setup health
// inspector can prove all Task 15-17 dependencies and the approved runtime
// baseline. A ready manifest alone is not evidence for those properties.
func inspectElevatedSetup(Config, policy.Effective) (elevatedSetupSnapshot, error) {
	return elevatedSetupSnapshot{}, ErrSetupRequired
}

// acquireElevatedLease is unreachable until inspectElevatedSetup can return a
// complete snapshot. Keeping this seam explicit prevents an interactive-token
// fallback while the installed client composition is unavailable.
func acquireElevatedLease(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
	return nil, ErrSetupRequired
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
	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() { releaseErr = lease.Release() })
		return releaseErr
	}
	spec := enforce.Spec{
		Wrap: func(dir string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
			final, configure, cleanup, wrapErr := lease.Wrap(dir, append([]string(nil), argv...), account)
			if wrapErr != nil {
				return nil, func(*exec.Cmd) error { return wrapErr }, cleanup
			}
			return final, configure, cleanup
		},
		Release: release,
	}
	level := profile.LevelDegraded
	if elevatedFullLevel(p, bits) {
		level = profile.LevelFull
	}
	return spec, elevatedCompileReport(p, snapshot), level, bits, nil
}

func validateElevatedSnapshot(snapshot elevatedSetupSnapshot) error {
	if !snapshot.Ready || snapshot.HostPath == "" || snapshot.HostSHA256 == "" ||
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
	// Task 20 owns offline network composition. Online mode deliberately claims
	// no network boundary, and this phase never infers one from account choice.
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
