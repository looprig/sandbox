//go:build windows

package windows

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/winpath"
	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

type restrictedCompileDependencies struct {
	prepare              func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error)
	configure            func(*exec.Cmd, []SID) (func(), error)
	newGrantSIDGenerator func(*RestrictedJournal) (*OneShotSIDGenerator, error)
	validateTrustees     func([]SID) error
	projectGrant         func(*policy.PathHandle, []policy.FSEntry, SID, *RestrictedJournal, io.Reader) (*ACLProjection, error)
}

// restrictedBackend is shared by every executor of one ExecutorSet (the set
// selects the backend once and each keyed executor compiles its own base
// spec against it), so it holds NO per-executor state: each Compile prepares
// its own base lease and hands it back on the spec as a
// restrictedGrantAuthority, and each executor's grants are compiled against
// the authority on that executor's own spec (CompileWithGrantAuthority). An
// earlier version kept a single "active base lease" on the backend, which
// refused a second executor's Compile — and therefore every second executor
// of a set — with "restricted backend base lease is already active".
type restrictedBackend struct {
	config  Config
	runtime *RestrictedRuntime
	deps    restrictedCompileDependencies
}

// autoBackend prefers the installed tier. It falls back only when that tier is
// unavailable, never after a malformed/partially constructed elevated result.
// The restricted compiler independently rejects requirements it cannot prove.
type autoBackend struct {
	elevated   enforce.Backend
	restricted enforce.Backend
}

// ReserveEgressProxy deliberately forwards only to the installed tier. A
// target-scoped route requires the offline firewall boundary, which the
// restricted-token fallback cannot prove; falling back to an ephemeral
// listener here would create a bypass before Compile gets a chance to reject
// the policy.
func (backend *autoBackend) ReserveEgressProxy(route network.Route) (*network.Proxy, func() error, error) {
	if backend == nil || backend.elevated == nil {
		return nil, nil, errors.New("sandbox: invalid Windows auto proxy backend")
	}
	provider, ok := backend.elevated.(interface {
		ReserveEgressProxy(network.Route) (*network.Proxy, func() error, error)
	})
	if !ok {
		return nil, nil, ErrSetupRequired
	}
	return provider.ReserveEgressProxy(route)
}

// CompileWithGrantAuthority routes a grant compile to the tier whose base
// spec issued authority. A restricted authority goes to the restricted
// fallback, which compiles the grant against that executor's own base lease;
// anything else keeps Auto's previous behaviour exactly — a full Compile of
// the grant policy — because Auto forwarded no grant-path compile before
// this method existed.
func (backend *autoBackend) CompileWithGrantAuthority(authority any, base, p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if backend == nil || backend.elevated == nil || backend.restricted == nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, errors.New("sandbox: invalid Windows auto backend")
	}
	if _, restricted := authority.(*restrictedGrantAuthority); restricted {
		compiler, ok := backend.restricted.(interface {
			CompileWithGrantAuthority(any, policy.Effective, policy.Effective, []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error)
		})
		if !ok {
			return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, errors.New("sandbox: Windows auto restricted tier cannot compile grants")
		}
		return compiler.CompileWithGrantAuthority(authority, base, p, handles)
	}
	return backend.Compile(p)
}

// SupportsGrantClass answers the executor's side-effect-free grant preflight
// with the elevated tier's answer, and refuses everything if the elevated
// backend cannot answer. Without this method the executor treats Auto as
// supporting every class and consumes a signed grant (network.broad.v1,
// filesystem.host.*) that Compile then rejects. Auto picks a tier per Compile,
// so the preflight cannot know which tier will compile; the elevated answer is
// the right bound because the restricted fallback never widens it: that tier
// rejects every network grant in Compile, and the one class the elevated tier
// accepts that the fallback refuses, network.proxy-target.v1, needs an egress
// route Auto reserves only through the installed tier (ReserveEgressProxy).
func (backend *autoBackend) SupportsGrantClass(class string) bool {
	if backend == nil {
		return false
	}
	support, ok := backend.elevated.(interface{ SupportsGrantClass(string) bool })
	return ok && support.SupportsGrantClass(class)
}

func (backend *autoBackend) Compile(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if backend == nil || backend.elevated == nil || backend.restricted == nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, errors.New("sandbox: invalid Windows auto backend")
	}
	spec, report, level, bits, err := backend.elevated.Compile(policy.Clone(p))
	if err == nil {
		return spec, report, level, bits, nil
	}
	if !errors.Is(err, ErrSetupRequired) {
		return spec, report, level, bits, err
	}
	return backend.restricted.Compile(policy.Clone(p))
}

func newRestrictedBackend(config Config, runtime *RestrictedRuntime) enforce.Backend {
	return &restrictedBackend{config: config, runtime: runtime, deps: restrictedCompileDependencies{
		prepare:   prepareRestrictedLease,
		configure: configureRestrictedSpawn,
		newGrantSIDGenerator: func(journal *RestrictedJournal) (*OneShotSIDGenerator, error) {
			return NewOneShotSIDGenerator(rand.Reader, journal)
		},
		validateTrustees: ensureModuleTrusteesAbsentFromCurrentToken,
		projectGrant:     projectRestrictedGrant,
	}}
}

func (backend *restrictedBackend) Compile(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if backend == nil || backend.deps.prepare == nil || backend.deps.configure == nil {
		return enforce.Spec{}, profile.CompileReport{}, profile.LevelNone, 0, errors.New("sandbox: invalid Windows restricted backend")
	}
	bits := uint64(0)
	if !p.Env.Inherit {
		bits = profile.GuaranteeEnvScrub
	}
	// AF_UNIX is refused before anything else: no lease, SID or journal
	// record may be created for a profile this tier can never honor.
	if unixSocketsRequested(p) {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, refuseUnixSockets("restricted")
	}
	if missing := p.RequiredGuarantees &^ bits; missing != 0 {
		if backend.config.Mode == Auto {
			return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits,
				fmt.Errorf("%w: missing guarantees %s", ErrSetupRequired, formatGuaranteeBits(missing))
		}
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits,
			fmt.Errorf("%w: Windows restricted mode missing guarantees %s", enforce.ErrUnavailable, formatGuaranteeBits(missing))
	}
	if err := validateRestrictedGrantClasses(p); err != nil {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, err
	}
	lease, err := backend.deps.prepare(backend.config, backend.runtime, policy.Clone(p))
	if err != nil {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, err
	}
	if !lease.sid.isRestrictedTierTrustee() || lease.release == nil {
		if lease.release != nil {
			err = errors.Join(err, lease.release())
		}
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits,
			errors.Join(errors.New("sandbox: restricted compile returned an invalid lease"), err)
	}
	// One lease per Compile, i.e. per executor: the authority below carries
	// it to this executor's grant compiles and its retire is this spec's
	// Release.
	authority := newRestrictedGrantAuthority(p, lease)
	configure := backend.deps.configure
	spec := enforce.Spec{
		Wrap: func(_ string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
			argv := append([]string(nil), innerArgv...)
			var cleanup func()
			var cleanupOnce sync.Once
			return argv, func(cmd *exec.Cmd) error {
					var err error
					cleanup, err = configure(cmd, []SID{lease.sid})
					return err
				}, func() {
					cleanupOnce.Do(func() {
						if cleanup != nil {
							cleanup()
						}
					})
				}
		},
		Release:        authority.retire,
		GrantAuthority: authority,
	}
	return spec, restrictedCompileReport(p), profile.LevelNone, bits, nil
}

func formatGuaranteeBits(bits uint64) string {
	names := []struct {
		bit  uint64
		name string
	}{
		{profile.GuaranteeProcessBoundary, "ProcessBoundary"}, {profile.GuaranteeWriteBoundary, "WriteBoundary"},
		{profile.GuaranteeReadBoundary, "ReadBoundary"}, {profile.GuaranteeEnvScrub, "EnvScrub"},
		{profile.GuaranteeNetworkBoundary, "NetworkBoundary"}, {profile.GuaranteeAddressNetwork, "AddressNetwork"},
		{profile.GuaranteeResourceLimits, "ResourceLimits"}, {profile.GuaranteeTargetNetwork, "TargetNetwork"},
	}
	var result []string
	known := uint64(0)
	for _, item := range names {
		known |= item.bit
		if bits&item.bit != 0 {
			result = append(result, item.name)
		}
	}
	if unknown := bits &^ known; unknown != 0 {
		result = append(result, fmt.Sprintf("unknown(%#x)", unknown))
	}
	return strings.Join(result, ",")
}

// CompileWithGrantAuthority compiles transient grant authority against the
// base lease of the executor whose spec issued rawAuthority (its
// enforce.Spec.GrantAuthority), with base the policy that executor compiled.
// It is used for every grant compile, with or without path handles: a grant
// with none still runs under the executor's base SID and projections. It
// borrows each caller-owned handle and never reacquires a grant target by
// path.
func (backend *restrictedBackend) CompileWithGrantAuthority(rawAuthority any, base, p policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	bits := uint64(0)
	if !p.Env.Inherit {
		bits = profile.GuaranteeEnvScrub
	}
	if unixSocketsRequested(p) {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, refuseUnixSockets("restricted")
	}
	if missing := p.RequiredGuarantees &^ bits; missing != 0 {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, fmt.Errorf("%w: Windows restricted grant missing guarantees %s", enforce.ErrUnavailable, formatGuaranteeBits(missing))
	}
	if err := validateRestrictedGrantClassesWithoutReopen(p); err != nil {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, err
	}
	authority, _ := rawAuthority.(*restrictedGrantAuthority)
	baseSID, journal, giveBack, err := authority.borrow(base)
	if err != nil {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, err
	}
	resources := &restrictedLeaseResources{}
	sids := []SID{baseSID}
	fail := func(cause error) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
		return enforce.Spec{}, restrictedCompileReport(p), profile.LevelNone, bits, errors.Join(cause, resources.close(), giveBack())
	}
	var generator *OneShotSIDGenerator
	if len(handles) != 0 {
		if backend.deps.newGrantSIDGenerator == nil || backend.deps.validateTrustees == nil || backend.deps.projectGrant == nil {
			return fail(errors.New("sandbox: restricted grant dependencies are unavailable"))
		}
		var generatorErr error
		generator, generatorErr = backend.deps.newGrantSIDGenerator(journal)
		if generatorErr != nil {
			return fail(generatorErr)
		}
	}
	for _, handle := range handles {
		if handle == nil || handle.NativeHandle() == 0 || handle.Access() == 0 {
			return fail(fmt.Errorf("%w: invalid retained Windows grant handle", policy.ErrUnsupportedClass))
		}
		sid, err := generator.Next()
		if err != nil {
			return fail(err)
		}
		if err := backend.deps.validateTrustees([]SID{sid}); err != nil {
			return fail(fmt.Errorf("validate one-shot trustee before ACL projection: %w", err))
		}
		projection, err := backend.deps.projectGrant(handle, p.FS, sid, journal, rand.Reader)
		if err != nil {
			return fail(err)
		}
		resources.projections = append(resources.projections, projection)
		sids = append(sids, sid)
	}
	configure := backend.deps.configure
	var releaseOnce sync.Once
	var releaseErr error
	return enforce.Spec{
		Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
			var cleanup func()
			var once sync.Once
			return append([]string(nil), argv...), func(cmd *exec.Cmd) (err error) {
					cleanup, err = configure(cmd, append([]SID(nil), sids...))
					return err
				}, func() {
					once.Do(func() {
						if cleanup != nil {
							cleanup()
						}
					})
				}
		},
		// The grant's own projections go first, then the borrow: if the base
		// spec was released meanwhile, giving the borrow back is what finally
		// releases the base lease.
		Release: func() error {
			releaseOnce.Do(func() { releaseErr = errors.Join(resources.close(), giveBack()) })
			return releaseErr
		},
	}, restrictedCompileReport(p), profile.LevelNone, bits, nil
}

func validateRestrictedGrantClassesWithoutReopen(p policy.Effective) error {
	if p.Net.Loopback || p.Net.Private || p.Net.DNS || p.Net.ProxyPort != 0 || len(p.Net.Ports) != 0 {
		return fmt.Errorf("%w: Windows restricted mode does not support network grants", policy.ErrUnsupportedClass)
	}
	return nil
}

func restrictedCompileReport(p policy.Effective) profile.CompileReport {
	entries := []profile.ReportEntry{
		{Feature: "windows.token", Status: "Narrowed", Detail: "restricted-token defense in depth; no end-to-end boundary claimed. " +
			"Restricting SIDs: the executor, its grants, and the session logon SID for window-station/desktop access (WRITE_RESTRICTED, so they gate writes only; " +
			"the logon SID also passes writes to whatever the logon session's objects grant it)"},
		{Feature: "windows.filesystem.write", Status: "Narrowed", Detail: "restricting SID ACL projection; a same-user COM/WMI broker can write outside it, and WRITE_RESTRICTED does not restrict an owner's DELETE, WRITE_DAC or WRITE_OWNER. " +
			"No-delete-sharing handles are retained only on the projected roots, write-denied carveouts and their ancestor directories; every other workspace file stays renameable and deletable for the lease, and an object the user moves out of a root keeps its inherited allow for this lease's one-shot SID (inert after the lease: that SID is never reissued)"},
		{Feature: "windows.job", Status: "Narrowed", Detail: "direct process tree only; a same-user COM/WMI broker can start a process outside the Job. " +
			"A pipe-backed child runs on its own hidden console (CREATE_NO_WINDOW), not the host's, so cooperative interrupt is unavailable and Kill terminates the Job; a TTY child has its own pseudo console"},
		{Feature: "windows.private-desktop", Status: "Narrowed", Detail: "Job UI restrictions only; no private desktop in restricted mode"},
		{Feature: "windows.resource-limits", Status: "Narrowed", Detail: "direct Job limits only; broker escape remains possible"},
		{Feature: "windows.env-scrub", Status: "Narrowed", Detail: "scrubs only the child's own environment block; a same-user child can read the host process's memory, including its environment"},
	}
	for _, baseline := range p.RuntimeBaselines {
		entries = append(entries, profile.ReportEntry{Feature: baseline, Status: "Narrowed", Detail: "platform runtime baseline; no read boundary claimed"})
	}
	return withUnixSocketsReport(profile.CompileReport{Entries: entries}, p)
}

func validateRestrictedGrantClasses(p policy.Effective) error {
	if p.Net.Loopback || p.Net.Private || p.Net.DNS || p.Net.ProxyPort != 0 || len(p.Net.Ports) != 0 {
		return fmt.Errorf("%w: Windows restricted mode does not support network grants", policy.ErrUnsupportedClass)
	}
	for _, entry := range p.FS {
		if !entry.Canonical {
			continue
		}
		if strings.ContainsAny(entry.Path, policy.GlobMeta) || entry.Access == 0 {
			return fmt.Errorf("%w: unsupported Windows filesystem grant", policy.ErrUnsupportedClass)
		}
		binding, err := policy.CapturePathBinding(entry.Path)
		if err != nil {
			return fmt.Errorf("%w: %v", policy.ErrUnsupportedClass, err)
		}
		handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, entry.Exact)
		if err != nil {
			return fmt.Errorf("%w: %v", policy.ErrUnsupportedClass, err)
		}
		_ = handle.Close()
	}
	return nil
}

type restrictedLeaseResources struct {
	projections []*ACLProjection
	mu          sync.Mutex
	closed      bool
}

func (resources *restrictedLeaseResources) close() error {
	if resources == nil {
		return nil
	}
	resources.mu.Lock()
	defer resources.mu.Unlock()
	if resources.closed {
		return nil
	}
	resources.closed = true
	var result error
	for index := len(resources.projections) - 1; index >= 0; index-- {
		result = errors.Join(result, resources.projections[index].Close())
	}
	resources.projections = nil
	return result
}

func prepareRestrictedLease(_ Config, runtime *RestrictedRuntime, p policy.Effective) (_ restrictedPreparedLease, err error) {
	journal, err := runtime.restrictedJournal()
	if err != nil {
		return restrictedPreparedLease{}, fmt.Errorf("sweep restricted ACL journal: %w", err)
	}
	stateRoot, err := restrictedStateRoot(runtime.scratchRoot)
	if err != nil {
		return restrictedPreparedLease{}, err
	}
	sid, err := newRetiredExecutorSID(rand.Reader, journal, stateRoot)
	if err != nil {
		return restrictedPreparedLease{}, err
	}
	if err := ensureModuleTrusteesAbsentFromCurrentToken([]SID{sid}); err != nil {
		return restrictedPreparedLease{}, fmt.Errorf("validate executor trustee before ACL projection: %w", err)
	}
	resources := &restrictedLeaseResources{}
	defer func() {
		if err != nil {
			err = errors.Join(err, resources.close())
		}
	}()
	for _, entry := range writableProjectionRoots(p.FS, p.ProjectionRoots) {
		projection, projectErr := projectRestrictedRoot(entry, p.FS, sid, journal, rand.Reader)
		if projectErr != nil {
			return restrictedPreparedLease{}, projectErr
		}
		resources.projections = append(resources.projections, projection)
	}
	return restrictedPreparedLease{sid: sid, journal: journal, release: resources.close}, nil
}

func restrictedStateRoot(configured string) (string, error) {
	if configured == "" {
		return "", errors.New("sandbox: stable restricted scratch root is required")
	}
	return filepath.Abs(configured)
}

func newRetiredExecutorSID(source io.Reader, store SIDRetirementStore, namespace string) (SID, error) {
	if source == nil || store == nil || namespace == "" {
		return SID{}, errors.New("sandbox: executor SID generator is not configured")
	}
	for attempt := 0; attempt < 8; attempt++ {
		entropy := make([]byte, sidEntropyBytes)
		if _, err := io.ReadFull(source, entropy); err != nil {
			return SID{}, fmt.Errorf("generate executor Windows SID: %w", err)
		}
		sid, err := ExecutorSID(namespace, hex.EncodeToString(entropy))
		if err != nil {
			return SID{}, err
		}
		retired, err := store.RetireSID(sid)
		if err != nil {
			return SID{}, fmt.Errorf("retire executor Windows SID: %w", err)
		}
		if retired {
			return sid, nil
		}
	}
	return SID{}, ErrSIDReuse
}

func writableProjectionRoots(entries []policy.FSEntry, projectionRoots []string) []policy.FSEntry {
	var candidates []policy.FSEntry
	for _, entry := range entries {
		if !slices.ContainsFunc(projectionRoots, func(path string) bool { return winpath.EqualPath(path, entry.Path) }) ||
			entry.Access&policy.WriteAccess == 0 || entry.Exact || strings.ContainsAny(entry.Path, policy.GlobMeta) {
			continue
		}
		candidates = append(candidates, entry)
	}
	slices.SortFunc(candidates, func(left, right policy.FSEntry) int { return winpath.Compare(left.Path, right.Path) })
	var roots []policy.FSEntry
	for _, entry := range candidates {
		covered := false
		for _, root := range roots {
			if policy.LiteralMatches(root.Path, entry.Path, false) {
				covered = true
				break
			}
		}
		if !covered {
			roots = append(roots, entry)
		}
	}
	return roots
}

func projectRestrictedRoot(root policy.FSEntry, entries []policy.FSEntry, sid SID, journal *RestrictedJournal, entropy io.Reader) (*ACLProjection, error) {
	clean := filepath.Clean(root.Path)
	if volume := filepath.VolumeName(clean); volume == "" || winpath.EqualPath(clean, volume+`\`) {
		return nil, fmt.Errorf("%w: projected Windows root must be below a supported local volume root", policy.ErrUnsupportedClass)
	}
	binding, err := policy.CapturePathBinding(root.Path)
	if err != nil {
		return nil, err
	}
	handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, false)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	tree, err := EnumerateSharedACLTree(handle)
	if err != nil {
		return nil, err
	}
	defer func() {
		if tree != nil {
			_ = tree.Close()
		}
	}()
	var leaseID ACLLeaseID
	if _, err := io.ReadFull(entropy, leaseID[:]); err != nil || leaseID == (ACLLeaseID{}) {
		return nil, errors.Join(errors.New("generate restricted ACL lease identity"), err)
	}
	request := ACLPlanRequest{LeaseID: leaseID, SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: tree.Root()}
	for _, child := range tree.Entries() {
		deny := ACLAccess(0)
		if child.Object.Kind != ACLObjectReparsePoint {
			path := filepath.Join(binding.CanonicalPath, child.RelativePath)
			if policy.ResolveFS(entries, path)&policy.WriteAccess == 0 {
				deny = ACLWrite
			}
		}
		request.Entries = append(request.Entries, ACLPlanEntry{Object: child.Object, Deny: deny})
	}
	plan, err := BuildACLPlan(request)
	if err != nil {
		return nil, err
	}
	projection, err := NewRestrictedACLTreeProjection(plan, tree, journal)
	if err != nil {
		return nil, err
	}
	tree = nil
	if err := projection.Apply(); err != nil {
		_ = projection.Close()
		return nil, err
	}
	return projection, nil
}

func projectRestrictedGrant(handle *policy.PathHandle, entries []policy.FSEntry, sid SID, journal *RestrictedJournal, entropy io.Reader) (*ACLProjection, error) {
	var leaseID ACLLeaseID
	if _, err := io.ReadFull(entropy, leaseID[:]); err != nil || leaseID == (ACLLeaseID{}) {
		return nil, errors.Join(errors.New("generate restricted grant lease identity"), err)
	}
	access := ACLAccess(0)
	if handle.Access()&policy.ReadAccess != 0 {
		access |= ACLRead
	}
	if handle.Access()&policy.ExecAccess != 0 {
		access |= ACLExecute
	}
	if handle.Access()&policy.WriteAccess != 0 {
		access |= ACLWrite
	}
	if access == 0 {
		return nil, fmt.Errorf("%w: empty Windows grant access", policy.ErrUnsupportedClass)
	}
	if handle.Exact() {
		identity, err := identityFromHandle(win.Handle(handle.NativeHandle()), handle.Target())
		if err != nil {
			return nil, err
		}
		plan, err := BuildACLPlan(ACLPlanRequest{LeaseID: leaseID, SID: sid, Scope: ACLScopeExact, Access: access, Root: identity})
		if err != nil {
			return nil, err
		}
		projection, err := NewRestrictedACLProjection(plan, []*policy.PathHandle{handle}, journal)
		if err != nil {
			return nil, err
		}
		if err := projection.Apply(); err != nil {
			_ = projection.Close()
			return nil, err
		}
		return projection, nil
	}
	if !handle.IsDir() {
		return nil, fmt.Errorf("%w: tree grant is not a directory", policy.ErrUnsupportedClass)
	}
	tree, err := EnumerateSharedACLTree(handle)
	if err != nil {
		return nil, err
	}
	request := ACLPlanRequest{LeaseID: leaseID, SID: sid, Scope: ACLScopeTree, Access: access, Root: tree.Root()}
	for _, child := range tree.Entries() {
		deny := ACLAccess(0)
		if child.Object.Kind != ACLObjectReparsePoint {
			resolved := policy.ResolveFS(entries, filepath.Join(handle.Target(), child.RelativePath))
			if resolved&policy.ReadAccess == 0 {
				deny |= ACLRead
			}
			if resolved&policy.ExecAccess == 0 {
				deny |= ACLExecute
			}
			if resolved&policy.WriteAccess == 0 {
				deny |= ACLWrite
			}
		}
		request.Entries = append(request.Entries, ACLPlanEntry{Object: child.Object, Deny: deny})
	}
	plan, err := BuildACLPlan(request)
	if err != nil {
		_ = tree.Close()
		return nil, err
	}
	projection, err := NewRestrictedACLTreeProjection(plan, tree, journal)
	if err != nil {
		_ = tree.Close()
		return nil, err
	}
	if err := projection.Apply(); err != nil {
		_ = projection.Close()
		return nil, err
	}
	return projection, nil
}

func configureRestrictedSpawn(cmd *exec.Cmd, sids []SID) (func(), error) {
	if cmd == nil || len(sids) == 0 {
		return nil, errors.New("sandbox: invalid restricted Windows spawn")
	}
	for _, sid := range sids {
		if !sid.isRestrictedTierTrustee() {
			return nil, errors.New("sandbox: invalid restricted Windows spawn SID")
		}
	}
	// TOKEN_ASSIGN_PRIMARY is required although this process never assigns
	// the SOURCE token: CreateRestrictedToken returns the new token's handle
	// with the same access rights as the source handle, and
	// CreateProcessAsUser (syscall.StartProcess with SysProcAttr.Token, and
	// the ConPTY launch) requires TOKEN_QUERY, TOKEN_DUPLICATE and
	// TOKEN_ASSIGN_PRIMARY on the token it launches with. Without it
	// CreateProcessAsUser refuses every restricted-tier launch with
	// ERROR_ACCESS_DENIED whatever the image — the documented explanation for
	// the first Windows CI run's "fork/exec ...policy-enforcement.test.exe:
	// Access is denied.".
	// (internal/exec now wraps such a refusal with the token handle's granted
	// access, so a recurrence names the missing right.)
	var source win.Token
	if err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_DUPLICATE|win.TOKEN_QUERY|win.TOKEN_ASSIGN_PRIMARY, &source); err != nil {
		return nil, fmt.Errorf("open source token for restricted spawn: %w", err)
	}
	token, err := CreateRestrictedToken(source, sids)
	_ = source.Close()
	if err != nil {
		return nil, err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(token)
	var once sync.Once
	return func() {
		once.Do(func() {
			cmd.SysProcAttr.Token = 0
			_ = token.Close()
		})
	}, nil
}
