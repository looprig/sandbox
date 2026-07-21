package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const currentAccessVersion uint16 = 1

// Access is the requested authority for one profile capability.
type Access uint8

const (
	Deny  Access = 0
	Gated Access = 1
	Allow Access = 2
)

// Home selects the HOME value exposed to a child process.
type Home uint8

const (
	IsolatedHome Home = iota
	RealHome
)

// Isolation selects whether process authority is OS-confined.
type Isolation uint8

const (
	Sandboxed Isolation = iota
	Unconfined
)

// RootAccess describes read and write authority for one additional root.
type RootAccess struct {
	Path  string
	Read  Access
	Write Access
}

// ProfileConfig contains every consumer-selected sandbox authority value.
type ProfileConfig struct {
	WorkspaceRoot   string
	WorkspaceRead   Access
	WorkspaceWrite  Access
	HostRead        Access
	HostWrite       Access
	Network         Access
	Command         Access
	Home            Home
	Isolation       Isolation
	AdditionalRoots []RootAccess
	AckUnconfined   bool
}

// ErrInvalidProfile identifies malformed, unconstructed, or inconsistent
// profiles. Details are wrapped for diagnostics; callers may use errors.Is.
var ErrInvalidProfile = errors.New("sandbox: invalid profile")

// Profile is an immutable, normalized access profile.
type Profile struct {
	version            uint16
	workspaceRoot      string
	workspaceRead      Access
	workspaceWrite     Access
	hostRead           Access
	hostWrite          Access
	network            Access
	command            Access
	home               Home
	isolation          Isolation
	additionalRoots    []RootAccess
	ackUnconfined      bool
	requiredGuarantees uint64
	fingerprint        string
}

// NewProfile validates, canonicalizes, and owns a copy of config.
func NewProfile(config ProfileConfig) (*Profile, error) {
	workspace, err := CanonicalRoot(config.WorkspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: workspace root: %v", ErrInvalidProfile, err)
	}
	for name, value := range map[string]Access{
		"workspace read":  config.WorkspaceRead,
		"workspace write": config.WorkspaceWrite,
		"host read":       config.HostRead,
		"host write":      config.HostWrite,
		"network":         config.Network,
		"command":         config.Command,
	} {
		if !validAccess(value) {
			return nil, fmt.Errorf("%w: %s access %d", ErrInvalidProfile, name, value)
		}
	}
	if config.Home != IsolatedHome && config.Home != RealHome {
		return nil, fmt.Errorf("%w: home %d", ErrInvalidProfile, config.Home)
	}
	if config.Isolation != Sandboxed && config.Isolation != Unconfined {
		return nil, fmt.Errorf("%w: isolation %d", ErrInvalidProfile, config.Isolation)
	}

	roots := make([]RootAccess, 0, len(config.AdditionalRoots))
	seen := make(map[string]RootAccess, len(config.AdditionalRoots))
	for i, root := range config.AdditionalRoots {
		if !validAccess(root.Read) || !validAccess(root.Write) {
			return nil, fmt.Errorf("%w: additional root %d has unknown access", ErrInvalidProfile, i)
		}
		path, err := CanonicalRoot(root.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: additional root %d: %v", ErrInvalidProfile, i, err)
		}
		if path == workspace {
			return nil, fmt.Errorf("%w: additional root duplicates workspace", ErrInvalidProfile)
		}
		normalized := RootAccess{Path: path, Read: root.Read, Write: root.Write}
		if prior, ok := seen[path]; ok {
			if prior.Read != normalized.Read || prior.Write != normalized.Write {
				return nil, fmt.Errorf("%w: contradictory additional root %q", ErrInvalidProfile, path)
			}
			continue
		}
		seen[path] = normalized
		roots = append(roots, normalized)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Path < roots[j].Path })

	p := &Profile{
		version:         currentAccessVersion,
		workspaceRoot:   workspace,
		workspaceRead:   config.WorkspaceRead,
		workspaceWrite:  config.WorkspaceWrite,
		hostRead:        config.HostRead,
		hostWrite:       config.HostWrite,
		network:         config.Network,
		command:         config.Command,
		home:            config.Home,
		isolation:       config.Isolation,
		additionalRoots: roots,
		ackUnconfined:   config.AckUnconfined,
	}
	if err := p.validateUnconfined(); err != nil {
		return nil, err
	}
	p.requiredGuarantees = deriveRequiredGuarantees(p)
	p.fingerprint, err = profileFingerprint(p)
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprint: %v", ErrInvalidProfile, err)
	}
	return p, nil
}

// CanonicalRoot resolves path to an absolute, symlink-free, existing
// directory. It is the canonicalization every configured root is held to.
func CanonicalRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func validAccess(access Access) bool { return access <= Allow }

// Validate reports whether p was constructed by NewProfile and carries the
// current ABI. It returns ErrInvalidProfile for a nil, zero, or stale Profile.
func (p *Profile) Validate() error {
	if p == nil || p.version != currentAccessVersion || p.workspaceRoot == "" || p.fingerprint == "" {
		return ErrInvalidProfile
	}
	return nil
}

func (p *Profile) validateUnconfined() error {
	if p.isolation != Unconfined {
		if p.ackUnconfined {
			return fmt.Errorf("%w: unconfined acknowledgement on sandboxed profile", ErrInvalidProfile)
		}
		return nil
	}
	if !p.ackUnconfined {
		return fmt.Errorf("%w: unconfined execution is not acknowledged", ErrInvalidProfile)
	}
	if p.workspaceRead != Allow || p.workspaceWrite != Allow || p.hostRead != Allow || p.hostWrite != Allow || p.network != Allow {
		return fmt.Errorf("%w: unconfined filesystem and network access must be Allow", ErrInvalidProfile)
	}
	for _, root := range p.additionalRoots {
		if root.Read != Allow || root.Write != Allow {
			return fmt.Errorf("%w: unconfined additional-root access must be Allow", ErrInvalidProfile)
		}
	}
	return nil
}

// AccessVersion reports the primitive profile ABI. An unconstructed Profile
// reports zero, which consumers must reject as unsupported.
func (p *Profile) AccessVersion() uint16 {
	if p == nil || p.version != currentAccessVersion || p.fingerprint == "" {
		return 0
	}
	return currentAccessVersion
}

// AccessFor returns the fixed numeric Access value for a normalized kind/scope.
func (p *Profile) AccessFor(kind, scope string) (uint8, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	switch kind {
	case "command.execute":
		if scope != "" {
			return 0, fmt.Errorf("%w: command scope must be empty", ErrInvalidProfile)
		}
		return uint8(p.command), nil
	case "network":
		if scope != "" {
			return 0, fmt.Errorf("%w: network scope must be empty", ErrInvalidProfile)
		}
		return uint8(p.network), nil
	case "filesystem.read", "filesystem.write":
		access, err := p.filesystemAccess(kind == "filesystem.write", scope)
		return uint8(access), err
	default:
		return 0, fmt.Errorf("%w: unknown access kind %q", ErrInvalidProfile, kind)
	}
}

func (p *Profile) filesystemAccess(write bool, scope string) (Access, error) {
	if scope == "host:*" {
		if write {
			return p.hostWrite, nil
		}
		return p.hostRead, nil
	}
	tree := strings.HasPrefix(scope, "tree:")
	path := scope
	if tree {
		path = strings.TrimPrefix(scope, "tree:")
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Deny, fmt.Errorf("%w: malformed filesystem scope %q", ErrInvalidProfile, scope)
	}
	if tree && !p.isConfiguredRoot(path) {
		return Deny, fmt.Errorf("%w: tree scope is not a configured root %q", ErrInvalidProfile, path)
	}
	return p.accessAtPath(write, path), nil
}

func (p *Profile) isConfiguredRoot(path string) bool {
	if path == p.workspaceRoot {
		return true
	}
	for _, root := range p.additionalRoots {
		if root.Path == path {
			return true
		}
	}
	return false
}

func (p *Profile) accessAtPath(write bool, path string) Access {
	bestPath := ""
	var best Access
	if PathWithin(path, p.workspaceRoot) {
		bestPath = p.workspaceRoot
		if write {
			best = p.workspaceWrite
		} else {
			best = p.workspaceRead
		}
	}
	for _, root := range p.additionalRoots {
		if PathWithin(path, root.Path) && len(root.Path) > len(bestPath) {
			bestPath = root.Path
			if write {
				best = root.Write
			} else {
				best = root.Read
			}
		}
	}
	if bestPath != "" {
		return best
	}
	if write {
		return p.hostWrite
	}
	return p.hostRead
}

// PathWithin reports whether path is root itself or lies beneath it.
func PathWithin(path, root string) bool {
	if root == string(filepath.Separator) {
		return true
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// Fingerprint returns the deterministic digest of all normalized authority.
func (p *Profile) Fingerprint() string {
	if p == nil || p.Validate() != nil {
		return ""
	}
	return p.fingerprint
}

func profileFingerprint(p *Profile) (string, error) {
	payload := struct {
		Version            uint16
		WorkspaceRoot      string
		WorkspaceRead      Access
		WorkspaceWrite     Access
		HostRead           Access
		HostWrite          Access
		Network            Access
		Command            Access
		Home               Home
		Isolation          Isolation
		AdditionalRoots    []RootAccess
		AckUnconfined      bool
		RequiredGuarantees uint64
	}{
		p.version, p.workspaceRoot, p.workspaceRead, p.workspaceWrite,
		p.hostRead, p.hostWrite, p.network, p.command, p.home, p.isolation,
		p.additionalRoots, p.ackUnconfined, p.requiredGuarantees,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// Restrict returns the component-wise intersection of base and ceiling.
func Restrict(base, ceiling *Profile) (*Profile, error) {
	if err := base.Validate(); err != nil {
		return nil, err
	}
	if err := ceiling.Validate(); err != nil {
		return nil, err
	}
	if base.workspaceRoot != ceiling.workspaceRoot {
		return nil, fmt.Errorf("%w: workspace roots differ", ErrInvalidProfile)
	}
	config := ProfileConfig{
		WorkspaceRoot:  base.workspaceRoot,
		WorkspaceRead:  minAccess(base.workspaceRead, ceiling.workspaceRead),
		WorkspaceWrite: minAccess(base.workspaceWrite, ceiling.workspaceWrite),
		HostRead:       minAccess(base.hostRead, ceiling.hostRead),
		HostWrite:      minAccess(base.hostWrite, ceiling.hostWrite),
		Network:        minAccess(base.network, ceiling.network),
		Command:        minAccess(base.command, ceiling.command),
		Home:           minHome(base.home, ceiling.home),
		Isolation:      minIsolation(base.isolation, ceiling.isolation),
	}
	config.AckUnconfined = config.Isolation == Unconfined && base.ackUnconfined && ceiling.ackUnconfined

	paths := make(map[string]struct{}, len(base.additionalRoots)+len(ceiling.additionalRoots))
	for _, root := range base.additionalRoots {
		paths[root.Path] = struct{}{}
	}
	for _, root := range ceiling.additionalRoots {
		paths[root.Path] = struct{}{}
	}
	for path := range paths {
		root := RootAccess{
			Path:  path,
			Read:  minAccess(base.accessAtPath(false, path), ceiling.accessAtPath(false, path)),
			Write: minAccess(base.accessAtPath(true, path), ceiling.accessAtPath(true, path)),
		}
		if root.Read != config.HostRead || root.Write != config.HostWrite {
			config.AdditionalRoots = append(config.AdditionalRoots, root)
		}
	}
	return NewProfile(config)
}

func minAccess(a, b Access) Access {
	if a < b {
		return a
	}
	return b
}

func minHome(a, b Home) Home {
	if a < b {
		return a
	}
	return b
}

func minIsolation(a, b Isolation) Isolation {
	if a < b {
		return a
	}
	return b
}

func deriveRequiredGuarantees(p *Profile) uint64 {
	bits := GuaranteeEnvScrub
	if p.isolation == Unconfined {
		return bits
	}
	if p.workspaceRead != Allow || p.hostRead != Allow {
		bits |= GuaranteeReadBoundary
	}
	if p.workspaceWrite != Allow || p.hostWrite != Allow {
		bits |= GuaranteeWriteBoundary
	}
	if p.network != Allow {
		bits |= GuaranteeNetworkBoundary
	}
	for _, root := range p.additionalRoots {
		if root.Read != Allow {
			bits |= GuaranteeReadBoundary
		}
		if root.Write != Allow {
			bits |= GuaranteeWriteBoundary
		}
	}
	return bits
}
