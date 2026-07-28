package exec

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/looprig/sandbox/internal/safetext"
	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

const (
	grantTokenPrefix     = "lrsx1"
	currentGrantVersion  = uint16(1)
	defaultRouteIdentity = "direct:v1"
)

// Grant enforcement-class identifiers. These string VALUES are the shipped
// wire/enforcement contract between the sandbox (which authenticates and
// enforces grants) and its producers (the harness/tools permission layer,
// which mints them). They are the single source of truth within sandbox:
// validateGrantClass and the executor switch on these constants rather than
// bare literals, and grant_class_test.go pins each value so a rename that
// silently changes a value fails here. The tools module independently pins the
// same literals (it must not depend on sandbox), so drift on either side is
// caught by a value test on that side.
const (
	GrantClassCommandStart        = "command.start.v1"
	GrantClassNetworkProxyTarget  = "network.proxy-target.v1"
	GrantClassNetworkBroad        = "network.broad.v1"
	GrantClassFilesystemPathRead  = "filesystem.path.read.v1"
	GrantClassFilesystemTreeRead  = "filesystem.tree.read.v1"
	GrantClassFilesystemHostRead  = "filesystem.host.read.v1"
	GrantClassFilesystemPathWrite = "filesystem.path.write.v1"
	GrantClassFilesystemTreeWrite = "filesystem.tree.write.v1"
	GrantClassFilesystemHostWrite = "filesystem.host.write.v1"
)

var grantEnc = base64.RawURLEncoding

var (
	ErrGrantMalformed             = policy.ErrMalformed
	ErrGrantBadMAC                = errors.New("sandbox: grant token MAC mismatch")
	ErrGrantExpired               = errors.New("sandbox: grant token expired")
	ErrGrantWrongCommand          = errors.New("sandbox: grant token command mismatch")
	ErrGrantWrongExecution        = errors.New("sandbox: grant token execution mismatch")
	ErrGrantWrongWorkingDirectory = errors.New("sandbox: grant token working directory mismatch")
	ErrGrantProfileMismatch       = errors.New("sandbox: grant token profile mismatch")
	ErrGrantGuaranteeMismatch     = errors.New("sandbox: grant token guarantee mismatch")
	ErrGrantRouteMismatch         = errors.New("sandbox: grant token route mismatch")
	ErrGrantTargetChanged         = policy.ErrTargetChanged
	ErrGrantReplay                = errors.New("sandbox: grant token replay")
	ErrGrantRequired              = errors.New("sandbox: approval grant required")
	ErrGrantDenied                = errors.New("sandbox: capability denied")
	ErrGrantUnsupported           = policy.ErrUnsupportedClass
	// ErrExecutorClosed is defined by the egress layer and re-used verbatim here
	// so that a refusal raised inside the proxy and one raised by the executor
	// are the same value under errors.Is.
	ErrExecutorClosed = network.ErrClosed
)

type grantPayload struct {
	ExecutionID        string
	Command            string
	WorkingDirectory   string
	ProfileFingerprint string
	RouteFingerprint   string
	GuaranteeBits      uint64
	Class              string
	Target             string
	PathBinding        *policy.PathBinding
	ExpiryUnixMilli    int64
	Nonce              [16]byte
}

func newGrantKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func mintGrant(key []byte, payload grantPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("mint grant: %w", err)
	}
	mac := grantMAC(key, body)
	return grantTokenPrefix + "." + grantEnc.EncodeToString(body) + "." + grantEnc.EncodeToString(mac), nil
}

func grantMAC(key, body []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(body)
	return h.Sum(nil)
}

func authenticateGrant(key []byte, token string) (grantPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != grantTokenPrefix {
		return grantPayload{}, ErrGrantMalformed
	}
	body, err := grantEnc.DecodeString(parts[1])
	if err != nil {
		return grantPayload{}, ErrGrantMalformed
	}
	mac, err := grantEnc.DecodeString(parts[2])
	if err != nil {
		return grantPayload{}, ErrGrantMalformed
	}
	if !hmac.Equal(mac, grantMAC(key, body)) {
		return grantPayload{}, ErrGrantBadMAC
	}
	var payload grantPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return grantPayload{}, ErrGrantMalformed
	}
	return payload, nil
}

func grantID(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func canonicalWorkingDirectory(path string) (string, error) {
	return profile.CanonicalRoot(path)
}

func normalizeGrantScopeTarget(scope, class, target string) (string, string, error) {
	if !strings.HasPrefix(class, "filesystem.") || strings.Contains(class, ".host.") {
		return scope, target, nil
	}
	canonicalTarget, err := policy.CanonicalPath(target)
	if err != nil {
		return "", "", fmt.Errorf("%w: target: %v", ErrGrantMalformed, err)
	}
	if strings.Contains(class, ".tree.") {
		if !strings.HasPrefix(scope, "tree:") {
			return "", "", ErrGrantMalformed
		}
		canonicalScope, err := policy.CanonicalPath(strings.TrimPrefix(scope, "tree:"))
		if err != nil || canonicalScope != canonicalTarget {
			return "", "", ErrGrantMalformed
		}
		return "tree:" + canonicalTarget, canonicalTarget, nil
	}
	canonicalScope, err := policy.CanonicalPath(scope)
	if err != nil || canonicalScope != canonicalTarget {
		return "", "", ErrGrantMalformed
	}
	return canonicalTarget, canonicalTarget, nil
}

func validGrantText(value string) bool {
	return safetext.Valid(value)
}

type grantDelta struct {
	entry             *policy.FSEntry
	port              uint16
	class             string
	target            *NetworkTarget
	droppedGuarantees uint64
	dns               bool
}

func validateGrantClass(kind, scope, class, target string) (grantDelta, uint64, error) {
	filesystem := func(wantKind, wantScope, policyPath string, access policy.FSAccess, guarantee uint64, exact bool) (grantDelta, uint64, error) {
		if kind != wantKind || scope != wantScope {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{entry: &policy.FSEntry{Path: policyPath, Access: access, Exact: exact, Canonical: filepath.IsAbs(policyPath)}, class: class}, guarantee, nil
	}
	switch class {
	case GrantClassCommandStart:
		if kind != "command.execute" || scope != "" || !validGrantText(target) {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{class: class}, 0, nil
	case GrantClassFilesystemPathRead, GrantClassFilesystemPathWrite:
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || scope != target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if class == GrantClassFilesystemPathRead {
			return filesystem("filesystem.read", target, target, policy.ReadAccess|policy.ExecAccess, GuaranteeReadBoundary, true)
		}
		return filesystem("filesystem.write", target, target, policy.WriteAccess, GuaranteeWriteBoundary, true)
	case GrantClassFilesystemTreeRead, GrantClassFilesystemTreeWrite:
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || scope != "tree:"+target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if class == GrantClassFilesystemTreeRead {
			return filesystem("filesystem.read", scope, target, policy.ReadAccess|policy.ExecAccess, GuaranteeReadBoundary, false)
		}
		return filesystem("filesystem.write", scope, target, policy.WriteAccess, GuaranteeWriteBoundary, false)
	case GrantClassFilesystemHostRead:
		if target != "host:*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if !hostFilesystemGrantsSupported() {
			return grantDelta{}, 0, ErrGrantUnsupported
		}
		delta, guarantee, err := filesystem("filesystem.read", "host:*", string(filepath.Separator), policy.ReadAccess|policy.ExecAccess, GuaranteeReadBoundary, false)
		delta.droppedGuarantees = GuaranteeReadBoundary
		return delta, guarantee, err
	case GrantClassFilesystemHostWrite:
		if target != "host:*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if !hostFilesystemGrantsSupported() {
			return grantDelta{}, 0, ErrGrantUnsupported
		}
		delta, guarantee, err := filesystem("filesystem.write", "host:*", string(filepath.Separator), policy.WriteAccess, GuaranteeWriteBoundary, false)
		delta.droppedGuarantees = GuaranteeWriteBoundary
		return delta, guarantee, err
	case GrantClassNetworkBroad:
		parts := strings.Split(target, ":")
		if kind != "network" || scope != "" || len(parts) != 3 || parts[0] != "tcp" || parts[1] != "*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || port == 0 {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{port: uint16(port), class: class, dns: true}, GuaranteeNetworkBoundary, nil
	case GrantClassNetworkProxyTarget:
		if kind != "network" || scope != "" || !validGrantText(target) {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		normalized, err := ParseNetworkTarget(target)
		if err != nil || normalized.String() != target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		// A target proxy is authority only when direct egress is independently
		// closed. Target normalization/authentication without the offline
		// NetworkBoundary would merely be advisory because the child could
		// bypass the listener.
		return grantDelta{class: class, target: &normalized},
			GuaranteeNetworkBoundary | GuaranteeTargetNetwork, nil
	default:
		return grantDelta{}, 0, ErrGrantUnsupported
	}
}

func verifyGrantBinding(payload grantPayload, now time.Time, executionID, command, cwd, profileFingerprint, routeFingerprint string, guaranteeBits uint64) error {
	if now.UnixMilli() > payload.ExpiryUnixMilli {
		return ErrGrantExpired
	}
	if payload.ExecutionID != executionID {
		return ErrGrantWrongExecution
	}
	if payload.Command != command {
		return ErrGrantWrongCommand
	}
	if payload.WorkingDirectory != cwd {
		return ErrGrantWrongWorkingDirectory
	}
	if payload.ProfileFingerprint != profileFingerprint {
		return ErrGrantProfileMismatch
	}
	if payload.RouteFingerprint != routeFingerprint {
		return ErrGrantRouteMismatch
	}
	if payload.GuaranteeBits != guaranteeBits {
		return ErrGrantGuaranteeMismatch
	}
	return nil
}

func expiryFromMillis(value int64) time.Time { return time.UnixMilli(value) }
