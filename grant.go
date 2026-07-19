package sandbox

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	grantTokenPrefix     = "lrsx1"
	currentGrantVersion  = uint16(1)
	defaultRouteIdentity = "direct:v1"
)

var grantEnc = base64.RawURLEncoding

var (
	ErrGrantMalformed             = errors.New("sandbox: grant token malformed")
	ErrGrantBadMAC                = errors.New("sandbox: grant token MAC mismatch")
	ErrGrantExpired               = errors.New("sandbox: grant token expired")
	ErrGrantWrongCommand          = errors.New("sandbox: grant token command mismatch")
	ErrGrantWrongExecution        = errors.New("sandbox: grant token execution mismatch")
	ErrGrantWrongWorkingDirectory = errors.New("sandbox: grant token working directory mismatch")
	ErrGrantProfileMismatch       = errors.New("sandbox: grant token profile mismatch")
	ErrGrantGuaranteeMismatch     = errors.New("sandbox: grant token guarantee mismatch")
	ErrGrantRouteMismatch         = errors.New("sandbox: grant token route mismatch")
	ErrGrantReplay                = errors.New("sandbox: grant token replay")
	ErrGrantRequired              = errors.New("sandbox: approval grant required")
	ErrGrantDenied                = errors.New("sandbox: capability denied")
	ErrGrantUnsupported           = errors.New("sandbox: grant class unsupported")
	ErrExecutorClosed             = errors.New("sandbox: executor closed")
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
	return canonicalRoot(path)
}

func canonicalGrantPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path is not absolute")
	}
	clean := filepath.Clean(path)
	ancestor := clean
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(ancestor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", err
		}
		suffix = append(suffix, filepath.Base(ancestor))
		ancestor = parent
	}
}

func normalizeGrantScopeTarget(scope, class, target string) (string, string, error) {
	if !strings.HasPrefix(class, "filesystem.") || strings.Contains(class, ".host.") {
		return scope, target, nil
	}
	canonicalTarget, err := canonicalGrantPath(target)
	if err != nil {
		return "", "", fmt.Errorf("%w: target: %v", ErrGrantMalformed, err)
	}
	if strings.Contains(class, ".tree.") {
		if !strings.HasPrefix(scope, "tree:") {
			return "", "", ErrGrantMalformed
		}
		canonicalScope, err := canonicalGrantPath(strings.TrimPrefix(scope, "tree:"))
		if err != nil || canonicalScope != canonicalTarget {
			return "", "", ErrGrantMalformed
		}
		return "tree:" + canonicalTarget, canonicalTarget, nil
	}
	canonicalScope, err := canonicalGrantPath(scope)
	if err != nil || canonicalScope != canonicalTarget {
		return "", "", ErrGrantMalformed
	}
	return canonicalTarget, canonicalTarget, nil
}

func validGrantText(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

type grantDelta struct {
	entry  *fsEntry
	port   uint16
	class  string
	target *NetworkTarget
}

func validateGrantClass(kind, scope, class, target string) (grantDelta, uint64, error) {
	filesystem := func(wantKind, wantScope string, access fsAccess, guarantee uint64) (grantDelta, uint64, error) {
		if kind != wantKind || scope != wantScope {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{entry: &fsEntry{Path: target, Access: access}, class: class}, guarantee, nil
	}
	switch class {
	case "command.start.v1":
		if kind != "command.execute" || scope != "" || !validGrantText(target) {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{class: class}, 0, nil
	case "filesystem.path.read.v1", "filesystem.path.write.v1":
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || scope != target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if class == "filesystem.path.read.v1" {
			return filesystem("filesystem.read", target, readFSAccess|execFSAccess, GuaranteeReadBoundary)
		}
		return filesystem("filesystem.write", target, writeFSAccess, GuaranteeWriteBoundary)
	case "filesystem.tree.read.v1", "filesystem.tree.write.v1":
		if !filepath.IsAbs(target) || filepath.Clean(target) != target || scope != "tree:"+target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		if class == "filesystem.tree.read.v1" {
			return filesystem("filesystem.read", scope, readFSAccess|execFSAccess, GuaranteeReadBoundary)
		}
		return filesystem("filesystem.write", scope, writeFSAccess, GuaranteeWriteBoundary)
	case "filesystem.host.read.v1":
		if target != "host:*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return filesystem("filesystem.read", "host:*", readFSAccess|execFSAccess, GuaranteeReadBoundary)
	case "filesystem.host.write.v1":
		if target != "host:*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return filesystem("filesystem.write", "host:*", writeFSAccess, GuaranteeWriteBoundary)
	case "network.broad.v1":
		parts := strings.Split(target, ":")
		if kind != "network" || scope != "" || len(parts) != 3 || parts[0] != "tcp" || parts[1] != "*" {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		port, err := strconv.ParseUint(parts[2], 10, 16)
		if err != nil || port == 0 {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{port: uint16(port), class: class}, GuaranteeNetworkBoundary, nil
	case "network.proxy-target.v1":
		if kind != "network" || scope != "" || !validGrantText(target) {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		normalized, err := ParseNetworkTarget(target)
		if err != nil || normalized.String() != target {
			return grantDelta{}, 0, ErrGrantMalformed
		}
		return grantDelta{class: class, target: &normalized}, GuaranteeTargetNetwork, nil
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
