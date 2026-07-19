package sandbox

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// This file implements the unforgeable grant tokens of SPEC §9.2. A grant token
// is the carrier for a single escalation: it authorizes applying one capability
// delta for one command, on one executor instance, until it expires. The gate
// separately prevents *bypass* (grant-carrying calls are never auto-approved
// below unconfined, §9.3); these tokens defend against the remaining threats:
//
//   - prompt inflation — the model fabricating a broad, scary-sounding delta or
//     description to social-engineer a wide human approval. The description is
//     MAC-covered, so the prompt text itself cannot be altered.
//   - replay across sessions or policy changes — the key is per-executor and
//     never serialized (so tokens cannot cross processes/restarts), and the
//     policy generation is bound (so a token is void the moment policy changes).
//   - reuse against a different command — the (dir, command) hash is bound.
//
// The functions here are the internal crypto core only; wiring into the Executor
// (PlanGrants / DescribeGrant / RunCommandWithGrants) is a separate concern.

// grantVersion is the mandatory token version prefix. It is checked on verify; a
// token with a different or missing prefix is malformed. Bumping this string is
// how a future incompatible payload encoding is rolled out.
const grantVersion = "lrsx1"

// grantEnc is the token segment codec: base64url with no padding, over the exact
// MAC-covered payload bytes and the raw HMAC.
var grantEnc = base64.RawURLEncoding

// Grant verification failures. These are typed sentinels so callers can react
// per-cause (e.g. re-mint on a stale generation vs. reject outright on a bad
// MAC) via errors.Is.
var (
	// ErrGrantMalformed is returned for a structurally invalid token: wrong
	// segment count, an unrecognized version prefix, or a segment that is not
	// valid base64url.
	ErrGrantMalformed = errors.New("sandbox: grant token malformed")
	// ErrGrantBadMAC is returned when the recomputed HMAC does not match the
	// token's MAC segment: a forged, tampered, or wrong-key (wrong-executor)
	// token. This is the executor-instance binding.
	ErrGrantBadMAC = errors.New("sandbox: grant token MAC mismatch")
	// ErrGrantExpired is returned when now is past the bound expiry.
	ErrGrantExpired = errors.New("sandbox: grant token expired")
	// ErrGrantWrongGeneration is returned when the bound policy generation does
	// not match the current one: the policy or mode changed since minting.
	ErrGrantWrongGeneration = errors.New("sandbox: grant token policy generation mismatch")
	// ErrGrantWrongCommand is returned when the bound (dir, command) hash does
	// not match the command being spawned.
	ErrGrantWrongCommand = errors.New("sandbox: grant token command mismatch")
)

// grantPayload is the MAC-covered body of a grant token (SPEC §9.2). Every field
// is bound by the MAC: none can be altered after minting without invalidating
// the token.
//
// The encoding need NOT be canonical: verification MACs the payload bytes as
// received and never re-marshals, so a future encoding change (or adding a map
// field, whose JSON key order is unspecified) stays safe to verify. The one
// caveat is token *equality* — do not compare two tokens byte-for-byte to decide
// "same grant"; the §10.7 session-repeat path re-mints a fresh token rather than
// comparing, so this never bites.
//
// NOTE: CmdHash currently marshals as a 32-element JSON int array (verbose). A
// compact wire format is deferred to a future lrsx1 successor (lrsx2) version
// bump; do not change the encoding under the lrsx1 prefix.
type grantPayload struct {
	// PolicyGen is the policy generation at mint time. It is bumped on any policy
	// profile generation change, so a token is void once
	// policy moves on — this is the anti-replay-across-policy-changes binding.
	PolicyGen uint64
	// CmdHash is hashCommand(dir, command): the token is reusable only against
	// the exact command it was minted for.
	CmdHash [32]byte
	// Delta is the machine-readable capability delta, opaque at this layer (the
	// grant crypto neither parses nor interprets it; higher layers apply it).
	Delta string
	// Description is the human-readable text shown in the approval prompt. It is
	// MAC-covered specifically so the model cannot inflate the prompt.
	Description string
	// Expiry is the instant the token stops verifying (default TTL 15 min).
	// Its Location() is not preserved across marshal/unmarshal — harmless, since
	// verifyGrant compares absolute instants (After/Before); it is only a caveat
	// if a prompt ever formats Expiry for human display.
	Expiry time.Time
}

// newGrantKey generates a fresh 32-byte per-executor grant key from crypto/rand.
// The key lives for the executor's lifetime and is never serialized: it is
// itself the session/instance binding, so tokens cannot cross executors,
// processes, or restarts. A new executor means a new key means all prior tokens
// stop verifying.
func newGrantKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// hashCommand binds a token to a specific (dir, command) pair. The NUL separator
// makes the encoding unambiguous across the dir/command boundary — ("a","bc")
// and ("ab","c") hash differently — since a filesystem path cannot contain NUL.
func hashCommand(dir, command string) [32]byte {
	return sha256.Sum256([]byte(dir + "\x00" + command))
}

// mintGrant produces a token of the form
//
//	lrsx1.<base64url(payload)>.<base64url(HMAC-SHA256)>
//
// The MAC is computed over the exact payload bytes that are base64-embedded, so
// verification can recompute it over the received bytes without re-encoding. The
// caller sets Expiry on p; mintGrant does not consult the clock.
//
// It returns an error rather than panicking on encode failure: time.Time rejects
// years outside [0,9999], so a caller passing a far-future/overflowing Expiry
// (e.g. a "never expires" sentinel, or now.Add(ttl) rolling past year 9999)
// reaches this path with attacker-influenceable data — a panic on the mint path
// of a security primitive would be a DoS footgun.
func mintGrant(key []byte, p grantPayload) (string, error) {
	payloadBytes, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("mint grant: %w", err)
	}
	mac := grantMAC(key, payloadBytes)
	return grantVersion + "." +
		grantEnc.EncodeToString(payloadBytes) + "." +
		grantEnc.EncodeToString(mac), nil
}

// grantMAC computes HMAC-SHA256(key, payloadBytes).
func grantMAC(key, payloadBytes []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payloadBytes)
	return h.Sum(nil)
}

// authenticateGrant performs the checks shared by full verification and
// display-only decoding: version prefix, segment structure, base64 decoding, and
// the constant-time MAC comparison over the RECEIVED payload bytes. It returns
// the raw payload bytes together with the unmarshaled payload.
//
// Crucially, the MAC is checked over the bytes as received and BEFORE unmarshal,
// so tampering any payload byte — including a single character of Description —
// fails the MAC. The payload is never re-encoded here; re-encoding would defeat
// the whole guarantee.
func authenticateGrant(key []byte, token string) (grantPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != grantVersion {
		return grantPayload{}, ErrGrantMalformed
	}
	payloadBytes, err := grantEnc.DecodeString(parts[1])
	if err != nil {
		return grantPayload{}, ErrGrantMalformed
	}
	mac, err := grantEnc.DecodeString(parts[2])
	if err != nil {
		return grantPayload{}, ErrGrantMalformed
	}
	if !hmac.Equal(mac, grantMAC(key, payloadBytes)) {
		return grantPayload{}, ErrGrantBadMAC
	}
	var p grantPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		// A valid MAC over bytes that are not a payload can only arise from a
		// mint that never happens; treat defensively as malformed.
		return grantPayload{}, ErrGrantMalformed
	}
	return p, nil
}

// verifyGrant performs full verification for an actual spawn: version/format,
// MAC (constant-time, the executor-instance binding), expiry against now, then
// the binding checks (policy generation and command hash). It returns the bound
// payload only when every check passes. now is injected so callers control time
// precisely.
func verifyGrant(key []byte, token string, now time.Time, wantGen uint64, wantCmdHash [32]byte) (grantPayload, error) {
	p, err := authenticateGrant(key, token)
	if err != nil {
		return grantPayload{}, err
	}
	if now.After(p.Expiry) {
		return grantPayload{}, ErrGrantExpired
	}
	if p.PolicyGen != wantGen {
		return grantPayload{}, ErrGrantWrongGeneration
	}
	if p.CmdHash != wantCmdHash {
		return grantPayload{}, ErrGrantWrongCommand
	}
	return p, nil
}

// decodeGrantForDisplay authenticates a token (version/format + MAC only) and
// returns its payload for prompt display, without checking expiry or binding.
// This is what lets an approval prompt show the MAC-verified Description: a
// fabricated or tampered token fails here and so never reaches a prompt, while a
// genuine-but-stale token (expired or mis-bound) can still be described. It is
// display-only; never authorize a spawn on its result — use verifyGrant.
func decodeGrantForDisplay(key []byte, token string) (grantPayload, error) {
	return authenticateGrant(key, token)
}
