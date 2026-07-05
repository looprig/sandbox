package sandbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// Grant-token tests use deterministic, reproducible inputs: keys derived from a
// fixed seed (NOT crypto/rand) and fixed instants (NO time.Now anywhere), so the
// crypto is asserted against known, stable values. newGrantKey is the sole
// exception — it *is* the crypto/rand path, so its own test exercises it.

// testGrantKey returns a fixed 32-byte key derived from seed. Distinct seeds
// yield distinct keys, which the wrong-key test relies on.
func testGrantKey(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}

var (
	grantExpiry  = time.Date(2026, 7, 5, 12, 15, 0, 0, time.UTC) // mint TTL horizon
	beforeExpiry = time.Date(2026, 7, 5, 12, 10, 0, 0, time.UTC)
	afterExpiry  = time.Date(2026, 7, 5, 12, 20, 0, 0, time.UTC)
)

const (
	grantDir   = "/work/repo"
	grantCmd   = "git push origin main"
	grantDesc  = "allow HTTPS egress for git push" // unique, human-readable
	grantDelta = "net:add:443/tcp"                 // machine-readable, opaque here
)

func samplePayload() grantPayload {
	return grantPayload{
		PolicyGen:   7,
		CmdHash:     hashCommand(grantDir, grantCmd),
		Delta:       grantDelta,
		Description: grantDesc,
		Expiry:      grantExpiry,
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", s, err)
	}
	return b
}

// flipByte returns a copy of b with byte i inverted, leaving the input intact.
func flipByte(b []byte, i int) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[i] ^= 0xFF
	return out
}

// 1. Round-trip: mint then verify with matching key/gen/cmdHash and a now before
// expiry returns the payload with the correct Description and Delta.
func TestGrantRoundTrip(t *testing.T) {
	key := testGrantKey(0x11)
	p := samplePayload()
	token := mintGrant(key, p)

	if !strings.HasPrefix(token, "lrsx1.") {
		t.Fatalf("token = %q, want lrsx1. prefix", token)
	}
	if n := strings.Count(token, "."); n != 2 {
		t.Fatalf("token has %d dots, want 2 (three segments): %q", n, token)
	}

	got, err := verifyGrant(key, token, beforeExpiry, p.PolicyGen, p.CmdHash)
	if err != nil {
		t.Fatalf("verifyGrant on fresh token: %v", err)
	}
	if got.Description != grantDesc {
		t.Errorf("Description = %q, want %q", got.Description, grantDesc)
	}
	if got.Delta != grantDelta {
		t.Errorf("Delta = %q, want %q", got.Delta, grantDelta)
	}
	if got.PolicyGen != p.PolicyGen {
		t.Errorf("PolicyGen = %d, want %d", got.PolicyGen, p.PolicyGen)
	}
	if got.CmdHash != p.CmdHash {
		t.Errorf("CmdHash = %x, want %x", got.CmdHash, p.CmdHash)
	}
	if !got.Expiry.Equal(p.Expiry) {
		t.Errorf("Expiry = %v, want %v", got.Expiry, p.Expiry)
	}
}

// 2. Tamper each of the three segments: a mangled version or non-base64 segment
// is ErrGrantMalformed; a flipped payload or mac byte is ErrGrantBadMAC.
func TestGrantTamperSegments(t *testing.T) {
	key := testGrantKey(0x22)
	p := samplePayload()
	token := mintGrant(key, p)
	parts := strings.Split(token, ".")

	t.Run("wrong-version", func(t *testing.T) {
		bad := "lrsx2." + parts[1] + "." + parts[2]
		if _, err := verifyGrant(key, bad, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantMalformed) {
			t.Errorf("err = %v, want ErrGrantMalformed", err)
		}
	})

	t.Run("missing-version", func(t *testing.T) {
		bad := parts[1] + "." + parts[2] // only two segments
		if _, err := verifyGrant(key, bad, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantMalformed) {
			t.Errorf("err = %v, want ErrGrantMalformed", err)
		}
	})

	t.Run("payload-flipped-byte", func(t *testing.T) {
		raw := flipByte(mustDecode(t, parts[1]), 0)
		bad := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
		if _, err := verifyGrant(key, bad, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantBadMAC) {
			t.Errorf("err = %v, want ErrGrantBadMAC", err)
		}
	})

	t.Run("payload-not-base64", func(t *testing.T) {
		bad := parts[0] + ".not valid base64!." + parts[2]
		if _, err := verifyGrant(key, bad, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantMalformed) {
			t.Errorf("err = %v, want ErrGrantMalformed", err)
		}
	})

	t.Run("mac-flipped-byte", func(t *testing.T) {
		raw := flipByte(mustDecode(t, parts[2]), 0)
		bad := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(raw)
		if _, err := verifyGrant(key, bad, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantBadMAC) {
			t.Errorf("err = %v, want ErrGrantBadMAC", err)
		}
	})
}

// 3. Wrong key: verifying (or display-decoding) with a different key is a MAC
// mismatch — the key is the executor-instance binding.
func TestGrantWrongKey(t *testing.T) {
	key := testGrantKey(0x33)
	other := testGrantKey(0x44)
	p := samplePayload()
	token := mintGrant(key, p)

	if _, err := verifyGrant(other, token, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantBadMAC) {
		t.Errorf("verifyGrant wrong key: err = %v, want ErrGrantBadMAC", err)
	}
	if _, err := decodeGrantForDisplay(other, token); !errors.Is(err, ErrGrantBadMAC) {
		t.Errorf("decodeGrantForDisplay wrong key: err = %v, want ErrGrantBadMAC", err)
	}
}

// 4. Expired: a now after Expiry is ErrGrantExpired; the expiry instant itself is
// still valid (expires-at semantics).
func TestGrantExpired(t *testing.T) {
	key := testGrantKey(0x55)
	p := samplePayload()
	token := mintGrant(key, p)

	if _, err := verifyGrant(key, token, afterExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantExpired) {
		t.Errorf("verifyGrant after expiry: err = %v, want ErrGrantExpired", err)
	}
	if _, err := verifyGrant(key, token, grantExpiry, p.PolicyGen, p.CmdHash); err != nil {
		t.Errorf("verifyGrant at expiry instant: err = %v, want nil", err)
	}
}

// 5. Bumped policy generation: wantGen != minted gen is ErrGrantWrongGeneration
// (defends against replay across policy/mode changes).
func TestGrantWrongGeneration(t *testing.T) {
	key := testGrantKey(0x66)
	p := samplePayload()
	token := mintGrant(key, p)

	if _, err := verifyGrant(key, token, beforeExpiry, p.PolicyGen+1, p.CmdHash); !errors.Is(err, ErrGrantWrongGeneration) {
		t.Errorf("verifyGrant bumped generation: err = %v, want ErrGrantWrongGeneration", err)
	}
}

// 6. Wrong command: wantCmdHash != minted cmdHash is ErrGrantWrongCommand
// (defends against reuse against a different command).
func TestGrantWrongCommand(t *testing.T) {
	key := testGrantKey(0x77)
	p := samplePayload()
	token := mintGrant(key, p)

	otherCmd := hashCommand(grantDir, "rm -rf /")
	if _, err := verifyGrant(key, token, beforeExpiry, p.PolicyGen, otherCmd); !errors.Is(err, ErrGrantWrongCommand) {
		t.Errorf("verifyGrant different command: err = %v, want ErrGrantWrongCommand", err)
	}
}

// 7. Description is MAC-covered: flipping a byte inside the description region of
// the payload WITHOUT recomputing the MAC breaks verification for both the full
// verify and the display decode — the prompt text cannot be inflated.
func TestGrantDescriptionMACCovered(t *testing.T) {
	key := testGrantKey(0x88)
	p := samplePayload()
	token := mintGrant(key, p)
	parts := strings.Split(token, ".")

	raw := mustDecode(t, parts[1])
	idx := bytes.Index(raw, []byte(grantDesc))
	if idx < 0 {
		t.Fatalf("description %q not present in payload bytes", grantDesc)
	}
	// Flip a byte inside the description region; keep the ORIGINAL mac (parts[2]).
	forgedPayload := flipByte(raw, idx+3)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forgedPayload) + "." + parts[2]

	if _, err := verifyGrant(key, forged, beforeExpiry, p.PolicyGen, p.CmdHash); !errors.Is(err, ErrGrantBadMAC) {
		t.Errorf("inflated description (verifyGrant): err = %v, want ErrGrantBadMAC", err)
	}
	if _, err := decodeGrantForDisplay(key, forged); !errors.Is(err, ErrGrantBadMAC) {
		t.Errorf("inflated description (decodeGrantForDisplay): err = %v, want ErrGrantBadMAC", err)
	}
}

// 8. decodeGrantForDisplay: a valid token yields the bound Description even when
// the token is expired and mis-bound (display is MAC-only). A tampered token
// errors, so a fabricated token never reaches a prompt.
func TestDecodeGrantForDisplay(t *testing.T) {
	key := testGrantKey(0x99)
	p := samplePayload()
	token := mintGrant(key, p)

	got, err := decodeGrantForDisplay(key, token)
	if err != nil {
		t.Fatalf("decodeGrantForDisplay valid token: %v", err)
	}
	if got.Description != grantDesc {
		t.Errorf("Description = %q, want %q", got.Description, grantDesc)
	}

	// Display still works for a token that would FAIL full verification: expired
	// and wrong generation. Only the MAC gates display.
	stale := samplePayload()
	stale.Expiry = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	stale.PolicyGen = 999
	staleToken := mintGrant(key, stale)

	got, err = decodeGrantForDisplay(key, staleToken)
	if err != nil {
		t.Fatalf("decodeGrantForDisplay expired/mis-bound token: %v", err)
	}
	if got.Description != grantDesc {
		t.Errorf("Description = %q, want %q", got.Description, grantDesc)
	}
	// Sanity: full verification of that same token does fail.
	if _, err := verifyGrant(key, staleToken, beforeExpiry, p.PolicyGen, p.CmdHash); err == nil {
		t.Error("verifyGrant on expired/mis-bound token: err = nil, want failure")
	}

	// A fabricated token never yields a displayable description.
	if _, err := decodeGrantForDisplay(key, "lrsx1.ZmFrZQ.ZmFrZQ"); err == nil {
		t.Error("decodeGrantForDisplay fabricated token: err = nil, want error")
	}
}

// 9. hashCommand is stable for identical inputs, distinguishes different commands
// and dirs, and is unambiguous across the dir/command boundary.
func TestHashCommand(t *testing.T) {
	if hashCommand(grantDir, grantCmd) != hashCommand(grantDir, grantCmd) {
		t.Error("hashCommand not stable for identical inputs")
	}
	if hashCommand(grantDir, grantCmd) == hashCommand(grantDir, "other command") {
		t.Error("hashCommand collides across different commands")
	}
	if hashCommand(grantDir, grantCmd) == hashCommand("/other/dir", grantCmd) {
		t.Error("hashCommand collides across different dirs")
	}
	// The NUL separator prevents boundary ambiguity: ("a","bc") must not equal
	// ("ab","c"), which naive concatenation would collide.
	if hashCommand("a", "bc") == hashCommand("ab", "c") {
		t.Error("hashCommand ambiguous across the dir/command boundary")
	}
}

// newGrantKey returns a 32-byte, non-zero, per-call-unique key. This is the one
// test that intentionally exercises crypto/rand (the function under test).
func TestNewGrantKey(t *testing.T) {
	k1, err := newGrantKey()
	if err != nil {
		t.Fatalf("newGrantKey: %v", err)
	}
	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
	if allZero(k1) {
		t.Error("newGrantKey returned an all-zero key")
	}

	k2, err := newGrantKey()
	if err != nil {
		t.Fatalf("newGrantKey: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Error("two newGrantKey calls returned identical keys")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
