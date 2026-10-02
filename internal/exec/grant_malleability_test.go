package exec

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const grantAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// flipPadBit returns segment with the lowest bit of its final character
// flipped. For an unpadded base64 segment whose decoded length is not a
// multiple of three, that bit is a pad bit the lenient decoder ignores, so the
// result is a different string that decodes to the same bytes.
func flipPadBit(t *testing.T, segment string) string {
	t.Helper()
	last := strings.IndexByte(grantAlphabet, segment[len(segment)-1])
	if last < 0 {
		t.Fatalf("segment %q ends outside the raw-URL alphabet", segment)
	}
	return segment[:len(segment)-1] + string(grantAlphabet[last^1])
}

// mintPaddedGrant mints a token whose body segment also carries pad bits: the
// body length is steered off a multiple of three by the execution ID length.
// The 32-byte MAC always does (43 characters carry 258 bits, 256 used).
func mintPaddedGrant(t *testing.T, key []byte) (token, body, mac string) {
	t.Helper()
	for pad := 0; pad < 3; pad++ {
		token, err := mintGrant(key, grantPayload{
			ExecutionID: "exec" + strings.Repeat("x", pad), Command: "true",
			Class: GrantClassCommandStart, Target: "true", ExpiryUnixMilli: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(token, ".")
		if len(parts[1])%4 != 0 {
			return token, parts[1], parts[2]
		}
	}
	t.Fatal("no execution ID length produced a body with pad bits")
	return "", "", ""
}

func TestGrantPadBitMalleabilityIsRejected(t *testing.T) {
	key, err := newGrantKey()
	if err != nil {
		t.Fatal(err)
	}
	token, body, mac := mintPaddedGrant(t, key)
	original, err := authenticateGrant(key, token)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutated := range map[string]string{
		"mac":  grantTokenPrefix + "." + body + "." + flipPadBit(t, mac),
		"body": grantTokenPrefix + "." + flipPadBit(t, body) + "." + mac,
	} {
		t.Run(name, func(t *testing.T) {
			if mutated == token {
				t.Fatal("mutation did not change the token text")
			}
			// Premise: the lenient decoder maps both spellings to the same bytes,
			// so the mutated token is a distinct string carrying a valid MAC.
			for i, segment := range strings.Split(mutated, ".")[1:] {
				want, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[i+1])
				got, err := base64.RawURLEncoding.DecodeString(segment)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("premise: lenient decode of segment %d = %x, %v; want %x", i+1, got, err, want)
				}
			}
			if _, err := authenticateGrant(key, mutated); !errors.Is(err, ErrGrantMalformed) {
				t.Fatalf("authenticate mutated token error = %v, want ErrGrantMalformed", err)
			}
			// Replay identity is the decoded MAC, so a spelling variant names
			// the same grant even before authentication refuses it.
			if grantID(mutated) != grantID(token) {
				t.Fatal("pad-bit variant has a different grant ID than the original")
			}
		})
	}
	if again, err := authenticateGrant(key, token); err != nil || again != original {
		t.Fatalf("original token no longer authenticates: %v", err)
	}
}

func TestGrantPadBitVariantCannotBeRedeemedTwice(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := portableSuccessCommand()
	token := issueTestGrant(t, executor, now, "exec-pad", command, workspace,
		"command.execute", "", GrantClassCommandStart, command)
	parts := strings.Split(token, ".")
	variant := parts[0] + "." + parts[1] + "." + flipPadBit(t, parts[2])

	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-pad", workspace, command, []string{variant}); !errors.Is(err, ErrGrantMalformed) {
		t.Fatalf("fresh pad-bit variant error = %v, want ErrGrantMalformed", err)
	}
	if _, code, err := executor.RunCommandWithGrants(context.Background(), "exec-pad", workspace, command, []string{token}); err != nil || code != 0 {
		t.Fatalf("original token = code %d err %v", code, err)
	}
	for name, replay := range map[string]string{"original": token, "variant": variant} {
		if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-pad", workspace, command, []string{replay}); !errors.Is(err, ErrGrantReplay) {
			t.Fatalf("%s replay after redemption error = %v, want ErrGrantReplay", name, err)
		}
	}
}
