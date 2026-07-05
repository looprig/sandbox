package sandbox

import "testing"

// TestPolicyZeroValues asserts every zero value in the policy and guarantee
// types is fail-closed: the most restrictive interpretation. A caller who
// forgets to set a field must never accidentally widen access.
func TestPolicyZeroValues(t *testing.T) {
	if Mode(0) != ZeroTrust {
		t.Errorf("Mode(0) = %v, want ZeroTrust (most restrictive mode)", Mode(0))
	}

	if FSAccess(0) != DenyAccess {
		t.Errorf("FSAccess(0) = %v, want DenyAccess (no access)", FSAccess(0))
	}

	if (EnvPolicy{}).Inherit {
		t.Error("EnvPolicy{}.Inherit = true, want false (baseline allowlist, no inheritance)")
	}

	var net NetPolicy
	if net.Loopback || net.Private || net.DNS || net.Open {
		t.Errorf("NetPolicy{} = %+v, want all bool fields false (fully blocked)", net)
	}
	if len(net.Ports) != 0 {
		t.Errorf("NetPolicy{}.Ports = %v, want empty (no ports allowed)", net.Ports)
	}

	var g Guarantees
	if g.ProcessBoundary || g.WriteBoundary || g.ReadDenies || g.EnvScrub ||
		g.NetworkBoundary || g.AddressNetwork || g.ResourceLimits {
		t.Errorf("Guarantees{} = %+v, want all seven fields false (nothing enforced)", g)
	}

	if LevelNone != 0 {
		t.Errorf("LevelNone = %d, want 0 (fail-closed isolation level)", LevelNone)
	}
}

// TestFSAccessBits asserts the three access bits are distinct, non-zero,
// non-overlapping single bits that OR-combine cleanly, and that DenyAccess is
// the zero value.
func TestFSAccessBits(t *testing.T) {
	if DenyAccess != 0 {
		t.Errorf("DenyAccess = %d, want 0", DenyAccess)
	}

	bits := map[string]FSAccess{
		"ReadAccess":  ReadAccess,
		"ExecAccess":  ExecAccess,
		"WriteAccess": WriteAccess,
	}

	// Each bit is non-zero and a single set bit (power of two).
	for name, b := range bits {
		if b == 0 {
			t.Errorf("%s = 0, want a non-zero single bit", name)
		}
		if b&(b-1) != 0 {
			t.Errorf("%s = %d, want a single bit (power of two)", name, b)
		}
	}

	// Distinct and non-overlapping, pairwise.
	if ReadAccess == ExecAccess || ReadAccess == WriteAccess || ExecAccess == WriteAccess {
		t.Errorf("access bits not distinct: Read=%d Exec=%d Write=%d", ReadAccess, ExecAccess, WriteAccess)
	}
	if ReadAccess&ExecAccess != 0 {
		t.Errorf("ReadAccess & ExecAccess = %d, want 0 (non-overlapping)", ReadAccess&ExecAccess)
	}
	if ReadAccess&WriteAccess != 0 {
		t.Errorf("ReadAccess & WriteAccess = %d, want 0 (non-overlapping)", ReadAccess&WriteAccess)
	}
	if ExecAccess&WriteAccess != 0 {
		t.Errorf("ExecAccess & WriteAccess = %d, want 0 (non-overlapping)", ExecAccess&WriteAccess)
	}

	// OR-combine cleanly: masking a combined value recovers each member.
	if (ReadAccess|WriteAccess)&WriteAccess != WriteAccess {
		t.Errorf("(ReadAccess|WriteAccess)&WriteAccess = %d, want %d", (ReadAccess|WriteAccess)&WriteAccess, WriteAccess)
	}
	if (ReadAccess|WriteAccess)&ReadAccess != ReadAccess {
		t.Errorf("(ReadAccess|WriteAccess)&ReadAccess = %d, want %d", (ReadAccess|WriteAccess)&ReadAccess, ReadAccess)
	}
	// A member absent from the combination reads back as unset.
	if (ReadAccess|WriteAccess)&ExecAccess != 0 {
		t.Errorf("(ReadAccess|WriteAccess)&ExecAccess = %d, want 0", (ReadAccess|WriteAccess)&ExecAccess)
	}
}
