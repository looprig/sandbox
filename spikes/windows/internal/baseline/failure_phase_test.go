package baseline

import "testing"

func TestFailurePhaseRules(t *testing.T) {
	for _, test := range []struct {
		name    string
		runtime RuntimeExecution
		trace   TraceCase
	}{
		{name: "inventory_absent", runtime: RuntimeExecution{Name: "python", FailureKind: FailureInventoryAbsent, CallerPID: 10, AttemptID: "n/python", LookupEvidence: []string{"python.exe: not found"}, Status: "FAIL", Diagnostic: "not found"}, trace: TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/python", CapturedPIDs: []int{10}}},
		{name: "pre_spawn", runtime: RuntimeExecution{Name: "powershell", FailureKind: FailurePreSpawn, CallerPID: 10, AttemptID: "n/powershell", ExecutablePath: `C:\powershell.exe`, ObjectIdentity: "unavailable", Win32Error: "ERROR_ACCESS_DENIED", Status: "FAIL", Diagnostic: "CreateProcess: access denied"}, trace: TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/powershell", CapturedPIDs: []int{10}, Events: []TraceEvent{{PID: 10, EventID: "e1", Sequence: 1, TimestampUTC: "2026-07-22T12:00:01Z", RunNonce: "n", AttemptID: "n/powershell", Operation: "Process Create", Result: "ACCESS DENIED", Path: `C:\powershell.exe`}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.trace.Runtime = test.runtime
			if err := validateTraceCase("n", test.runtime, test.trace); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailurePhaseRejectsFabricatedOrMissingFields(t *testing.T) {
	baseInventory := RuntimeExecution{Name: "python", FailureKind: FailureInventoryAbsent, CallerPID: 10, AttemptID: "n/python", LookupEvidence: []string{"python.exe: not found"}, Status: "FAIL", Diagnostic: "not found"}
	basePre := RuntimeExecution{Name: "powershell", FailureKind: FailurePreSpawn, CallerPID: 10, AttemptID: "n/powershell", ExecutablePath: `C:\powershell.exe`, Win32Error: "ERROR_ACCESS_DENIED", Status: "FAIL", Diagnostic: "denied"}
	basePost := RuntimeExecution{Name: "runner", FailureKind: FailurePostSpawn, CallerPID: 10, AttemptID: "n/runner", PID: 20, ExecutablePath: `C:\runner.exe`, ObjectIdentity: "volume=1 file=2", ExecutableSHA256: SHA256Hex([]byte("runner")), Status: "FAIL", Diagnostic: "exit 1"}
	event := []TraceEvent{{Operation: "Process Create", Result: "ACCESS DENIED", Path: `C:\x.exe`}}
	tests := []struct {
		name    string
		runtime RuntimeExecution
		trace   TraceCase
	}{
		{"inventory child", func() RuntimeExecution { r := baseInventory; r.PID = 20; return r }(), TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/python", CapturedPIDs: []int{10}}},
		{"inventory hash", func() RuntimeExecution { r := baseInventory; r.ExecutableSHA256 = SHA256Hex([]byte("fake")); return r }(), TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/python", CapturedPIDs: []int{10}}},
		{"inventory denial", baseInventory, TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/python", CapturedPIDs: []int{10}, Denials: []TraceDenial{{Operation: "fake"}}}},
		{"pre missing error", func() RuntimeExecution { r := basePre; r.Win32Error = ""; return r }(), TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/powershell", CapturedPIDs: []int{10}, Events: event}},
		{"pre missing event", basePre, TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/powershell", CapturedPIDs: []int{10}}},
		{"post missing child", func() RuntimeExecution { r := basePost; r.PID = 0; return r }(), TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/runner", CapturedPIDs: []int{10}, Events: event}},
		{"post missing hash", func() RuntimeExecution { r := basePost; r.ExecutableSHA256 = ""; return r }(), TraceCase{Complete: true, CapturedNonce: "n", CapturedAttemptID: "n/runner", CapturedPIDs: []int{10, 20}, Events: event}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.trace.Runtime = test.runtime
			if err := validateTraceCase("n", test.runtime, test.trace); err == nil {
				t.Fatal("invalid phase evidence accepted")
			}
		})
	}
}
