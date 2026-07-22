package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStrictJSONRejectsUnknownDuplicateAndTrailing(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":3,"schema_version":3}`,
		`{"schema_version":3,"unknown":true}`,
		`{"schema_version":3,"run":{"platform":{"windows_build":"x","windows_build":"y"}},"cases":[]}`,
		`{"schema_version":3,"run":{"unknown_nested":true},"cases":[]}`,
		`{"schema_version":3} {}`,
	} {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTraceEvidence(path); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestEventProvenanceRejectsUnrelatedAndDuplicateEvents(t *testing.T) {
	r := RuntimeExecution{Name: "x", Status: "FAIL", FailureKind: FailurePostSpawn, CallerPID: 10, PID: 20, AttemptID: "n/x", ExecutablePath: "x.exe", ObjectIdentity: "id", ExecutableSHA256: SHA256Hex([]byte("x")), Diagnostic: "failed"}
	e := TraceEvent{PID: 20, EventID: "event-1", Sequence: 1, TimestampUTC: "2026-07-22T12:00:01Z", RunNonce: "n", AttemptID: "n/x", Operation: "CreateFile", Result: "ACCESS DENIED", Path: "x.dll", RequestedAccess: "read"}
	c := TraceCase{Runtime: r, Complete: true, CapturedPIDs: []int{10, 20}, CapturedNonce: "n", CapturedAttemptID: "n/x", Events: []TraceEvent{e}, Denials: []TraceDenial{{EventID: "event-1", PID: 20, Operation: "CreateFile", RequestedAccess: "read", ObjectPath: "x.dll", ObjectIdentity: "id", Owner: "owner", DACL: "dacl"}}}
	if err := validateTraceCaseWindow("n", "2026-07-22T12:00:00Z", "2026-07-22T12:00:02Z", r, c); err != nil {
		t.Fatal(err)
	}
	c.Events[0].PID = 99
	if err := validateTraceCaseWindow("n", "2026-07-22T12:00:00Z", "2026-07-22T12:00:02Z", r, c); err == nil {
		t.Fatal("unrelated PID accepted")
	}
	c.Events[0] = e
	c.Events = append(c.Events, e)
	if err := validateTraceCaseWindow("n", "2026-07-22T12:00:00Z", "2026-07-22T12:00:02Z", r, c); err == nil {
		t.Fatal("duplicate event accepted")
	}
	c.Events = []TraceEvent{e}
	c.Events[0].TimestampUTC = "2026-07-22T11:59:59Z"
	if err := validateTraceCaseWindow("n", "2026-07-22T12:00:00Z", "2026-07-22T12:00:02Z", r, c); err == nil {
		t.Fatal("stale event accepted")
	}
	c.Events = []TraceEvent{e}
	c.Denials[0].EventID = "unrelated"
	if err := validateTraceCaseWindow("n", "2026-07-22T12:00:00Z", "2026-07-22T12:00:02Z", r, c); err == nil {
		t.Fatal("unbound denial accepted")
	}
}
