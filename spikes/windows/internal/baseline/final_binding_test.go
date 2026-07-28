package baseline

import "testing"

func TestDenialMustSemanticallyMatchDeniedEvent(t *testing.T) {
	event := TraceEvent{PID: 2, EventID: "e", Result: "SUCCESS", Operation: "CreateFile", Path: `C:\x`, RequestedAccess: "Read Data"}
	denial := TraceDenial{PID: 2, EventID: "e", Operation: "CreateFile", ObjectPath: `c:\x`, RequestedAccess: "Read Data", ObjectIdentity: "id", Owner: "o", DACL: "d"}
	if err := validateDenialBinding(map[string]TraceEvent{"e": event}, denial); err == nil {
		t.Fatal("success event accepted")
	}
	event.Result = "ACCESS DENIED"
	events := map[string]TraceEvent{"e": event}
	if err := validateDenialBinding(events, denial); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*TraceDenial){func(d *TraceDenial) { d.PID = 3 }, func(d *TraceDenial) { d.Operation = "OpenKey" }, func(d *TraceDenial) { d.ObjectPath = `C:\y` }, func(d *TraceDenial) { d.RequestedAccess = "Write Data" }} {
		changed := denial
		mutate(&changed)
		if validateDenialBinding(events, changed) == nil {
			t.Fatal("semantic mismatch accepted")
		}
	}
}

func TestIncompleteCleanupInvokesTerminalBoundary(t *testing.T) {
	called := false
	next := false
	if EnforceCleanupCompleted(CleanupResult{Completed: false}, func(string) { called = true }) {
		next = true
	}
	if !called || next {
		t.Fatal("incomplete cleanup allowed next row")
	}
}
