//go:build windows

package windows

import (
	"bytes"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	xwindows "golang.org/x/sys/windows"
)

const (
	testOwnerSID        = "S-1-5-21-1-2-3-1001"
	testInstallationSID = "S-1-5-32-1-2-3-4-5-6-7-8"
)

func TestBrokerPipeDACLIsClosedToConfiguredTrustees(t *testing.T) {
	sddl, err := brokerPipeSDDL(testOwnerSID)
	if err != nil {
		t.Fatal(err)
	}
	want := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + testOwnerSID + ")"
	if sddl != want {
		t.Fatalf("SDDL = %q, want %q", sddl, want)
	}
	if _, err := xwindows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatalf("SDDL is not accepted by Windows: %v", err)
	}
	if _, err := brokerPipeSDDL("not-a-sid"); err == nil {
		t.Fatal("invalid owner SID accepted")
	}
}

func TestBrokerPipeAuthenticationUsesKernelClientIdentityAndBindsLease(t *testing.T) {
	process := &fakeBrokerClientProcess{facts: brokerClientFacts{PID: 41, CreationTime: 9001, UserSID: testOwnerSID}}
	system := &fakeBrokerPipeSystem{pids: []uint32{41, 41, 41}, process: process}
	authenticator := testBrokerAuthenticator(system)
	connection, err := authenticator.Authenticate(xwindows.Handle(7))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	binding := connection.LeaseBinding()
	if binding.PID != 41 || binding.CreationTime != 9001 || binding.Process != process {
		t.Fatalf("unexpected lease binding: %#v", binding)
	}
	if binding.Nonce == ([brokerNonceSize]byte{}) {
		t.Fatal("zero connection nonce")
	}
	if !reflect.DeepEqual(system.openedPIDs, []uint32{41}) {
		t.Fatalf("opened PIDs = %v", system.openedPIDs)
	}
	if err := connection.ValidateIdentity(); err != nil {
		t.Fatalf("revalidate stable identity: %v", err)
	}
}

func TestBrokerPipeRejectsOwnerAppContainerAndInstallationRestriction(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*brokerClientFacts)
	}{
		{"owner mismatch", func(facts *brokerClientFacts) { facts.UserSID = "S-1-5-21-9-9-9-1002" }},
		{"AppContainer", func(facts *brokerClientFacts) { facts.AppContainer = true }},
		{"installation restricting SID", func(facts *brokerClientFacts) { facts.RestrictedSIDs = []string{testInstallationSID} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := brokerClientFacts{PID: 41, CreationTime: 9001, UserSID: testOwnerSID}
			test.mutate(&facts)
			process := &fakeBrokerClientProcess{facts: facts}
			system := &fakeBrokerPipeSystem{pids: []uint32{41, 41}, process: process}
			_, err := testBrokerAuthenticator(system).Authenticate(xwindows.Handle(7))
			if !errors.Is(err, errBrokerClientUnauthorized) {
				t.Fatalf("error = %v", err)
			}
			if process.closeCount.Load() != 1 {
				t.Fatalf("process close count = %d", process.closeCount.Load())
			}
		})
	}
}

func TestBrokerPipeRejectsPIDReuseBetweenLookupAndOpen(t *testing.T) {
	process := &fakeBrokerClientProcess{facts: brokerClientFacts{PID: 41, CreationTime: 9001, UserSID: testOwnerSID}}
	system := &fakeBrokerPipeSystem{pids: []uint32{41, 42}, process: process}
	_, err := testBrokerAuthenticator(system).Authenticate(xwindows.Handle(7))
	if !errors.Is(err, errBrokerClientChanged) {
		t.Fatalf("error = %v", err)
	}
	if process.closeCount.Load() != 1 {
		t.Fatalf("process close count = %d", process.closeCount.Load())
	}
}

func TestBrokerPipeRejectsCreationTimeChangeAfterAuthentication(t *testing.T) {
	process := &fakeBrokerClientProcess{facts: brokerClientFacts{PID: 41, CreationTime: 9001, UserSID: testOwnerSID}}
	system := &fakeBrokerPipeSystem{pids: []uint32{41, 41, 41}, process: process}
	connection, err := testBrokerAuthenticator(system).Authenticate(xwindows.Handle(7))
	if err != nil {
		t.Fatal(err)
	}
	process.creationTime = 9002
	if err := connection.ValidateIdentity(); !errors.Is(err, errBrokerClientChanged) {
		t.Fatalf("error = %v", err)
	}
	_ = connection.Close()
}

func TestBrokerPipeDisconnectCleansLeasesBeforeClosingProcessOnce(t *testing.T) {
	process := &fakeBrokerClientProcess{facts: brokerClientFacts{PID: 41, CreationTime: 9001, UserSID: testOwnerSID}}
	system := &fakeBrokerPipeSystem{pids: []uint32{41, 41}, process: process}
	connection, err := testBrokerAuthenticator(system).Authenticate(xwindows.Handle(7))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	connection.OnDisconnect(func() {
		if process.closeCount.Load() != 0 {
			t.Error("process closed before cleanup")
		}
		order = append(order, "first")
	})
	connection.OnDisconnect(func() { order = append(order, "second") })
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"second", "first"}) {
		t.Fatalf("cleanup order = %v", order)
	}
	if process.closeCount.Load() != 1 {
		t.Fatalf("process close count = %d", process.closeCount.Load())
	}
	connection.OnDisconnect(func() { order = append(order, "late") })
	if !reflect.DeepEqual(order, []string{"second", "first", "late"}) {
		t.Fatalf("late cleanup order = %v", order)
	}
}

func testBrokerAuthenticator(system brokerPipeSystem) *brokerPipeAuthenticator {
	return &brokerPipeAuthenticator{system: system, nonceSource: bytes.NewReader(bytes.Repeat([]byte{7}, brokerNonceSize)), ownerSID: testOwnerSID, installationRestrictingSID: testInstallationSID}
}

type fakeBrokerPipeSystem struct {
	pids       []uint32
	process    brokerClientProcess
	openedPIDs []uint32
}

func (system *fakeBrokerPipeSystem) ClientPID(xwindows.Handle) (uint32, error) {
	if len(system.pids) == 0 {
		return 0, errors.New("unexpected PID lookup")
	}
	pid := system.pids[0]
	system.pids = system.pids[1:]
	return pid, nil
}

func (system *fakeBrokerPipeSystem) OpenClient(pid uint32) (brokerClientProcess, error) {
	system.openedPIDs = append(system.openedPIDs, pid)
	return system.process, nil
}

type fakeBrokerClientProcess struct {
	facts        brokerClientFacts
	creationTime uint64
	closeCount   atomic.Int32
}

func (process *fakeBrokerClientProcess) Facts() (brokerClientFacts, error) { return process.facts, nil }
func (process *fakeBrokerClientProcess) CreationTime() (uint64, error) {
	if process.creationTime != 0 {
		return process.creationTime, nil
	}
	return process.facts.CreationTime, nil
}
func (process *fakeBrokerClientProcess) Close() error { process.closeCount.Add(1); return nil }
