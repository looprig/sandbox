package baseline

import (
	"bytes"
	"debug/pe"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSFixtureHasPECallbackDirectoryOnBothArchitectures(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			image, err := GenerateTLSFixture(arch)
			if err != nil {
				t.Fatal(err)
			}
			second, err := GenerateTLSFixture(arch)
			if err != nil || !bytes.Equal(image, second) {
				t.Fatalf("fixture generation is not deterministic: err=%v", err)
			}
			path := filepath.Join(t.TempDir(), "tlsfixture.exe")
			if err := os.WriteFile(path, image, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := pe.Open(path)
			if err != nil {
				t.Fatalf("generated PE: %v", err)
			}
			defer file.Close()
			info, err := InspectTLSFixture(file)
			if err != nil {
				t.Fatal(err)
			}
			if info.CallbackVA == 0 || info.EntryPointRVA == 0 {
				t.Fatalf("fixture lacks callback/entry: %+v", info)
			}
			wantMachine := map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64}[arch]
			if info.Machine != wantMachine {
				t.Fatalf("fixture machine = %#x, want %#x", info.Machine, wantMachine)
			}
			if info.CallbackMarker != "TLS_CALLBACK_EXECUTED\n" || info.MainMarker != "MAIN_AFTER_TLS\n" {
				t.Fatalf("fixture markers = %#v / %#v", info.CallbackMarker, info.MainMarker)
			}
		})
	}
}

func TestRuntimeManifestPinsProductContract(t *testing.T) {
	manifest, err := LoadRuntimeManifest()
	if err != nil {
		t.Fatal(err)
	}
	wantRequired := []string{
		"installed-runner-go-helper",
		"go-subprocess",
		"crt-and-dll-initializers",
		"locale-and-console-startup",
		"pe-tls-callback-fixture",
		"canonical-system32-cmd",
		"windows-powershell",
		"python",
	}
	if err := manifest.RequireExactly(wantRequired); err != nil {
		t.Fatal(err)
	}
	if len(manifest.SupportedImages) != 2 || manifest.SupportedImages[0] != "windows-11" || manifest.SupportedImages[1] != "windows-server" {
		t.Fatalf("supported images = %v", manifest.SupportedImages)
	}
}

func TestClassifyWindowsImage(t *testing.T) {
	tests := []struct {
		name        string
		major       uint32
		minor       uint32
		build       uint32
		productType byte
		want        string
		wantError   bool
	}{
		{name: "Windows 11", major: 10, build: 22631, productType: 1, want: "windows-11"},
		{name: "Windows Server", major: 10, build: 20348, productType: 3, want: "windows-server"},
		{name: "Windows domain controller", major: 10, build: 26100, productType: 2, want: "windows-server"},
		{name: "Windows 10", major: 10, build: 19045, productType: 1, wantError: true},
		{name: "unknown version", major: 6, minor: 3, build: 9600, productType: 1, wantError: true},
		{name: "unknown product", major: 10, build: 26100, productType: 0, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClassifyWindowsImage(tt.major, tt.minor, tt.build, tt.productType)
			if (err != nil) != tt.wantError {
				t.Fatalf("ClassifyWindowsImage() error = %v, wantError %v", err, tt.wantError)
			}
			if got != tt.want {
				t.Fatalf("ClassifyWindowsImage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRuntimeManifestSupportsImage(t *testing.T) {
	manifest := RuntimeManifest{SupportedImages: []string{"windows-11", "windows-server"}}
	if !manifest.SupportsImage("windows-11") || !manifest.SupportsImage("windows-server") {
		t.Fatal("manifest rejected an explicitly supported image")
	}
	if manifest.SupportsImage("windows-10") || manifest.SupportsImage("") {
		t.Fatal("manifest accepted an image outside the explicit support list")
	}
}

func TestFailedRuntimeRequiresCompleteTrace(t *testing.T) {
	rawPath := filepath.Join(t.TempDir(), "baseline.pml")
	if err := os.WriteFile(rawPath, []byte("immutable raw trace"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := RuntimeExecution{Name: "windows-powershell", ExecutablePath: `C:\Windows\powershell.exe`, ObjectIdentity: "volume=1 file=2", ExecutableSHA256: SHA256Hex([]byte("exe")), PID: 42, Status: "FAIL", ExitCode: 5, Diagnostic: "access denied", FailureKind: FailurePostSpawn, CallerPID: 10, AttemptID: "caller-nonce-123/windows-powershell"}
	manifest := RunManifest{SchemaVersion: 3, RunNonce: "caller-nonce-123", SourceRevision: "0123456789abcdef", Platform: RunPlatform{WindowsBuild: "10.0.26100", Architecture: "amd64", Filesystem: "NTFS:00000001"}, TokenInventorySHA256: SHA256Hex([]byte("token")), RuntimeManifestSHA256: RuntimeManifestDigest(), MatrixSHA256: SHA256Hex([]byte("matrix")), Runtimes: []RuntimeExecution{runtime}, StartedUTC: "2026-07-22T12:00:00Z", FinishedUTC: "2026-07-22T12:00:02Z"}
	manifest, err := FinalizeRunManifest(manifest, TraceCollector{Name: "Microsoft Sysinternals Process Monitor", Version: "4.01", Command: "procmon64.exe /BackingFile baseline.pml"}, rawPath)
	if err != nil {
		t.Fatal(err)
	}
	trace := TraceEvidence{SchemaVersion: 3, Run: manifest, Cases: []TraceCase{{Runtime: runtime, Complete: true, CapturedPIDs: []int{10, 42}, CapturedNonce: manifest.RunNonce, CapturedAttemptID: runtime.AttemptID, Events: []TraceEvent{{PID: 42, EventID: "e1", Sequence: 1, TimestampUTC: "2026-07-22T12:00:01Z", RunNonce: manifest.RunNonce, AttemptID: runtime.AttemptID, Operation: "CreateFile", Result: "ACCESS DENIED", Path: `C:\Windows\System32\example.dll`, RequestedAccess: "Read Data/List Directory, Execute/Traverse"}}, Denials: []TraceDenial{{EventID: "e1", PID: 42, Operation: "CreateFile", RequestedAccess: "Read Data/List Directory, Execute/Traverse", ObjectPath: `C:\Windows\System32\example.dll`, ObjectIdentity: "volume=00000001 file=0000000000000002", Owner: "S-1-5-18", DACL: "D:(A;;GR;;;RC)"}}}}}
	if err := ValidateFailureTrace(manifest, trace); err != nil {
		t.Fatalf("complete trace rejected: %v", err)
	}
	mutations := map[string]func(*TraceEvidence){
		"nonce": func(e *TraceEvidence) { e.Run.RunNonce = "stale" }, "revision": func(e *TraceEvidence) { e.Run.SourceRevision = "stale" },
		"windows build": func(e *TraceEvidence) { e.Run.Platform.WindowsBuild = "stale" }, "architecture": func(e *TraceEvidence) { e.Run.Platform.Architecture = "stale" },
		"filesystem": func(e *TraceEvidence) { e.Run.Platform.Filesystem = "stale" }, "token": func(e *TraceEvidence) { e.Run.TokenInventorySHA256 = SHA256Hex([]byte("stale")) },
		"runtime manifest": func(e *TraceEvidence) { e.Run.RuntimeManifestSHA256 = SHA256Hex([]byte("stale")) }, "matrix": func(e *TraceEvidence) { e.Run.MatrixSHA256 = SHA256Hex([]byte("stale")) },
		"runtime path": func(e *TraceEvidence) { e.Cases[0].Runtime.ExecutablePath = "stale" }, "runtime identity": func(e *TraceEvidence) { e.Cases[0].Runtime.ObjectIdentity = "stale" },
		"runtime hash": func(e *TraceEvidence) { e.Cases[0].Runtime.ExecutableSHA256 = SHA256Hex([]byte("stale")) }, "runtime exit": func(e *TraceEvidence) { e.Cases[0].Runtime.ExitCode++ },
		"runtime diagnostic": func(e *TraceEvidence) { e.Cases[0].Runtime.Diagnostic = "stale" }, "raw hash": func(e *TraceEvidence) { e.Run.RawTraceSHA256 = SHA256Hex([]byte("stale")) },
		"collector name": func(e *TraceEvidence) { e.Run.Collector.Name = "stale" }, "collector version": func(e *TraceEvidence) { e.Run.Collector.Version = "stale" },
		"collector command": func(e *TraceEvidence) { e.Run.Collector.Command = "stale" }, "raw path": func(e *TraceEvidence) { e.Run.RawTracePath = "stale" },
		"pid":            func(e *TraceEvidence) { e.Cases[0].CapturedPIDs = []int{99} },
		"captured nonce": func(e *TraceEvidence) { e.Cases[0].CapturedNonce = "stale" }, "eligibility": func(e *TraceEvidence) { e.Run.ExactTokenGatePassed = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			encoded, _ := json.Marshal(trace)
			var changed TraceEvidence
			_ = json.Unmarshal(encoded, &changed)
			mutate(&changed)
			if err := ValidateFailureTrace(manifest, changed); err == nil {
				t.Fatal("binding mismatch unexpectedly accepted")
			}
		})
	}
	if err := os.WriteFile(rawPath, []byte("mutated raw trace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFailureTrace(manifest, trace); err == nil {
		t.Fatal("mutated raw artifact unexpectedly accepted")
	}
}

func TestTraceSchemaIsMachineReadableJSON(t *testing.T) {
	if !json.Valid(traceEvidenceSchema) {
		t.Fatal("embedded trace evidence schema is not valid JSON")
	}
}
