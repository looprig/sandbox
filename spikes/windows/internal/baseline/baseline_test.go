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

func TestFailedRuntimeRequiresCompleteTrace(t *testing.T) {
	failures := []string{"windows-powershell"}
	if err := ValidateFailureTrace(failures, TraceEvidence{}); err == nil {
		t.Fatal("missing trace unexpectedly accepted")
	}
	trace := TraceEvidence{
		SchemaVersion:  1,
		Collector:      TraceCollector{Name: "Microsoft Sysinternals Process Monitor", Version: "4.01", Command: "procmon64.exe /BackingFile baseline.pml"},
		RawTraceSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Cases: []TraceCase{{
			Runtime:  "windows-powershell",
			Complete: true,
			Denials: []TraceDenial{{
				Operation:       "CreateFile",
				RequestedAccess: "Read Data/List Directory, Execute/Traverse",
				ObjectPath:      `C:\Windows\System32\example.dll`,
				ObjectIdentity:  "volume=00000001 file=0000000000000002",
				Owner:           "S-1-5-18",
				DACL:            "D:(A;;GR;;;RC)",
			}},
		}},
	}
	if err := ValidateFailureTrace(failures, trace); err != nil {
		t.Fatalf("complete trace rejected: %v", err)
	}
	trace.Cases[0].Denials[0].DACL = ""
	if err := ValidateFailureTrace(failures, trace); err == nil {
		t.Fatal("denial without DACL unexpectedly accepted")
	}
}

func TestTraceSchemaIsMachineReadableJSON(t *testing.T) {
	if !json.Valid(traceEvidenceSchema) {
		t.Fatal("embedded trace evidence schema is not valid JSON")
	}
}
