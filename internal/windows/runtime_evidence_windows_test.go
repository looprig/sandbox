//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type runtimeEvidenceVerifier struct {
	paths []string
	err   error
}

func (v *runtimeEvidenceVerifier) Verify(path, _ string) error {
	v.paths = append(v.paths, path)
	return v.err
}

func TestProtectedApprovedRuntimeEvidenceAcceptsBoundTask5Pass(t *testing.T) {
	root := t.TempDir()
	evidence := validApprovedRuntimeEvidence()
	writeApprovedRuntimeEvidence(t, root, evidence)
	verifier := &runtimeEvidenceVerifier{}
	inspector := protectedApprovedRuntimeEvidence{
		verifier: verifier,
		platform: func(string) (string, runtimeEvidencePlatform, error) {
			return evidence.SupportedImage, evidence.Run.Platform, nil
		},
		build: func(string) (runtimeEvidenceBuild, error) {
			return runtimeEvidenceBuild{GoVersion: evidence.GoVersion, Revision: evidence.Run.SourceRevision}, nil
		},
	}
	approved, err := inspector.Approved(context.Background(),
		validatedSetup{stateRoot: root, ownerSID: "S-1-5-21-owner"},
		setupManifest{HostPath: filepath.Join(root, "sandbox-host.exe")})
	if err != nil || !approved {
		t.Fatalf("approved evidence = %v, %v", approved, err)
	}
	if len(verifier.paths) != 1 || verifier.paths[0] != filepath.Join(root, runtimeEvidenceName) {
		t.Fatalf("verified paths = %v", verifier.paths)
	}
}

func TestApprovedRuntimeEvidenceFailsClosedOnUnboundFields(t *testing.T) {
	base := validApprovedRuntimeEvidence()
	tests := map[string]func(*approvedRuntimeEvidence){
		"selection":        func(e *approvedRuntimeEvidence) { e.Selection = "pending" },
		"supported image":  func(e *approvedRuntimeEvidence) { e.SupportedImage = "windows-server" },
		"Windows build":    func(e *approvedRuntimeEvidence) { e.Run.Platform.WindowsBuild = "10.0.99999" },
		"architecture":     func(e *approvedRuntimeEvidence) { e.Run.Platform.Architecture = "arm64" },
		"toolchain":        func(e *approvedRuntimeEvidence) { e.GoVersion = "go0.0" },
		"source revision":  func(e *approvedRuntimeEvidence) { e.Run.SourceRevision = strings.Repeat("b", 40) },
		"nonce":            func(e *approvedRuntimeEvidence) { e.Run.RunNonce = "short" },
		"runtime manifest": func(e *approvedRuntimeEvidence) { e.Run.RuntimeManifestSHA256 = strings.Repeat("0", 64) },
		"exact-token gate": func(e *approvedRuntimeEvidence) { e.Run.ExactTokenGatePassed = false },
		"runtime result":   func(e *approvedRuntimeEvidence) { e.Run.Runtimes[0].Status = "FAIL" },
		"attempt binding":  func(e *approvedRuntimeEvidence) { e.Run.Runtimes[0].AttemptID = "other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := base
			evidence.Run.Runtimes = append([]runtimeEvidenceExecution(nil), base.Run.Runtimes...)
			mutate(&evidence)
			err := validateApprovedRuntimeEvidence(evidence, base.SupportedImage, base.Run.Platform,
				runtimeEvidenceBuild{GoVersion: base.GoVersion, Revision: base.Run.SourceRevision})
			if !errors.Is(err, ErrSetupStale) {
				t.Fatalf("error = %v, want ErrSetupStale", err)
			}
		})
	}
}

func TestApprovedRuntimeEvidenceBindsImageFilesystemClassNotWorkerSerial(t *testing.T) {
	evidence := validApprovedRuntimeEvidence()
	current := evidence.Run.Platform
	current.Filesystem = "ntfs:ffffffff:00000002"
	build := runtimeEvidenceBuild{GoVersion: evidence.GoVersion, Revision: evidence.Run.SourceRevision}
	if err := validateApprovedRuntimeEvidence(evidence, evidence.SupportedImage, current, build); err != nil {
		t.Fatalf("equivalent disposable-worker filesystem class rejected: %v", err)
	}
	current.Filesystem = "NTFS:ffffffff:00000004"
	if err := validateApprovedRuntimeEvidence(evidence, evidence.SupportedImage, current, build); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("changed filesystem flags error = %v, want ErrSetupStale", err)
	}
}

func TestProtectedApprovedRuntimeEvidenceRejectsMalformedArtifact(t *testing.T) {
	base, err := json.Marshal(validApprovedRuntimeEvidence())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"unknown":   append(base[:len(base)-1], []byte(`,"approved":true}`)...),
		"duplicate": []byte(`{"schema_version":1,"schema_version":1}`),
		"trailing":  append(base, []byte(`{}`)...),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, runtimeEvidenceName), data, 0600); err != nil {
				t.Fatal(err)
			}
			inspector := protectedApprovedRuntimeEvidence{
				verifier: &runtimeEvidenceVerifier{},
				platform: func(string) (string, runtimeEvidencePlatform, error) {
					return "windows-11", runtimeEvidencePlatform{}, nil
				},
				build: func(string) (runtimeEvidenceBuild, error) { return runtimeEvidenceBuild{}, nil },
			}
			if approved, err := inspector.Approved(context.Background(), validatedSetup{stateRoot: root}, setupManifest{}); err == nil || approved {
				t.Fatalf("malformed evidence approved: approved=%v err=%v", approved, err)
			}
		})
	}
}

func TestProtectedApprovedRuntimeEvidenceRequiresProtectedFile(t *testing.T) {
	root := t.TempDir()
	writeApprovedRuntimeEvidence(t, root, validApprovedRuntimeEvidence())
	inspector := protectedApprovedRuntimeEvidence{
		verifier: &runtimeEvidenceVerifier{err: errors.New("permissive DACL")},
		platform: func(string) (string, runtimeEvidencePlatform, error) {
			return "", runtimeEvidencePlatform{}, errors.New("must not inspect")
		},
		build: func(string) (runtimeEvidenceBuild, error) {
			return runtimeEvidenceBuild{}, errors.New("must not inspect")
		},
	}
	if approved, err := inspector.Approved(context.Background(), validatedSetup{stateRoot: root}, setupManifest{}); err == nil || approved {
		t.Fatalf("unprotected evidence approved: approved=%v err=%v", approved, err)
	}
}

func validApprovedRuntimeEvidence() approvedRuntimeEvidence {
	nonce := "0123456789abcdef0123456789abcdef"
	run := runtimeEvidenceRunManifest{
		SchemaVersion: runtimeRunManifestSchemaVersion, RunNonce: nonce,
		SourceRevision: strings.Repeat("a", 40),
		Platform: runtimeEvidencePlatform{
			WindowsBuild: "10.0.26100", Architecture: "amd64", Filesystem: "NTFS:00000001:00000002",
		},
		TokenInventorySHA256: strings.Repeat("1", 64), RuntimeManifestSHA256: task5RuntimeManifestSHA256,
		MatrixSHA256: strings.Repeat("2", 64), ExactTokenGatePassed: true,
		StartedUTC: "2026-07-22T12:00:00Z", FinishedUTC: "2026-07-22T12:00:02Z",
	}
	for index, name := range requiredTask5Runtimes {
		run.Runtimes = append(run.Runtimes, runtimeEvidenceExecution{
			Name: name, ExecutablePath: `C:\runtime.exe`, ObjectIdentity: "volume=1 file=" + name,
			ExecutableSHA256: strings.Repeat("3", 64), PID: 100 + index, Status: "PASS",
			CallerPID: 99, AttemptID: nonce + "/" + name,
		})
	}
	return approvedRuntimeEvidence{
		SchemaVersion: runtimeEvidenceSchemaVersion, Selection: runtimeEvidenceSelectionExactToken,
		SupportedImage: "windows-11", GoVersion: "go1.26.4", Run: run,
	}
}

func writeApprovedRuntimeEvidence(t *testing.T, root string, evidence approvedRuntimeEvidence) {
	t.Helper()
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, runtimeEvidenceName), data, 0600); err != nil {
		t.Fatal(err)
	}
}
