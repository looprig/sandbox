package baseline

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

//go:embed trace-evidence.schema.json
var traceEvidenceSchema []byte

type RunPlatform struct {
	WindowsBuild string `json:"windows_build"`
	Architecture string `json:"architecture"`
	Filesystem   string `json:"filesystem"`
}

type RuntimeExecution struct {
	Name             string   `json:"name"`
	ExecutablePath   string   `json:"executable_path"`
	ObjectIdentity   string   `json:"object_identity"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	PID              int      `json:"pid"`
	Status           string   `json:"status"`
	ExitCode         int      `json:"exit_code"`
	Diagnostic       string   `json:"diagnostic"`
	FailureKind      string   `json:"failure_kind,omitempty"`
	CallerPID        int      `json:"caller_pid,omitempty"`
	AttemptID        string   `json:"attempt_id,omitempty"`
	LookupEvidence   []string `json:"lookup_evidence,omitempty"`
	Win32Error       string   `json:"win32_error,omitempty"`
}

const (
	FailureInventoryAbsent = "inventory_absent"
	FailurePreSpawn        = "pre_spawn"
	FailurePostSpawn       = "post_spawn"
)

type TraceCollector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Command string `json:"command"`
}

type RunManifest struct {
	SchemaVersion         int                `json:"schema_version"`
	RunNonce              string             `json:"run_nonce"`
	SourceRevision        string             `json:"source_revision"`
	Platform              RunPlatform        `json:"platform"`
	TokenInventorySHA256  string             `json:"token_inventory_sha256"`
	RuntimeManifestSHA256 string             `json:"runtime_manifest_sha256"`
	MatrixSHA256          string             `json:"matrix_sha256"`
	ExactTokenGatePassed  bool               `json:"exact_token_gate_passed"`
	Runtimes              []RuntimeExecution `json:"runtimes"`
	Collector             TraceCollector     `json:"collector"`
	RawTracePath          string             `json:"raw_trace_path"`
	RawTraceSHA256        string             `json:"raw_trace_sha256"`
}

type TraceDenial struct {
	Operation       string `json:"operation"`
	RequestedAccess string `json:"requested_access"`
	ObjectPath      string `json:"object_path"`
	ObjectIdentity  string `json:"object_identity"`
	Owner           string `json:"owner"`
	DACL            string `json:"dacl"`
}

type TraceCase struct {
	Runtime           RuntimeExecution `json:"runtime"`
	Complete          bool             `json:"complete"`
	CapturedPIDs      []int            `json:"captured_pids"`
	CapturedNonce     string           `json:"captured_nonce"`
	CapturedAttemptID string           `json:"captured_attempt_id"`
	Events            []TraceEvent     `json:"events,omitempty"`
	Denials           []TraceDenial    `json:"denials"`
}

type TraceEvent struct {
	Operation string `json:"operation"`
	Result    string `json:"result"`
	Path      string `json:"path"`
}

type TraceEvidence struct {
	SchemaVersion int         `json:"schema_version"`
	Run           RunManifest `json:"run"`
	Cases         []TraceCase `json:"cases"`
}

func SHA256Hex(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func RuntimeManifestDigest() string { return SHA256Hex(runtimeManifestJSON) }

func LoadRunManifest(path string) (RunManifest, error) {
	var manifest RunManifest
	if err := loadJSON(path, &manifest); err != nil {
		return RunManifest{}, err
	}
	return manifest, nil
}

func LoadTraceEvidence(path string) (TraceEvidence, error) {
	var evidence TraceEvidence
	if err := loadJSON(path, &evidence); err != nil {
		return TraceEvidence{}, err
	}
	return evidence, nil
}

func loadJSON(path string, target any) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(contents, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func FinalizeRunManifest(invocation RunManifest, collector TraceCollector, rawTracePath string) (RunManifest, error) {
	absolute, err := filepath.Abs(rawTracePath)
	if err != nil {
		return RunManifest{}, fmt.Errorf("absolute raw trace path: %w", err)
	}
	contents, err := os.ReadFile(absolute)
	if err != nil {
		return RunManifest{}, fmt.Errorf("read raw trace: %w", err)
	}
	invocation.Collector = collector
	invocation.RawTracePath = absolute
	invocation.RawTraceSHA256 = SHA256Hex(contents)
	return invocation, nil
}

func ValidateFailureTrace(manifest RunManifest, evidence TraceEvidence) error {
	if manifest.SchemaVersion != 3 || evidence.SchemaVersion != 3 || evidence.Run.SchemaVersion != 3 {
		return fmt.Errorf("run/trace schema version must be 3")
	}
	if manifest.ExactTokenGatePassed || evidence.Run.ExactTokenGatePassed {
		return fmt.Errorf("failure evidence cannot claim exact-token PASS")
	}
	if err := compareRunBinding(manifest, evidence.Run); err != nil {
		return err
	}
	if !filepath.IsAbs(manifest.RawTracePath) {
		return fmt.Errorf("raw trace path must be absolute")
	}
	raw, err := os.ReadFile(manifest.RawTracePath)
	if err != nil {
		return fmt.Errorf("open bound raw trace: %w", err)
	}
	if got := SHA256Hex(raw); got != manifest.RawTraceSHA256 {
		return fmt.Errorf("raw trace hash mismatch: got %s want %s", got, manifest.RawTraceSHA256)
	}
	failed := make(map[string]RuntimeExecution)
	for _, runtime := range manifest.Runtimes {
		if runtime.Status == "FAIL" {
			failed[runtime.Name] = runtime
		}
	}
	if len(failed) == 0 {
		return fmt.Errorf("run manifest has no failed runtimes")
	}
	cases := make(map[string]TraceCase)
	for _, traceCase := range evidence.Cases {
		name := traceCase.Runtime.Name
		if _, exists := cases[name]; exists {
			return fmt.Errorf("duplicate trace case for runtime %q", name)
		}
		cases[name] = traceCase
	}
	for name, runtime := range failed {
		traceCase, ok := cases[name]
		if !ok {
			return fmt.Errorf("failed runtime %q lacks trace case", name)
		}
		if !reflect.DeepEqual(traceCase.Runtime, runtime) {
			return fmt.Errorf("failed runtime %q path/identity/hash/PID/exit/diagnostic mismatch", name)
		}
		if err := validateTraceCase(manifest.RunNonce, runtime, traceCase); err != nil {
			return fmt.Errorf("failed runtime %q: %w", name, err)
		}
		for index, denial := range traceCase.Denials {
			if denial.Operation == "" || denial.RequestedAccess == "" || denial.ObjectPath == "" || denial.ObjectIdentity == "" || denial.Owner == "" || denial.DACL == "" {
				return fmt.Errorf("failed runtime %q denial %d is incomplete", name, index)
			}
		}
	}
	return nil
}

func compareRunBinding(want, got RunManifest) error {
	checks := []struct{ name, want, got string }{
		{"nonce", want.RunNonce, got.RunNonce}, {"revision", want.SourceRevision, got.SourceRevision},
		{"windows build", want.Platform.WindowsBuild, got.Platform.WindowsBuild}, {"architecture", want.Platform.Architecture, got.Platform.Architecture},
		{"filesystem", want.Platform.Filesystem, got.Platform.Filesystem}, {"token", want.TokenInventorySHA256, got.TokenInventorySHA256},
		{"runtime manifest", want.RuntimeManifestSHA256, got.RuntimeManifestSHA256}, {"matrix", want.MatrixSHA256, got.MatrixSHA256},
		{"collector name", want.Collector.Name, got.Collector.Name}, {"collector version", want.Collector.Version, got.Collector.Version},
		{"collector command", want.Collector.Command, got.Collector.Command}, {"raw trace path", want.RawTracePath, got.RawTracePath},
		{"raw trace hash", want.RawTraceSHA256, got.RawTraceSHA256},
	}
	for _, check := range checks {
		if check.want == "" || check.want != check.got {
			return fmt.Errorf("%s binding mismatch", check.name)
		}
	}
	if len(want.Runtimes) != len(got.Runtimes) {
		return fmt.Errorf("runtime count binding mismatch")
	}
	for index := range want.Runtimes {
		if !reflect.DeepEqual(want.Runtimes[index], got.Runtimes[index]) {
			return fmt.Errorf("runtime %d binding mismatch", index)
		}
	}
	return nil
}

func validateTraceCase(nonce string, runtime RuntimeExecution, traceCase TraceCase) error {
	if !traceCase.Complete || traceCase.CapturedNonce != nonce || traceCase.CapturedAttemptID != runtime.AttemptID || !containsPID(traceCase.CapturedPIDs, runtime.CallerPID) {
		return fmt.Errorf("trace lacks complete caller nonce/attempt/PID binding")
	}
	switch runtime.FailureKind {
	case FailureInventoryAbsent:
		if runtime.PID != 0 || runtime.ExecutableSHA256 != "" || runtime.Win32Error != "" || len(runtime.LookupEvidence) == 0 || len(traceCase.Events) != 0 || len(traceCase.Denials) != 0 {
			return fmt.Errorf("inventory_absent requires lookup evidence and forbids child/hash/Win32/collector denial fabrication")
		}
	case FailurePreSpawn:
		if runtime.PID != 0 || runtime.Win32Error == "" || runtime.ExecutablePath == "" || len(traceCase.Events) == 0 {
			return fmt.Errorf("pre_spawn requires candidate/Win32 error/caller-keyed collector events and no child PID")
		}
	case FailurePostSpawn:
		if runtime.PID <= 0 || runtime.ExecutableSHA256 == "" || runtime.ObjectIdentity == "" || !containsPID(traceCase.CapturedPIDs, runtime.PID) || len(traceCase.Events) == 0 {
			return fmt.Errorf("post_spawn requires child PID/executable hash/identity and child-keyed events")
		}
	default:
		return fmt.Errorf("unknown failure kind %q", runtime.FailureKind)
	}
	for _, event := range traceCase.Events {
		if event.Operation == "" || event.Result == "" || event.Path == "" {
			return fmt.Errorf("collector event is incomplete")
		}
	}
	return nil
}

func containsPID(pids []int, want int) bool {
	for _, pid := range pids {
		if pid == want {
			return true
		}
	}
	return false
}
