package baseline

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

//go:embed trace-evidence.schema.json
var traceEvidenceSchema []byte

type TraceCollector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Command string `json:"command"`
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
	Runtime  string        `json:"runtime"`
	Complete bool          `json:"complete"`
	Denials  []TraceDenial `json:"denials"`
}

type TraceEvidence struct {
	SchemaVersion  int            `json:"schema_version"`
	Collector      TraceCollector `json:"collector"`
	RawTraceSHA256 string         `json:"raw_trace_sha256"`
	Cases          []TraceCase    `json:"cases"`
}

func LoadTraceEvidence(path string) (TraceEvidence, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return TraceEvidence{}, fmt.Errorf("read trace evidence: %w", err)
	}
	var evidence TraceEvidence
	if err := json.Unmarshal(contents, &evidence); err != nil {
		return TraceEvidence{}, fmt.Errorf("decode trace evidence: %w", err)
	}
	return evidence, nil
}

func ValidateFailureTrace(failures []string, evidence TraceEvidence) error {
	if len(failures) == 0 {
		return nil
	}
	if evidence.SchemaVersion != 1 {
		return fmt.Errorf("trace schema version %d, want 1", evidence.SchemaVersion)
	}
	if evidence.Collector.Name == "" || evidence.Collector.Version == "" || evidence.Collector.Command == "" {
		return fmt.Errorf("trace collector name, version, and command are required")
	}
	digest, err := hex.DecodeString(evidence.RawTraceSHA256)
	if err != nil || len(digest) != 32 {
		return fmt.Errorf("raw_trace_sha256 must be 64 hexadecimal characters")
	}
	byRuntime := make(map[string]TraceCase)
	for _, traceCase := range evidence.Cases {
		if traceCase.Runtime == "" {
			return fmt.Errorf("trace case has empty runtime")
		}
		if _, duplicate := byRuntime[traceCase.Runtime]; duplicate {
			return fmt.Errorf("duplicate trace case for runtime %q", traceCase.Runtime)
		}
		if !traceCase.Complete {
			return fmt.Errorf("trace case %q is not marked complete", traceCase.Runtime)
		}
		byRuntime[traceCase.Runtime] = traceCase
	}
	for _, runtimeName := range failures {
		traceCase, ok := byRuntime[runtimeName]
		if !ok || len(traceCase.Denials) == 0 {
			return fmt.Errorf("failed runtime %q lacks trace-backed denials", runtimeName)
		}
		for index, denial := range traceCase.Denials {
			if denial.Operation == "" || denial.RequestedAccess == "" || denial.ObjectPath == "" || denial.ObjectIdentity == "" || denial.Owner == "" || denial.DACL == "" {
				return fmt.Errorf("failed runtime %q denial %d lacks operation/access/path/identity/owner/DACL", runtimeName, index)
			}
		}
	}
	return nil
}
