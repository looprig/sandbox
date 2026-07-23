//go:build windows

package windows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	win "golang.org/x/sys/windows"
)

const (
	runtimeEvidenceName                      = "runtime-evidence.json"
	runtimeEvidenceSchemaVersion             = 1
	runtimeRunManifestSchemaVersion          = 3
	runtimeEvidenceSelectionExactToken       = "exact-token"
	task5RuntimeManifestSHA256               = "93b0c2b3ccfdb2d628938a615601f1237d010e8611e50e1f743127fa7892df4b"
	maxRuntimeEvidenceBytes            int64 = 4 << 20
)

var requiredTask5Runtimes = []string{
	"installed-runner-go-helper",
	"go-subprocess",
	"crt-and-dll-initializers",
	"locale-and-console-startup",
	"pe-tls-callback-fixture",
	"canonical-system32-cmd",
	"windows-powershell",
	"python",
}

type runtimeEvidencePlatform struct {
	WindowsBuild string `json:"windows_build"`
	Architecture string `json:"architecture"`
	Filesystem   string `json:"filesystem"`
}

type runtimeEvidenceExecution struct {
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

type runtimeEvidenceCollector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Command string `json:"command"`
}

type runtimeEvidenceRunManifest struct {
	SchemaVersion         int                        `json:"schema_version"`
	RunNonce              string                     `json:"run_nonce"`
	SourceRevision        string                     `json:"source_revision"`
	Platform              runtimeEvidencePlatform    `json:"platform"`
	TokenInventorySHA256  string                     `json:"token_inventory_sha256"`
	RuntimeManifestSHA256 string                     `json:"runtime_manifest_sha256"`
	MatrixSHA256          string                     `json:"matrix_sha256"`
	ExactTokenGatePassed  bool                       `json:"exact_token_gate_passed"`
	Runtimes              []runtimeEvidenceExecution `json:"runtimes"`
	Collector             runtimeEvidenceCollector   `json:"collector"`
	RawTracePath          string                     `json:"raw_trace_path"`
	RawTraceSHA256        string                     `json:"raw_trace_sha256"`
	StartedUTC            string                     `json:"started_utc"`
	FinishedUTC           string                     `json:"finished_utc"`
}

// approvedRuntimeEvidence wraps the v3 Task 5 run manifest with the reviewed
// selection and the exact Go toolchain that produced it. The run nonce,
// source revision, platform, token/matrix digests, executable identities, and
// versioned runtime-contract digest remain in their original Task 5 format.
type approvedRuntimeEvidence struct {
	SchemaVersion  int                        `json:"schema_version"`
	Selection      string                     `json:"selection"`
	SupportedImage string                     `json:"supported_image"`
	GoVersion      string                     `json:"go_version"`
	Run            runtimeEvidenceRunManifest `json:"run"`
}

type runtimeEvidenceBuild struct {
	GoVersion, Revision string
}

type runtimeEvidencePlatformProvider func(string) (string, runtimeEvidencePlatform, error)
type runtimeEvidenceBuildProvider func(string) (runtimeEvidenceBuild, error)

type protectedApprovedRuntimeEvidence struct {
	verifier brokerInstallPathVerifier
	platform runtimeEvidencePlatformProvider
	build    runtimeEvidenceBuildProvider
}

func (p protectedApprovedRuntimeEvidence) Approved(_ context.Context, setup validatedSetup, manifest setupManifest) (bool, error) {
	if p.verifier == nil || p.platform == nil || p.build == nil {
		return false, errors.New("sandbox: incomplete approved runtime evidence verifier")
	}
	path := filepath.Join(setup.stateRoot, runtimeEvidenceName)
	if err := p.verifier.Verify(path, setup.ownerSID); err != nil {
		return false, fmt.Errorf("verify protected Windows runtime evidence: %w", err)
	}
	data, err := readBoundedRuntimeEvidence(path)
	if err != nil {
		return false, err
	}
	var evidence approvedRuntimeEvidence
	if err := strictJSON(data, &evidence); err != nil {
		return false, fmt.Errorf("decode approved Windows runtime evidence: %w", err)
	}
	image, platform, err := p.platform(setup.stateRoot)
	if err != nil {
		return false, fmt.Errorf("inspect Windows runtime evidence platform: %w", err)
	}
	build, err := p.build(manifest.HostPath)
	if err != nil {
		return false, fmt.Errorf("inspect installed Windows host build: %w", err)
	}
	if err := validateApprovedRuntimeEvidence(evidence, image, platform, build); err != nil {
		return false, err
	}
	return true, nil
}

func validateApprovedRuntimeEvidence(e approvedRuntimeEvidence, image string, platform runtimeEvidencePlatform, build runtimeEvidenceBuild) error {
	fail := func(reason string) error {
		return fmt.Errorf("%w: approved Windows runtime evidence %s", ErrSetupStale, reason)
	}
	if e.SchemaVersion != runtimeEvidenceSchemaVersion ||
		e.Selection != runtimeEvidenceSelectionExactToken {
		return fail("has an unsupported schema or selection")
	}
	evidenceFilesystem, evidenceFilesystemErr := runtimeEvidenceFilesystemClass(e.Run.Platform.Filesystem)
	currentFilesystem, currentFilesystemErr := runtimeEvidenceFilesystemClass(platform.Filesystem)
	if e.SupportedImage != image || e.Run.Platform.WindowsBuild != platform.WindowsBuild ||
		e.Run.Platform.Architecture != platform.Architecture ||
		evidenceFilesystemErr != nil || currentFilesystemErr != nil ||
		evidenceFilesystem != currentFilesystem {
		return fail("does not bind the current supported OS image")
	}
	if e.GoVersion == "" || e.GoVersion != build.GoVersion ||
		e.Run.SourceRevision == "" || !strings.EqualFold(e.Run.SourceRevision, build.Revision) {
		return fail("does not bind the installed host toolchain and source revision")
	}
	if e.Run.SchemaVersion != runtimeRunManifestSchemaVersion ||
		!e.Run.ExactTokenGatePassed ||
		!validRuntimeNonce(e.Run.RunNonce) ||
		!validSHA256(e.Run.TokenInventorySHA256) ||
		!validSHA256(e.Run.MatrixSHA256) ||
		e.Run.RuntimeManifestSHA256 != task5RuntimeManifestSHA256 {
		return fail("does not contain a complete passing Task 5 run binding")
	}
	started, startErr := time.Parse(time.RFC3339Nano, e.Run.StartedUTC)
	finished, finishErr := time.Parse(time.RFC3339Nano, e.Run.FinishedUTC)
	if startErr != nil || finishErr != nil || finished.Before(started) {
		return fail("has an invalid run time window")
	}
	seen := make(map[string]runtimeEvidenceExecution, len(e.Run.Runtimes))
	for _, execution := range e.Run.Runtimes {
		if execution.Name == "" {
			return fail("contains an unnamed runtime")
		}
		if _, duplicate := seen[execution.Name]; duplicate {
			return fail("contains a duplicate runtime")
		}
		seen[execution.Name] = execution
	}
	for _, name := range requiredTask5Runtimes {
		execution, ok := seen[name]
		if !ok || execution.Status != "PASS" || execution.ExitCode != 0 ||
			execution.PID <= 0 || execution.CallerPID <= 0 ||
			execution.ObjectIdentity == "" || !validSHA256(execution.ExecutableSHA256) ||
			execution.AttemptID != e.Run.RunNonce+"/"+name {
			return fail("does not prove every required runtime")
		}
	}
	return nil
}

// Task 5 evidence describes a supported image/filesystem capability, not one
// physical worker. The spike records type:serial:flags for audit provenance;
// promotion deliberately ignores only the volume serial so a standard-user
// evidence job can authorize a distinct disposable elevated worker with the
// same exact build, architecture, filesystem type, and filesystem flags.
func runtimeEvidenceFilesystemClass(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 ||
		(!strings.EqualFold(parts[0], "NTFS") && !strings.EqualFold(parts[0], "ReFS")) ||
		len(parts[1]) != 8 || len(parts[2]) != 8 {
		return "", errors.New("invalid Windows runtime evidence filesystem identity")
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", errors.New("invalid Windows runtime evidence volume serial")
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return "", errors.New("invalid Windows runtime evidence filesystem flags")
	}
	return strings.ToUpper(parts[0]) + ":" + strings.ToLower(parts[2]), nil
}

func validRuntimeNonce(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func currentRuntimeEvidencePlatform(stateRoot string) (string, runtimeEvidencePlatform, error) {
	version := win.RtlGetVersion()
	image := ""
	switch version.ProductType {
	case 1:
		if version.MajorVersion != 10 || version.MinorVersion != 0 || version.BuildNumber < 22000 {
			return "", runtimeEvidencePlatform{}, fmt.Errorf("unsupported Windows client %d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
		}
		image = "windows-11"
	case 2, 3:
		if version.MajorVersion != 10 || version.MinorVersion != 0 {
			return "", runtimeEvidencePlatform{}, fmt.Errorf("unsupported Windows server %d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber)
		}
		image = "windows-server"
	default:
		return "", runtimeEvidencePlatform{}, fmt.Errorf("unsupported Windows product type %d", version.ProductType)
	}
	volume := filepath.VolumeName(stateRoot)
	if volume == "" {
		return "", runtimeEvidencePlatform{}, errors.New("Windows runtime evidence state volume is unavailable")
	}
	root, err := win.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return "", runtimeEvidencePlatform{}, err
	}
	fsName := make([]uint16, win.MAX_PATH+1)
	var serial, maxComponent, flags uint32
	if err := win.GetVolumeInformation(root, nil, 0, &serial, &maxComponent, &flags, &fsName[0], uint32(len(fsName))); err != nil {
		return "", runtimeEvidencePlatform{}, fmt.Errorf("inspect Windows runtime evidence volume: %w", err)
	}
	filesystem := win.UTF16ToString(fsName)
	if !strings.EqualFold(filesystem, "NTFS") && !strings.EqualFold(filesystem, "ReFS") {
		return "", runtimeEvidencePlatform{}, fmt.Errorf("unsupported Windows runtime evidence filesystem %q", filesystem)
	}
	return image, runtimeEvidencePlatform{
		WindowsBuild: fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber),
		Architecture: runtime.GOARCH,
		Filesystem:   fmt.Sprintf("%s:%08x:%08x", filesystem, serial, flags),
	}, nil
}

func readRuntimeEvidenceBuild(path string) (runtimeEvidenceBuild, error) {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return runtimeEvidenceBuild{}, err
	}
	result := runtimeEvidenceBuild{GoVersion: info.GoVersion}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			result.Revision = setting.Value
			break
		}
	}
	if result.GoVersion == "" || result.Revision == "" {
		return runtimeEvidenceBuild{}, errors.New("sandbox: installed host lacks Go version or VCS revision")
	}
	return result, nil
}

func importApprovedRuntimeEvidence(setup validatedSetup) error {
	source := filepath.Clean(setup.config.RuntimeEvidencePath)
	if setup.config.RuntimeEvidencePath == "" || !filepath.IsAbs(source) ||
		source != setup.config.RuntimeEvidencePath {
		return errors.New("sandbox: Task 5 runtime evidence source must be an absolute canonical path")
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() {
		return errors.Join(errors.New("sandbox: Task 5 runtime evidence source must be a regular file"), err)
	}
	attributes, err := win.GetFileAttributes(win.StringToUTF16Ptr(source))
	if err != nil || attributes&win.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("sandbox: Task 5 runtime evidence source must not be a reparse point"), err)
	}
	data, err := readBoundedRuntimeEvidence(source)
	if err != nil {
		return err
	}
	var evidence approvedRuntimeEvidence
	if err := strictJSON(data, &evidence); err != nil {
		return fmt.Errorf("decode Task 5 runtime evidence source: %w", err)
	}
	image, platform, err := currentRuntimeEvidencePlatform(setup.stateRoot)
	if err != nil {
		return fmt.Errorf("inspect Task 5 runtime evidence platform: %w", err)
	}
	build, err := readRuntimeEvidenceBuild(setup.sourceHost)
	if err != nil {
		return fmt.Errorf("inspect Task 5 runtime evidence host build: %w", err)
	}
	if err := validateApprovedRuntimeEvidence(evidence, image, platform, build); err != nil {
		return err
	}
	destination := filepath.Join(setup.stateRoot, runtimeEvidenceName)
	if strings.EqualFold(source, destination) {
		return (realBrokerInstallPathVerifier{}).Verify(destination, setup.ownerSID)
	}
	temporary := destination + ".tmp"
	_ = os.Remove(temporary)
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if err := protectSetupPath(temporary, setup.ownerSID, setup.sandboxSID, false); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	if err := win.MoveFileEx(win.StringToUTF16Ptr(temporary), win.StringToUTF16Ptr(destination), win.MOVEFILE_REPLACE_EXISTING|win.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	cleanup = false
	return (realBrokerInstallPathVerifier{}).Verify(destination, setup.ownerSID)
}

func readBoundedRuntimeEvidence(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRuntimeEvidenceBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxRuntimeEvidenceBytes {
		return nil, errors.New("sandbox: Windows runtime evidence exceeds size limit")
	}
	return data, nil
}

func strictJSON(data []byte, target any) error {
	if err := rejectRuntimeEvidenceDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectRuntimeEvidenceDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var parse func() error
	parse = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("non-string JSON object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := parse(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := parse(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := parse(); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
