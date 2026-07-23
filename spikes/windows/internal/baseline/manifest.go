package baseline

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	windowsWorkstationProductType = 1
	windowsDomainControllerType   = 2
	windowsServerProductType      = 3
	windows11FirstBuild           = 22000
)

//go:embed runtime-manifest.json
var runtimeManifestJSON []byte

type RuntimeSpec struct {
	Name       string   `json:"name"`
	Resolver   string   `json:"resolver"`
	Candidates []string `json:"candidates,omitempty"`
	Args       []string `json:"args,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	NewConsole bool     `json:"new_console,omitempty"`
}

type RuntimeManifest struct {
	SchemaVersion   int           `json:"schema_version"`
	SupportedImages []string      `json:"supported_images"`
	Required        []RuntimeSpec `json:"required"`
	InventoryOnly   []RuntimeSpec `json:"inventory_only"`
}

// ClassifyWindowsImage maps the native Windows version tuple to one of the
// product images named by the runtime manifest. It deliberately rejects
// Windows 10 clients: a successful run there is not evidence for Windows 11.
func ClassifyWindowsImage(major, minor, build uint32, productType byte) (string, error) {
	if major != 10 || minor != 0 {
		return "", fmt.Errorf("unsupported Windows version %d.%d.%d", major, minor, build)
	}
	switch productType {
	case windowsWorkstationProductType:
		if build < windows11FirstBuild {
			return "", fmt.Errorf("unsupported Windows client build %d (Windows 11 starts at %d)", build, windows11FirstBuild)
		}
		return "windows-11", nil
	case windowsDomainControllerType, windowsServerProductType:
		return "windows-server", nil
	default:
		return "", fmt.Errorf("unsupported Windows product type %d", productType)
	}
}

// SupportsImage reports whether the product image is explicitly in scope for
// this runtime manifest.
func (m RuntimeManifest) SupportsImage(image string) bool {
	for _, supported := range m.SupportedImages {
		if supported == image {
			return true
		}
	}
	return false
}

func LoadRuntimeManifest() (RuntimeManifest, error) {
	var manifest RuntimeManifest
	if err := json.Unmarshal(runtimeManifestJSON, &manifest); err != nil {
		return RuntimeManifest{}, fmt.Errorf("decode runtime manifest: %w", err)
	}
	if manifest.SchemaVersion != 1 {
		return RuntimeManifest{}, fmt.Errorf("runtime manifest schema version %d, want 1", manifest.SchemaVersion)
	}
	seen := make(map[string]string)
	for class, specs := range map[string][]RuntimeSpec{"required": manifest.Required, "inventory_only": manifest.InventoryOnly} {
		for _, spec := range specs {
			if spec.Name == "" || spec.Resolver == "" {
				return RuntimeManifest{}, fmt.Errorf("%s runtime has empty name or resolver", class)
			}
			if previous := seen[spec.Name]; previous != "" {
				return RuntimeManifest{}, fmt.Errorf("runtime %q occurs in both %s and %s", spec.Name, previous, class)
			}
			seen[spec.Name] = class
		}
	}
	return manifest, nil
}

func (m RuntimeManifest) RequireExactly(want []string) error {
	got := make([]string, 0, len(m.Required))
	for _, spec := range m.Required {
		got = append(got, spec.Name)
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("required runtime names = %v, want %v", got, want)
	}
	return nil
}
