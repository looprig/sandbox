package baseline

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
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
