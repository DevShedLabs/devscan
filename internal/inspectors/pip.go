package inspectors

import (
	"encoding/json"
	"os/exec"
	"path/filepath"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type PipInspector struct{}

func (i *PipInspector) Name() string      { return "pip" }
func (i *PipInspector) Ecosystem() string { return "pypi" }

func (i *PipInspector) Inspect(scope, path string) ([]schema.Package, error) {
	binary := "pip3"
	if _, err := exec.LookPath(binary); err != nil {
		binary = "pip"
		if _, err := exec.LookPath(binary); err != nil {
			return nil, nil
		}
	}

	// -v adds the "location" field (install directory) to JSON output.
	cmd := exec.Command(binary, "list", "-v", "--format=json")
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var raw []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Location string `json:"location"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(raw))
	for _, p := range raw {
		pkgPath := ""
		if p.Location != "" {
			// Point to the package directory inside site-packages.
			pkgPath = filepath.Join(p.Location, p.Name)
		}
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: "pypi",
			Scope:     scope,
			Direct:    true,
			Path:      pkgPath,
		})
	}
	return packages, nil
}
