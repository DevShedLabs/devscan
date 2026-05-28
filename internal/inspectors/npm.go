package inspectors

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type NpmInspector struct{}

func (i *NpmInspector) Name() string      { return "npm" }
func (i *NpmInspector) Ecosystem() string { return "npm" }

func (i *NpmInspector) Inspect(scope, path string) ([]schema.Package, error) {
	args := []string{"list", "--json", "--depth=0"}
	if scope == "global" {
		args = append(args, "--global")
	}

	cmd := exec.Command("npm", args...)
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		if len(out) == 0 {
			return nil, err
		}
	}

	var raw struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	modulesRoot := npmModulesRoot(scope, path)

	var packages []schema.Package
	for name, dep := range raw.Dependencies {
		pkgPath := ""
		if modulesRoot != "" {
			pkgPath = filepath.Join(modulesRoot, name)
		}
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
			Scope:     scope,
			Direct:    true,
			Path:      pkgPath,
		})
	}
	return packages, nil
}

func npmModulesRoot(scope, projectPath string) string {
	if scope == "project" && projectPath != "" {
		return filepath.Join(projectPath, "node_modules")
	}
	out, err := exec.Command("npm", "root", "-g").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
