package inspectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type ComposerInspector struct{}

func (i *ComposerInspector) Name() string      { return "composer" }
func (i *ComposerInspector) Ecosystem() string { return "packagist" }

func (i *ComposerInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if scope == "project" {
		if path == "" {
			return nil, nil
		}
		if _, err := os.Stat(filepath.Join(path, "composer.json")); err != nil {
			return nil, nil
		}
		return inspectComposerLock(path)
	}

	if _, err := exec.LookPath("composer"); err != nil {
		return nil, nil
	}

	cmd := exec.Command("composer", "show", "--format=json", "--no-interaction", "--global")
	out, err := cmd.Output()
	if err != nil {
		if len(out) == 0 {
			return nil, nil
		}
	}

	var raw struct {
		Installed []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"installed"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}

	packages := make([]schema.Package, 0, len(raw.Installed))
	for _, p := range raw.Installed {
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   strings.TrimPrefix(p.Version, "v"),
			Ecosystem: "packagist",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}

// inspectComposerLock reads composer.lock and returns all locked packages with
// accurate versions, avoiding the stale-cache problem of `composer show`.
func inspectComposerLock(path string) ([]schema.Package, error) {
	lockPath := filepath.Join(path, "composer.lock")
	f, err := os.Open(lockPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var lock struct {
		Packages    []composerLockPkg `json:"packages"`
		PackagesDev []composerLockPkg `json:"packages-dev"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, err
	}

	vendorDir := filepath.Join(path, "vendor")

	var packages []schema.Package
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		pkgPath := filepath.Join(vendorDir, p.Name)
		if _, err := os.Stat(pkgPath); err != nil {
			pkgPath = ""
		}
		packages = append(packages, schema.Package{
			Name:      p.Name,
			Version:   strings.TrimPrefix(p.Version, "v"),
			Ecosystem: "packagist",
			Scope:     "project",
			Direct:    true,
			Path:      pkgPath,
		})
	}
	return packages, nil
}

type composerLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
