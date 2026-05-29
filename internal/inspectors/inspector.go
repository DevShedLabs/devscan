package inspectors

import (
	"github.com/DevShedLabs/devscan/internal/schema"
)

// Inspector scans an ecosystem for installed packages.
type Inspector interface {
	Name() string
	Ecosystem() string
	// Inspect returns packages for the given scope and path.
	// scope: "global" | "project"
	Inspect(scope, path string) ([]schema.Package, error)
}

// RunAll runs all registered inspectors concurrently and merges results.
func RunAll(inspectors []Inspector, scope, path string) []schema.Package {
	type result struct {
		packages []schema.Package
		err      error
	}

	ch := make(chan result, len(inspectors))

	for _, ins := range inspectors {
		ins := ins
		go func() {
			pkgs, err := ins.Inspect(scope, path)
			ch <- result{pkgs, err}
		}()
	}

	var packages []schema.Package
	for range inspectors {
		res := <-ch
		if res.err == nil {
			packages = append(packages, res.packages...)
		}
	}
	return packages
}

// All returns the default set of inspectors.
func All() []Inspector {
	return []Inspector{
		&NpmInspector{},
		&PipInspector{},
		&ComposerInspector{},
		&CargoInspector{},
		&GoModInspector{},
		&BrewInspector{},
	}
}
