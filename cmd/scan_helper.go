package cmd

import (
	"os"
	"time"

	"github.com/DevShedLabs/devscan/internal/advisory"
	"github.com/DevShedLabs/devscan/internal/detectors"
	"github.com/DevShedLabs/devscan/internal/inspectors"
	"github.com/DevShedLabs/devscan/internal/schema"
	"github.com/DevShedLabs/devscan/internal/versions"
	"github.com/spf13/cobra"
)

type scanOptions struct {
	scope   string // "global" | "project"
	path    string
	noCache bool
}

func scanOptsFromCmd(cmd *cobra.Command) scanOptions {
	project, _ := cmd.Flags().GetBool("project")
	global, _ := cmd.Flags().GetBool("global")
	path, _ := cmd.Flags().GetString("path")
	noCache, _ := cmd.Flags().GetBool("no-cache")

	scope := "global"
	if project || path != "" {
		scope = "project"
	}
	_ = global

	if path == "" && scope == "project" {
		cwd, _ := os.Getwd()
		path = cwd
	}

	return scanOptions{scope: scope, path: path, noCache: noCache}
}

func deduplicatePackages(packages []schema.Package) []schema.Package {
	seen := map[string]bool{}
	out := make([]schema.Package, 0, len(packages))
	for _, p := range packages {
		key := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func runFullScan(opts scanOptions) (*schema.Report, error) {
	start := time.Now()

	report := &schema.Report{
		Meta: schema.Meta{
			Version:   "0.1.0",
			Timestamp: start,
			Target:    opts.scope,
			Path:      opts.path,
		},
		System: map[string]string{},
	}

	// Detect runtimes and enrich with latest version info
	report.Runtimes = detectors.RunAll(detectors.All())
	versions.Enrich(report.Runtimes)

	// Inspect packages
	report.Packages = deduplicatePackages(inspectors.RunAll(inspectors.All(), opts.scope, opts.path))

	// Query advisories
	client := advisory.NewClient(opts.noCache)
	vulns, err := client.QueryPackages(report.Packages)
	if err == nil {
		report.Vulnerabilities = vulns
	}

	report.Meta.DurationMs = time.Since(start).Milliseconds()
	report.ComputeSummary()

	return report, nil
}
