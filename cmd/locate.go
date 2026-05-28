package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DevShedLabs/devscan/internal/output"
	"github.com/DevShedLabs/devscan/internal/schema"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var locateCmd = &cobra.Command{
	Use:   "locate",
	Short: "Show filesystem paths for vulnerable or outdated packages",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts := scanOptsFromCmd(cmd)
		report, err := runFullScan(opts)
		if err != nil {
			return err
		}

		format := output.Format(viper.GetString("format"))
		if format == output.FormatJSON {
			return renderLocateJSON(report)
		}

		return renderLocateTable(report)
	},
}

type locateEntry struct {
	Name      string           `json:"name"`
	Version   string           `json:"version"`
	Ecosystem string           `json:"ecosystem"`
	Path      string           `json:"path"`
	Severity  schema.Severity  `json:"severity"`
	IDs       []string         `json:"ids"`
}

func buildLocateEntries(report *schema.Report) []locateEntry {
	// Index packages by name+ecosystem for path lookup.
	pathIndex := map[string]string{}
	for _, p := range report.Packages {
		key := p.Ecosystem + "|" + p.Name
		if p.Path != "" {
			pathIndex[key] = p.Path
		}
	}

	// Group vulns by package to get worst severity and all IDs.
	type group struct {
		version   string
		ecosystem string
		worst     schema.Severity
		ids       []string
	}
	order := []string{}
	groups := map[string]*group{}

	severityRank := map[schema.Severity]int{
		schema.SeverityCritical: 4,
		schema.SeverityHigh:     3,
		schema.SeverityMedium:   2,
		schema.SeverityLow:      1,
		schema.SeverityUnknown:  0,
	}

	for _, v := range report.Vulnerabilities {
		key := v.Ecosystem + "|" + v.Package
		if _, exists := groups[key]; !exists {
			order = append(order, key)
			groups[key] = &group{
				version:   v.InstalledVersion,
				ecosystem: v.Ecosystem,
				worst:     schema.SeverityUnknown,
			}
		}
		g := groups[key]
		g.ids = append(g.ids, v.ID)
		if severityRank[v.Severity] > severityRank[g.worst] {
			g.worst = v.Severity
		}
	}

	entries := make([]locateEntry, 0, len(order))
	for _, key := range order {
		g := groups[key]
		// key is "ecosystem|name"
		name := key[len(g.ecosystem)+1:]
		entries = append(entries, locateEntry{
			Name:      name,
			Version:   g.version,
			Ecosystem: g.ecosystem,
			Path:      pathIndex[key],
			Severity:  g.worst,
			IDs:       g.ids,
		})
	}
	return entries
}

func renderLocateTable(report *schema.Report) error {
	entries := buildLocateEntries(report)
	if len(entries) == 0 {
		fmt.Println("No vulnerable packages found.")
		return nil
	}

	for _, e := range entries {
		path := e.Path
		if path == "" {
			path = "(path unknown)"
		}
		fmt.Fprintf(os.Stdout, "%s %s@%s\n", severityBadge(e.Severity), e.Name, e.Version)
		fmt.Fprintf(os.Stdout, "  path:  %s\n", path)
		fmt.Fprintf(os.Stdout, "  vulns: %s\n\n", joinIDs(e.IDs))
	}
	return nil
}

func renderLocateJSON(report *schema.Report) error {
	entries := buildLocateEntries(report)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		VulnerablePackages []locateEntry `json:"vulnerable_packages"`
	}{entries})
}

func severityBadge(s schema.Severity) string {
	switch s {
	case schema.SeverityCritical:
		return "\033[31;1m[CRIT]\033[0m"
	case schema.SeverityHigh:
		return "\033[31m[HIGH]\033[0m"
	case schema.SeverityMedium:
		return "\033[33m[MED] \033[0m"
	case schema.SeverityLow:
		return "\033[90m[LOW] \033[0m"
	default:
		return "[?]   "
	}
}

func joinIDs(ids []string) string {
	result := ""
	for i, id := range ids {
		if i > 0 {
			result += ", "
		}
		result += id
	}
	return result
}

func init() {
	rootCmd.AddCommand(locateCmd)
}
