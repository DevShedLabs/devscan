package inspectors

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type GemInspector struct{}

func (i *GemInspector) Name() string      { return "gem" }
func (i *GemInspector) Ecosystem() string { return "gem" }

func (i *GemInspector) Inspect(scope, path string) ([]schema.Package, error) {
	if _, err := exec.LookPath("gem"); err != nil {
		return nil, nil
	}

	args := []string{"list", "--no-verbose"}
	if scope == "global" {
		args = append(args, "--no-user-install")
	}

	cmd := exec.Command("gem", args...)
	if scope == "project" && path != "" {
		cmd.Dir = path
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}

	var packages []schema.Package
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name, version, ok := parseGemLine(line)
		if !ok {
			continue
		}
		packages = append(packages, schema.Package{
			Name:      name,
			Version:   version,
			Ecosystem: "gem",
			Scope:     scope,
			Direct:    true,
		})
	}
	return packages, nil
}

// parseGemLine parses "bundler (2.5.6)" or "rails (7.1.0, 6.1.7)" → name, latest version.
func parseGemLine(line string) (name, version string, ok bool) {
	open := strings.Index(line, " (")
	close := strings.LastIndex(line, ")")
	if open < 0 || close < 0 || close <= open {
		return "", "", false
	}
	name = strings.TrimSpace(line[:open])
	versions := strings.Split(line[open+2:close], ", ")
	if len(versions) == 0 {
		return "", "", false
	}
	// Skip default/bundled gems — not independently versioned.
	v := strings.TrimSpace(versions[0])
	if strings.Contains(v, "default") {
		return "", "", false
	}
	return name, v, true
}
