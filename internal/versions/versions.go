package versions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/DevShedLabs/devscan/internal/schema"
)

var client = &http.Client{Timeout: 10 * time.Second}

// Enrich fetches the latest known version for each runtime and sets Latest + Status.
// Runs concurrently; unknown runtimes are left unchanged.
func Enrich(runtimes []schema.Runtime) {
	type result struct {
		idx    int
		latest string
	}

	ch := make(chan result, len(runtimes))

	for i, rt := range runtimes {
		i, rt := i, rt
		go func() {
			latest, err := fetchLatest(rt.Name)
			if err != nil || latest == "" {
				ch <- result{i, ""}
				return
			}
			ch <- result{i, latest}
		}()
	}

	for range runtimes {
		r := <-ch
		if r.latest == "" {
			continue
		}
		runtimes[r.idx].Latest = r.latest
		runtimes[r.idx].Status = compareVersions(runtimes[r.idx].Version, r.latest)
	}
}

func fetchLatest(runtime string) (string, error) {
	if v, ok := loadCached(runtime); ok {
		return v, nil
	}

	var (
		v   string
		err error
	)
	switch runtime {
	case "go":
		v, err = fetchGo()
	case "node":
		v, err = fetchNode()
	case "python":
		v, err = fetchPython()
	default:
		return "", nil
	}

	if err == nil && v != "" {
		saveCached(runtime, v)
	}
	return v, err
}

func fetchGo() (string, error) {
	resp, err := client.Get("https://go.dev/dl/?mode=json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var releases []struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}
	for _, r := range releases {
		if r.Stable {
			// "go1.26.3" → "1.26.3"
			return strings.TrimPrefix(r.Version, "go"), nil
		}
	}
	return "", fmt.Errorf("no stable go release found")
}

func fetchNode() (string, error) {
	resp, err := client.Get("https://nodejs.org/dist/index.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var releases []struct {
		Version string `json:"version"`
		LTS     any    `json:"lts"` // false or a string like "Jod"
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}
	for _, r := range releases {
		// lts is false when not LTS, or a string codename when LTS
		if _, isStr := r.LTS.(string); isStr {
			return strings.TrimPrefix(r.Version, "v"), nil
		}
	}
	return "", fmt.Errorf("no LTS node release found")
}

func fetchPython() (string, error) {
	resp, err := client.Get("https://endoflife.date/api/python.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var releases []struct {
		Latest string `json:"latest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}
	if len(releases) > 0 {
		return releases[0].Latest, nil
	}
	return "", fmt.Errorf("no python release found")
}

// compareVersions returns ok/outdated by comparing semver-like strings.
// Handles Go's "1.23.4" and Node's "24.2.0" style versions.
func compareVersions(installed, latest string) schema.Status {
	// Strip any metadata Go appends like " (Apple Git-154)"
	installed = strings.Fields(installed)[0]

	iv := parseVer(installed)
	lv := parseVer(latest)

	if iv[0] < lv[0] || (iv[0] == lv[0] && iv[1] < lv[1]) || (iv[0] == lv[0] && iv[1] == lv[1] && iv[2] < lv[2]) {
		return schema.StatusOutdated
	}
	return schema.StatusOK
}

func parseVer(v string) [3]int {
	// Strip leading 'v' or 'go'
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "go")
	// Take only the numeric portion
	v = strings.Split(v, "-")[0]
	v = strings.Split(v, "+")[0]

	var a, b, c int
	parts := strings.Split(v, ".")
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &a)
	}
	if len(parts) >= 2 {
		fmt.Sscanf(parts[1], "%d", &b)
	}
	if len(parts) >= 3 {
		fmt.Sscanf(parts[2], "%d", &c)
	}
	return [3]int{a, b, c}
}
