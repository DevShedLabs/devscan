package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/DevShedLabs/devscan/internal/schema"
)

const (
	osvBatchURL   = "https://api.osv.dev/v1/querybatch"
	osvVulnURL    = "https://api.osv.dev/v1/vulns/"
	osvBatchLimit = 500
)

type Client struct {
	http    *http.Client
	baseURL string
	noCache bool
}

func NewClient(noCache bool) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: osvBatchURL,
		noCache: noCache,
	}
}

// osvEcosystem maps our ecosystem names to OSV ecosystem names.
var osvEcosystem = map[string]string{
	"npm":        "npm",
	"pypi":       "PyPI",
	"gem":        "RubyGems",
	"go":         "Go",
	"crates.io":  "crates.io",
	"packagist":  "Packagist",
	"homebrew":   "Bitnami",
}

type osvQuery struct {
	Queries []osvPackageQuery `json:"queries"`
}

type osvPackageQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
	Refs     []osvRef      `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed string `json:"fixed"`
}

type osvRef struct {
	URL string `json:"url"`
}

// QueryPackages queries OSV for vulnerabilities across a set of packages.
func (c *Client) QueryPackages(packages []schema.Package) ([]schema.Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Build queries and keep a parallel slice of the packages that were queried,
	// so batch.Results[i] always maps to queried[i] regardless of skipped ecosystems.
	queries := make([]osvPackageQuery, 0, len(packages))
	queried := make([]schema.Package, 0, len(packages))
	for _, p := range packages {
		eco, ok := osvEcosystem[p.Ecosystem]
		if !ok {
			continue
		}
		queries = append(queries, osvPackageQuery{
			Package: osvPackage{Name: p.Name, Ecosystem: eco},
			Version: p.Version,
		})
		queried = append(queried, p)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	// Sort by a stable key so the cache hash is order-independent.
	// queries and queried are parallel slices so we sort them together.
	type pair struct {
		q osvPackageQuery
		p schema.Package
	}
	pairs := make([]pair, len(queries))
	for i := range queries {
		pairs[i] = pair{queries[i], queried[i]}
	}
	sort.Slice(pairs, func(i, j int) bool {
		ki := pairs[i].q.Package.Ecosystem + "|" + pairs[i].q.Package.Name + "|" + pairs[i].q.Version
		kj := pairs[j].q.Package.Ecosystem + "|" + pairs[j].q.Package.Name + "|" + pairs[j].q.Version
		return ki < kj
	})
	for i := range pairs {
		queries[i] = pairs[i].q
		queried[i] = pairs[i].p
	}

	key := cacheKey(queries)
	if !c.noCache {
		if cached, ok := c.loadCache(key); ok {
			return cached, nil
		}
	}

	seen := map[string]bool{}
	var vulns []schema.Vulnerability

	// OSV batch API rejects requests above ~1000 packages; chunk to stay safe.
	for start := 0; start < len(queries); start += osvBatchLimit {
		end := start + osvBatchLimit
		if end > len(queries) {
			end = len(queries)
		}
		chunkQ := queries[start:end]
		chunkP := queried[start:end]

		chunkVulns, err := c.queryChunk(chunkQ, chunkP, seen)
		if err != nil {
			return nil, err
		}
		vulns = append(vulns, chunkVulns...)
	}

	// Enrich each vuln with full details (summary + severity) from /v1/vulns/{id}.
	// The batch endpoint omits these fields; the detail endpoint returns them.
	c.enrichVulns(vulns)

	if !c.noCache {
		c.saveCache(key, vulns)
	}

	return vulns, nil
}

// queryChunk sends one OSV batch request for up to osvBatchLimit packages.
func (c *Client) queryChunk(queries []osvPackageQuery, queried []schema.Package, seen map[string]bool) ([]schema.Vulnerability, error) {
	body, err := json.Marshal(osvQuery{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("advisory: marshal: %w", err)
	}

	resp, err := c.http.Post(c.baseURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("advisory: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("advisory: OSV returned %d", resp.StatusCode)
	}

	var batch osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return nil, fmt.Errorf("advisory: decode: %w", err)
	}

	var vulns []schema.Vulnerability
	for i, result := range batch.Results {
		if i >= len(queried) {
			break
		}
		pkg := queried[i]
		for _, v := range result.Vulns {
			dedupeKey := v.ID + "|" + pkg.Name + "|" + pkg.Version
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			vuln := schema.Vulnerability{
				ID:               v.ID,
				Package:          pkg.Name,
				Ecosystem:        pkg.Ecosystem,
				InstalledVersion: pkg.Version,
				Title:            v.Summary,
				Description:      v.Details,
				Severity:         parseSeverity(v.Severity),
			}

			for _, ref := range v.Refs {
				vuln.References = append(vuln.References, ref.URL)
			}

			if fixed := extractFixed(v.Affected); fixed != "" {
				vuln.FixedIn = fixed
				vuln.Fix = &schema.Fix{
					Type:    "upgrade",
					Command: upgradeCommand(pkg, fixed),
				}
			}

			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

// enrichVulns fetches full vuln details concurrently for any entry missing a title or severity.
func (c *Client) enrichVulns(vulns []schema.Vulnerability) {
	type work struct {
		idx int
		id  string
	}

	jobs := make([]work, 0, len(vulns))
	for i, v := range vulns {
		if v.Title == "" || v.Severity == schema.SeverityUnknown {
			jobs = append(jobs, work{i, v.ID})
		}
	}
	if len(jobs) == 0 {
		return
	}

	type result struct {
		idx  int
		data *osvVuln
	}

	ch := make(chan result, len(jobs))
	for _, j := range jobs {
		j := j
		go func() {
			resp, err := c.http.Get(osvVulnURL + j.id)
			if err != nil || resp.StatusCode != http.StatusOK {
				ch <- result{j.idx, nil}
				return
			}
			defer resp.Body.Close()
			var v osvVuln
			if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
				ch <- result{j.idx, nil}
				return
			}
			ch <- result{j.idx, &v}
		}()
	}

	for range jobs {
		r := <-ch
		if r.data == nil {
			continue
		}
		if vulns[r.idx].Title == "" {
			vulns[r.idx].Title = r.data.Summary
		}
		if vulns[r.idx].Severity == schema.SeverityUnknown {
			vulns[r.idx].Severity = parseSeverity(r.data.Severity)
		}
		if vulns[r.idx].FixedIn == "" {
			if fixed := extractFixed(r.data.Affected); fixed != "" {
				vulns[r.idx].FixedIn = fixed
				// Reconstruct the package from what we already stored on the vuln.
				pkg := schema.Package{
					Name:      vulns[r.idx].Package,
					Ecosystem: vulns[r.idx].Ecosystem,
				}
				vulns[r.idx].Fix = &schema.Fix{
					Type:    "upgrade",
					Command: upgradeCommand(pkg, fixed),
				}
			}
		}
	}
}

func parseSeverity(severities []osvSeverity) schema.Severity {
	// Prefer CVSS_V3, fall back to CVSS_V4, then CVSS_V2.
	order := []string{"CVSS_V3", "CVSS_V4", "CVSS_V2"}
	byType := map[string]string{}
	for _, s := range severities {
		byType[s.Type] = s.Score
	}
	for _, t := range order {
		if score, ok := byType[t]; ok {
			return cvssVectorToSeverity(score)
		}
	}
	return schema.SeverityUnknown
}

// cvssVectorToSeverity derives a severity bucket from a CVSS vector string.
// Rather than re-implementing the full CVSS calculator we derive the numeric
// base score from the Impact and Exploitability sub-scores encoded in the
// vector, which is accurate for the NVD severity bands:
//
//	0.0        → none
//	0.1 – 3.9  → low
//	4.0 – 6.9  → medium
//	7.0 – 8.9  → high
//	9.0 – 10.0 → critical
//
// For simplicity we map the confidentiality/integrity/availability impact
// components (N/L/H) and the attack vector to a coarse score that matches
// the NVD bands in practice.
func cvssVectorToSeverity(vector string) schema.Severity {
	// Extract the numeric base score from the vector by scoring each metric.
	// CVSS:3.x/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	// Impact sub-score weights (simplified NVD mapping).
	impactWeight := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
	c := impactWeight[metrics["C"]]
	i := impactWeight[metrics["I"]]
	a := impactWeight[metrics["A"]]
	iss := 1 - (1-c)*(1-i)*(1-a)

	// Scope affects impact calculation.
	var impact float64
	if metrics["S"] == "C" {
		impact = 7.52*(iss-0.029) - 3.25*pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	if impact <= 0 {
		return schema.SeverityLow
	}

	// Exploitability sub-score.
	avW := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acW := map[string]float64{"L": 0.77, "H": 0.44}
	prW := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if metrics["S"] == "C" {
		prW = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	uiW := map[string]float64{"N": 0.85, "R": 0.62}

	exploitability := 8.22 *
		avW[metrics["AV"]] *
		acW[metrics["AC"]] *
		prW[metrics["PR"]] *
		uiW[metrics["UI"]]

	base := impact + exploitability
	if base > 10 {
		base = 10
	}

	switch {
	case base >= 9.0:
		return schema.SeverityCritical
	case base >= 7.0:
		return schema.SeverityHigh
	case base >= 4.0:
		return schema.SeverityMedium
	case base > 0:
		return schema.SeverityLow
	default:
		return schema.SeverityUnknown
	}
}

func pow(x, y float64) float64 {
	result := 1.0
	for i := 0; i < int(y); i++ {
		result *= x
	}
	return result
}

func extractFixed(affected []osvAffected) string {
	for _, a := range affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func upgradeCommand(pkg schema.Package, fixedIn string) string {
	switch pkg.Ecosystem {
	case "npm":
		return fmt.Sprintf("npm install %s@^%s", pkg.Name, fixedIn)
	case "pypi":
		return fmt.Sprintf("pip install --upgrade %s>=%s", pkg.Name, fixedIn)
	case "packagist":
		return fmt.Sprintf("composer require %s:^%s", pkg.Name, fixedIn)
	case "crates.io":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg.Name, fixedIn)
	case "go":
		return fmt.Sprintf("go get %s@v%s", pkg.Name, fixedIn)
	case "gem":
		return fmt.Sprintf("gem update %s", pkg.Name)
	default:
		return ""
	}
}
