package report

import (
	"fmt"
	"html"
	"io"
	"time"

	"github.com/DevShedLabs/devscan/internal/schema"
)

func renderHTML(w io.Writer, r *schema.Report) error {
	p := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	p(`<!DOCTYPE html>`)
	p(`<html lang="en">`)
	p(`<head>`)
	p(`<meta charset="UTF-8">`)
	p(`<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	p(`<title>DevScan Report — %s</title>`, r.Meta.Timestamp.Format("2006-01-02"))
	p(`<style>%s</style>`, htmlCSS())
	p(`</head>`)
	p(`<body>`)

	// Header
	p(`<header>`)
	p(`  <div class="logo">DevScan</div>`)
	p(`  <div class="meta">`)
	p(`    <span>%s</span>`, r.Meta.Timestamp.Format("2 Jan 2006, 15:04 MST"))
	p(`    <span>Target: <strong>%s</strong></span>`, r.Meta.Target)
	if r.Meta.Path != "" {
		p(`    <span>Path: <code>%s</code></span>`, html.EscapeString(r.Meta.Path))
	}
	p(`    <span>Scan time: %s</span>`, formatDuration(r.Meta.DurationMs))
	if r.Meta.OS != "" {
		osStr := r.Meta.OS
		if r.Meta.OSVersion != "" {
			osStr += " " + r.Meta.OSVersion
		}
		p(`    <span>OS: <strong>%s</strong></span>`, html.EscapeString(osStr))
	}
	if r.Meta.Chip != "" {
		p(`    <span>Chip: <strong>%s</strong></span>`, html.EscapeString(r.Meta.Chip))
	}
	if r.Meta.Arch != "" {
		p(`    <span>Arch: <strong>%s</strong></span>`, html.EscapeString(r.Meta.Arch))
	}
	p(`  </div>`)
	p(`</header>`)

	// Summary cards
	s := r.Summary
	p(`<section class="summary">`)
	fmt.Fprintf(w, "  <div class=\"card\"><div class=\"card-value\">%d</div><div class=\"card-label\">Runtimes</div></div>\n", s.Runtimes)
	fmt.Fprintf(w, "  <div class=\"card\"><div class=\"card-value\">%d</div><div class=\"card-label\">Packages Scanned</div></div>\n", s.Packages)
	fmt.Fprintf(w, "  <div class=\"card critical\"><div class=\"card-value\">%d</div><div class=\"card-label\">Critical</div></div>\n", s.Vulnerabilities.Critical)
	fmt.Fprintf(w, "  <div class=\"card high\"><div class=\"card-value\">%d</div><div class=\"card-label\">High</div></div>\n", s.Vulnerabilities.High)
	fmt.Fprintf(w, "  <div class=\"card medium\"><div class=\"card-value\">%d</div><div class=\"card-label\">Medium</div></div>\n", s.Vulnerabilities.Medium)
	fmt.Fprintf(w, "  <div class=\"card low\"><div class=\"card-value\">%d</div><div class=\"card-label\">Low</div></div>\n", s.Vulnerabilities.Low)
	// Outdated has always been 0 so no reason to show it.
	//fmt.Fprintf(w, "  <div class=\"card\"><div class=\"card-value\">%d</div><div class=\"card-label\">Outdated</div></div>\n", s.Outdated)
	fmt.Fprintf(w, "  <div class=\"card\"><div class=\"card-value\">%s</div><div class=\"card-label\">Scan Duration</div></div>\n", formatDuration(r.Meta.DurationMs))
	p(`</section>`)

	// Runtimes
	p(`<section>`)
	p(`  <h2>Runtimes</h2>`)
	if len(r.Runtimes) == 0 {
		p(`  <p class="empty">No runtimes detected.</p>`)
	} else {
		p(`  <table>`)
		p(`    <thead><tr><th>Runtime</th><th>Version</th><th>Status</th><th>Path</th></tr></thead>`)
		p(`    <tbody>`)
		for _, rt := range r.Runtimes {
			status := string(rt.Status)
			statusClass := "status-" + string(rt.Status)
			if rt.Latest != "" && rt.Status == schema.StatusOutdated {
				status = fmt.Sprintf("outdated → %s", rt.Latest)
			}
			p(`      <tr><td>%s</td><td><code>%s</code></td><td class="%s">%s</td><td><code>%s</code></td></tr>`,
				html.EscapeString(rt.Name),
				html.EscapeString(rt.Version),
				statusClass,
				html.EscapeString(status),
				html.EscapeString(rt.Path),
			)
		}
		p(`    </tbody>`)
		p(`  </table>`)
	}
	p(`</section>`)

	// Vulnerabilities
	vs := r.Summary.Vulnerabilities
	vulnTotal := vs.Critical + vs.High + vs.Medium + vs.Low
	p(`<section>`)
	p(`  <h2 class="section-heading">Vulnerabilities<span class="heading-count">%d</span></h2>`, vulnTotal)
	if len(r.Vulnerabilities) == 0 {
		p(`  <p class="empty">No vulnerabilities found.</p>`)
	} else {
		groups := groupBySeverity(r.Vulnerabilities)
		for _, sev := range []schema.Severity{
			schema.SeverityCritical,
			schema.SeverityHigh,
			schema.SeverityMedium,
			schema.SeverityLow,
			schema.SeverityUnknown,
		} {
			pkgs, ok := groups[sev]
			if !ok || len(pkgs) == 0 {
				continue
			}
			p(`  <h3 class="sev-%s">%s</h3>`, string(sev), severityBadge(sev))
			for _, pkg := range pkgs {
				p(`  <div class="vuln-block">`)
				p(`    <div class="vuln-header">`)
				p(`      <span class="pkg-name"><code>%s@%s</code></span>`, html.EscapeString(pkg.name), html.EscapeString(pkg.version))
				p(`      <span class="ecosystem">%s</span>`, html.EscapeString(pkg.ecosystem))
				p(`    </div>`)
				for _, path := range pkg.paths {
					p(`    <div class="vuln-path">📂 <code>%s</code></div>`, html.EscapeString(path))
				}
				hasFixed := anyFixedIn(pkg.vulns)
				hasFix := anyFix(pkg.vulns)
				p(`    <table>`)
				fmt.Fprint(w, "      <thead><tr><th>Advisory</th><th>Title</th>")
				if hasFixed {
					fmt.Fprint(w, "<th>Fixed In</th>")
				}
				if hasFix {
					fmt.Fprint(w, "<th>Fix</th>")
				}
				fmt.Fprintln(w, "</tr></thead>")
				p(`      <tbody>`)
				for _, v := range pkg.vulns {
					title := v.Title
					if title == "" {
						title = v.ID
					}
					p(`        <tr>`)
					p(`          <td><a href="https://osv.dev/vulnerability/%s" target="_blank">%s</a></td>`,
						html.EscapeString(v.ID), html.EscapeString(v.ID))
					p(`          <td>%s</td>`, html.EscapeString(title))
					if hasFixed {
						fixedIn := v.FixedIn
						if fixedIn == "" {
							fixedIn = "—"
						}
						p(`          <td>%s</td>`, html.EscapeString(fixedIn))
					}
					if hasFix {
						fix := "—"
						if v.Fix != nil && v.Fix.Command != "" {
							fix = fmt.Sprintf("<code>%s</code>", html.EscapeString(v.Fix.Command))
						}
						p(`          <td>%s</td>`, fix)
					}
					p(`        </tr>`)
				}
				p(`      </tbody>`)
				p(`    </table>`)
				p(`  </div>`)
			}
		}
	}
	p(`</section>`)

	// Packages
	p(`<section>`)
	p(`  <h2>Installed Packages</h2>`)
	p(`  <table>`)
	p(`    <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>Path</th></tr></thead>`)
	p(`    <tbody>`)
	for _, pkg := range r.Packages {
		path := pkg.Path
		if path == "" {
			path = "—"
		}
		p(`      <tr><td>%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>`,
			html.EscapeString(pkg.Name),
			html.EscapeString(pkg.Version),
			html.EscapeString(pkg.Ecosystem),
			html.EscapeString(path),
		)
	}
	p(`    </tbody>`)
	p(`  </table>`)
	p(`</section>`)

	p(`<footer>`)
	p(`  <p>Generated by <a href="https://github.com/DevShedLabs/devscan">devscan</a> · %s</p>`, time.Now().Format("2006"))
	p(`</footer>`)
	p(`</body>`)
	p(`</html>`)

	return nil
}

func htmlCSS() string {
	return `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  color: #1a1a1a;
  background: #f5f5f5;
}

header {
  background: #111;
  color: #fff;
  padding: 20px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}

.logo {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.5px;
  color: #fff;
}

.meta {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
  font-size: 13px;
  color: #aaa;
}

.meta strong { color: #fff; }
.meta code { color: #93c5fd; background: rgba(255,255,255,0.1); }

section {
  max-width: 1100px;
  margin: 32px auto;
  padding: 0 24px;
}

h2 {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e5e7eb;
  color: #111;
}

h2.section-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.heading-count {
  font-size: 13px;
  font-weight: 600;
  color: #6b7280;
  background: #e5e7eb;
  padding: 2px 10px;
  border-radius: 99px;
}

h3 {
  font-size: 15px;
  font-weight: 600;
  margin: 24px 0 12px;
}

.sev-critical { color: #dc2626; }
.sev-high     { color: #ea580c; }
.sev-medium   { color: #ca8a04; }
.sev-low      { color: #16a34a; }
.sev-unknown  { color: #6b7280; }

.summary {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  max-width: 1100px;
  margin: 24px auto 0;
  padding: 0 24px;
}

.card {
  background: #fff;
  border-radius: 8px;
  padding: 16px 20px;
  min-width: 110px;
  text-align: center;
  border: 1px solid #e5e7eb;
  flex: 1;
}

.card-value { font-size: 28px; font-weight: 700; color: #111; }
.card-label { font-size: 12px; color: #6b7280; margin-top: 2px; }

.card.critical .card-value { color: #dc2626; }
.card.high     .card-value { color: #ea580c; }
.card.medium   .card-value { color: #ca8a04; }
.card.low      .card-value { color: #16a34a; }

table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #e5e7eb;
  font-size: 13px;
}

thead { background: #f9fafb; }
th { padding: 10px 14px; text-align: left; font-weight: 600; color: #374151; border-bottom: 1px solid #e5e7eb; }
td { padding: 9px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafafa; }

code {
  font-family: "SF Mono", "Fira Code", monospace;
  font-size: 12px;
  background: #f3f4f6;
  padding: 1px 5px;
  border-radius: 3px;
  color: #374151;
}

a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }

.vuln-block {
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  margin-bottom: 16px;
  overflow: hidden;
}

.vuln-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
}

.pkg-name code { font-size: 13px; font-weight: 600; background: none; padding: 0; }
.ecosystem { font-size: 11px; color: #6b7280; background: #e5e7eb; padding: 2px 8px; border-radius: 99px; }

.vuln-path {
  padding: 8px 16px;
  font-size: 12px;
  color: #6b7280;
  border-bottom: 1px solid #f3f4f6;
  background: #fafafa;
}

.status-ok      { color: #16a34a; }
.status-outdated { color: #ca8a04; }
.status-eol     { color: #dc2626; }
.status-unknown { color: #6b7280; }

.empty { color: #6b7280; font-style: italic; }

footer {
  text-align: center;
  padding: 24px;
  color: #9ca3af;
  font-size: 12px;
  border-top: 1px solid #e5e7eb;
  margin-top: 48px;
}
`
}
