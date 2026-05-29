# devscan

A developer environment security and health scanner. Detects runtimes, inspects installed packages, and surfaces known vulnerabilities and outdated dependencies — across your global environment or a specific project.

Built with Go. Designed to be scriptable, CI-friendly, and extensible.

---

## Install

```bash
go install github.com/DevShedLabs/devscan@latest
```

Or build from source:

```bash
git clone https://github.com/DevShedLabs/devscan
cd devscan
go build -o devscan .
```

---

## Commands

| Command | Description |
|---|---|
| `devscan doctor` | Full scan: runtimes, packages, vulnerabilities, outdated deps |
| `devscan audit` | Vulnerabilities only |
| `devscan outdated` | Version drift only |
| `devscan list` | Inventory of detected runtimes and packages |
| `devscan locate` | Filesystem paths for every vulnerable package |
| `devscan scan` | Raw JSON scan output for piping |
| `devscan fix` | Suggested fix commands |
| `devscan report` | Export a full report as Markdown, HTML, or JSON |

---

## Usage

```bash
# Full health report
devscan doctor

# Audit for vulnerabilities, filter to high and above
devscan audit --severity high

# Show exactly where vulnerable packages are installed
devscan locate

# Scan a specific project
devscan doctor --path ./my-app

# Scan a project and all sub-projects up to 2 levels deep
devscan doctor --path ./my-app --depth 2

# Machine-readable output
devscan doctor --format json

# CI: exit non-zero if critical vulns found
devscan audit --severity critical
```

---

## Reports

Generate a shareable report in Markdown, HTML, or JSON:

```bash
# Markdown to stdout
devscan report --md

# HTML file
devscan report --html --output report.html

# JSON file
devscan report --json --output scan.json

# Scoped to a project
devscan report --html --output report.html --path ./my-app

# Traverse sub-projects
devscan report --html --output report.html --path ./my-app --depth 2
```

Reports include:
- System info: OS, version, chip, architecture
- Summary cards with severity counts and scan duration
- Runtime versions with outdated status
- Vulnerabilities grouped by severity, with OSV advisory links, fixed-in versions, and fix commands
- Filesystem paths for every vulnerable package installation
- Full package inventory

---

## Flags

```
--format string      Output format: table|json|compact (default "table")
--severity string    Filter by severity: critical|high|medium|low
--ecosystem string   Filter by ecosystem: npm|pypi|packagist|crates.io|go
--global             Scan global packages (default)
--project            Scan current project directory
--path string        Explicit project path to scan
--depth int          Traverse subdirectories up to this depth (0 = path only)
--no-color           Disable color output
--no-cache           Bypass cache and force a fresh advisory lookup
-o, --output string  Write report to file (report command only)
```

---

## Fix Commands

When a fix is available, devscan generates the exact command to run:

| Ecosystem | Example |
|---|---|
| npm | `npm install pkg@^1.2.3` |
| pypi | `pip install --upgrade pkg>=1.2.3` |
| packagist | `composer require vendor/pkg:^1.2.3` |
| crates.io | `cargo update -p pkg --precise 1.2.3` |
| go | `go get module@v1.2.3` |
| gem | `gem update pkg` |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean |
| `1` | General error |
| `2` | Vulnerabilities found |
| `3` | Critical vulnerabilities found |
| `4` | Outdated packages found |

Useful for CI pipelines:

```yaml
- name: Security scan
  run: devscan audit --severity high
```

---

## Cache

Network results are cached locally to keep scans fast.

| Data | TTL | Location (macOS) |
|---|---|---|
| Vulnerability advisories (OSV.dev) | 1 hour | `~/Library/Caches/devscan/` |
| Runtime latest versions | 7 days | `~/Library/Caches/devscan/versions/` |

On Linux: `~/.cache/devscan/` · On Windows: `%LocalAppData%\devscan\`

Force a fresh lookup at any time:

```bash
devscan doctor --no-cache
```

---

## Config File

Place `.devscan.json` in your project root or home directory:

```json
{
  "ignore": ["left-pad"],
  "severity_threshold": "medium",
  "ecosystems": ["npm", "pypi"],
  "auto_fix": false
}
```

---

## Supported Ecosystems

| Ecosystem | Runtime | Packages | Vulnerabilities |
|---|---|---|---|
| Node.js / npm | ✓ | ✓ | ✓ via OSV.dev |
| Bun | ✓ | ✓ (via npm) | ✓ via OSV.dev |
| Python / pip | ✓ | ✓ | ✓ via OSV.dev |
| PHP / Composer | ✓ | ✓ | ✓ via OSV.dev |
| Rust / Cargo | ✓ | ✓ | ✓ via OSV.dev |
| Go modules | ✓ | ✓ (project) | ✓ via OSV.dev |
| Git | ✓ | — | — |

Vulnerability data is sourced from [OSV.dev](https://osv.dev) — an open, community-driven vulnerability database covering npm, PyPI, Go, crates.io, Packagist, RubyGems, and more.

Large scans (1000+ packages) are automatically chunked into batches to stay within OSV API limits.

---

## Architecture

```
devscan/
  cmd/                  # CLI commands (Cobra)
  internal/
    detectors/          # Runtime detection (node, bun, python, git, php, rust, go)
    inspectors/         # Package inspection (npm, pip, composer, cargo, gomod)
    advisory/           # Vulnerability lookups (OSV.dev) with 1hr cache
    versions/           # Runtime latest-version checks with 7-day cache
    sysinfo/            # OS, chip, and architecture detection
    traverse/           # Sub-project discovery by manifest files
    output/             # Terminal renderers (table, JSON, compact)
    report/             # Export renderers (Markdown, HTML, JSON)
    schema/             # Shared types
```

The JSON output schema is the central contract. The CLI, and future TUI and GUI layers, are all thin wrappers on top of it.

---

## Roadmap

- [x] Runtime latest-version checks — Go, Node, Bun, Python, PHP, Rust, Git
- [x] Fix commands for all supported ecosystems
- [x] Sub-project traversal with `--depth`
- [x] Filesystem paths for vulnerable packages
- [x] System info in reports (OS, chip, arch)
- [x] HTML and Markdown report export
- [ ] Ruby / gem support
- [ ] Homebrew package inspection
- [ ] Baseline diff (`--compare baseline.json`)
- [ ] CI summary output (GitHub Actions annotations)
- [ ] `--ignore` flag to suppress known/accepted advisories

---

## License

MIT
