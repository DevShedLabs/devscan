package detectors

import (
	"os/exec"
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

// Detector detects a single runtime on the system.
type Detector interface {
	Name() string
	Detect() (*schema.Runtime, error)
}

// RunAll runs all registered detectors concurrently and returns results.
func RunAll(detectors []Detector) []schema.Runtime {
	type result struct {
		runtime *schema.Runtime
		err     error
	}

	ch := make(chan result, len(detectors))

	for _, d := range detectors {
		d := d
		go func() {
			r, err := d.Detect()
			ch <- result{r, err}
		}()
	}

	var runtimes []schema.Runtime
	for range detectors {
		res := <-ch
		if res.err == nil && res.runtime != nil {
			runtimes = append(runtimes, *res.runtime)
		}
	}
	return runtimes
}

// All returns the default set of detectors.
func All() []Detector {
	return []Detector{
		&NodeDetector{},
		&BunDetector{},
		&PythonDetector{},
		&RubyDetector{},
		&GitDetector{},
		&PHPDetector{},
		&RustDetector{},
		&GoDetector{},
	}
}

// execVersion runs a binary with a version flag and returns the trimmed output.
func execVersion(binary string, args ...string) (string, error) {
	out, err := exec.Command(binary, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// which returns the full path to a binary.
func which(binary string) string {
	path, err := exec.LookPath(binary)
	if err != nil {
		return ""
	}
	return path
}
