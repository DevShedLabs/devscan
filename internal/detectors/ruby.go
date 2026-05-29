package detectors

import (
	"strings"

	"github.com/DevShedLabs/devscan/internal/schema"
)

type RubyDetector struct{}

func (d *RubyDetector) Name() string { return "ruby" }

func (d *RubyDetector) Detect() (*schema.Runtime, error) {
	ver, err := execVersion("ruby", "--version")
	if err != nil {
		return nil, err
	}
	// "ruby 3.3.0 (2023-12-25 revision ...) [arm64-darwin23]" → "3.3.0"
	fields := strings.Fields(ver)
	if len(fields) < 2 {
		return nil, nil
	}
	return &schema.Runtime{
		Name:    "ruby",
		Version: fields[1],
		Path:    which("ruby"),
		Status:  schema.StatusUnknown,
	}, nil
}
