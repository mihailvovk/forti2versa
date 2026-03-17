package forti2versa

import (
	"fmt"
	"strings"
)

// ConversionReport tracks [OK], [SKIP], [WARN] entries.
type ConversionReport struct {
	Converted []string
	Skipped   []string
	Warnings  []string
}

func NewConversionReport() *ConversionReport {
	return &ConversionReport{}
}

func (r *ConversionReport) AddConverted(msg string) {
	r.Converted = append(r.Converted, msg)
}

func (r *ConversionReport) AddSkipped(msg string) {
	r.Skipped = append(r.Skipped, msg)
}

func (r *ConversionReport) AddWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

func (r *ConversionReport) Render() string {
	var b strings.Builder
	b.WriteString(strings.Repeat("=", 72))
	b.WriteByte('\n')
	b.WriteString("CONVERSION REPORT\n")
	b.WriteString(strings.Repeat("=", 72))
	b.WriteByte('\n')
	b.WriteByte('\n')
	fmt.Fprintf(&b, "Converted: %d\n", len(r.Converted))
	fmt.Fprintf(&b, "Skipped:   %d\n", len(r.Skipped))
	fmt.Fprintf(&b, "Warnings:  %d\n", len(r.Warnings))
	b.WriteByte('\n')
	if len(r.Converted) > 0 {
		b.WriteString("--- Converted Objects ---\n")
		for _, c := range r.Converted {
			fmt.Fprintf(&b, "  [OK] %s\n", c)
		}
		b.WriteByte('\n')
	}
	if len(r.Skipped) > 0 {
		b.WriteString("--- Skipped Objects ---\n")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "  [SKIP] %s\n", s)
		}
		b.WriteByte('\n')
	}
	if len(r.Warnings) > 0 {
		b.WriteString("--- Warnings ---\n")
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  [WARN] %s\n", w)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
