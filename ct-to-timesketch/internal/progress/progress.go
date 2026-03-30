package progress

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func Header(text string) {
	line := strings.Repeat("=", 60)
	fmt.Fprintf(os.Stderr, "\n%s\n%s\n%s\n\n", line, text, line)
}

func Info(text string) {
	fmt.Fprintf(os.Stderr, "  %s\n", text)
}

func Success(text string) {
	fmt.Fprintf(os.Stderr, "✓ %s\n", text)
}

func Warning(text string) {
	fmt.Fprintf(os.Stderr, "⚠ %s\n", text)
}

func Errorf(text string) {
	fmt.Fprintf(os.Stderr, "✗ %s\n", text)
}

// StepTimer tracks elapsed time for a named processing step.
type StepTimer struct {
	Label string
	Start time.Time
}

func NewStepTimer(label string) *StepTimer {
	return &StepTimer{Label: label, Start: time.Now()}
}

func (t *StepTimer) Done() {
	Info(fmt.Sprintf("%s completed in %.1fs", t.Label, time.Since(t.Start).Seconds()))
}

// ProgressLine overwrites the current stderr line with a progress update.
func ProgressLine(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\r  "+format, args...)
}

// ProgressDone finishes a progress line with a newline.
func ProgressDone() {
	fmt.Fprintln(os.Stderr)
}

// PrintSummary outputs the event type stats table.
func PrintSummary(stats map[string]int, totalEvents int, elapsed time.Duration) {
	Header("CONVERSION SUMMARY")

	type kv struct {
		key   string
		count int
	}
	var sorted []kv
	for k, v := range stats {
		sorted = append(sorted, kv{k, v})
	}
	// Simple descending sort by count
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, kv := range sorted {
		fmt.Fprintf(os.Stderr, "  %-30s %6d\n", kv.key, kv.count)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 40))
	fmt.Fprintf(os.Stderr, "  %-30s %6d\n", "TOTAL EVENTS", totalEvents)
	fmt.Fprintf(os.Stderr, "\n  Total time: %.1fs\n", elapsed.Seconds())
}
