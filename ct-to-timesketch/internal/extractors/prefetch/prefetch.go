package prefetch

import (
	"bytes"
	"fmt"
	"strconv"

	goprefetch "www.velocidex.com/golang/go-prefetch"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() {
	extractors.Register(&Extractor{})
}

type Extractor struct{}

func (e *Extractor) Name() string        { return "prefetch" }
func (e *Extractor) Description() string { return "Windows Prefetch files (.pf) - program execution" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	pfFiles, err := idx.GetCollectedFiles(`\.pf$`, "")
	if err != nil {
		return 0, fmt.Errorf("get prefetch files: %w", err)
	}
	if len(pfFiles) == 0 {
		progress.Info("No Prefetch files with collected content found")
		return 0, nil
	}

	progress.Info(fmt.Sprintf("Processing %d Prefetch files with pure-Go parser", len(pfFiles)))
	totalEvents := 0

	for i, pf := range pfFiles {
		progress.ProgressLine("Prefetch [%d/%d] %s", i+1, len(pfFiles), pf.Filename)

		decoded, err := extractors.GetFileContent(pf)
		if err != nil || len(decoded) == 0 {
			continue
		}

		count := e.parsePrefetchFile(decoded, pf.Filename, pf.Path, conv)
		totalEvents += count
	}

	progress.ProgressDone()
	progress.Info(fmt.Sprintf("Prefetch: %d events extracted", totalEvents))
	return totalEvents, nil
}

func (e *Extractor) parsePrefetchFile(data []byte, filename, path string, conv *converter.Converter) int {
	reader := bytes.NewReader(data)
	pfInfo, err := goprefetch.LoadPrefetch(reader)
	if err != nil {
		return 0
	}

	events := 0
	exeName := pfInfo.Executable
	runCount := pfInfo.RunCount

	for _, ts := range pfInfo.LastRunTimes {
		if ts.IsZero() || ts.Year() < 1970 || ts.Year() > 2100 {
			continue
		}
		tsISO := ts.UTC().Format("2006-01-02T15:04:05.000Z")

		msg := "Program executed: " + exeName
		if runCount > 0 {
			msg += " (run count: " + strconv.FormatUint(uint64(runCount), 10) + ")"
		}

		if conv.AddEvent(tsISO, "Prefetch Execution Time", msg,
			"prefetch_execution", "CT-Prefetch",
			"CyberTriage TSK - Prefetch",
			"windows:prefetch:execution",
			map[string]interface{}{
				"executable":    exeName,
				"prefetch_file": filename,
				"prefetch_path": path,
				"run_count":     strconv.FormatUint(uint64(runCount), 10),
				"hash":          pfInfo.Hash,
			}) {
			events++
		}
	}

	return events
}
