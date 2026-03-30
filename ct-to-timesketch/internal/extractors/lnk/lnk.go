package lnk

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	golnk "github.com/parsiya/golnk"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() {
	extractors.Register(&Extractor{})
}

type Extractor struct{}

func (e *Extractor) Name() string        { return "lnk" }
func (e *Extractor) Description() string { return "Windows shortcut files (.lnk)" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	lnkFiles, err := idx.GetCollectedFiles(`\.lnk$`, "")
	if err != nil {
		return 0, fmt.Errorf("get LNK files: %w", err)
	}
	if len(lnkFiles) == 0 {
		progress.Info("No LNK files with collected content found")
		return 0, nil
	}

	progress.Info(fmt.Sprintf("Processing %d LNK files with pure-Go parser", len(lnkFiles)))
	totalEvents := 0

	for i, lf := range lnkFiles {
		progress.ProgressLine("LNK [%d/%d] %s", i+1, len(lnkFiles), lf.Filename)

		fpath, cleanup := resolveLNKPath(lf)
		if fpath == "" {
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}

		count := e.parseLNKPath(fpath, lf.Filename, lf.Path, conv)
		totalEvents += count
	}

	progress.ProgressDone()
	progress.Info(fmt.Sprintf("LNK: %d events extracted", totalEvents))
	return totalEvents, nil
}

func resolveLNKPath(lf cache.CollectedFile) (string, func()) {
	if lf.DiskPath != "" {
		return lf.DiskPath, nil
	}
	decoded, err := extractors.GetFileContent(lf)
	if err != nil || len(decoded) == 0 {
		return "", nil
	}
	safe := regexp.MustCompile(`[^\w\-_.]`).ReplaceAllString(lf.Filename, "_")
	tmpPath := filepath.Join(os.TempDir(), "ct_lnk_"+safe)
	if err := os.WriteFile(tmpPath, decoded, 0600); err != nil {
		return "", nil
	}
	return tmpPath, func() { os.Remove(tmpPath) }
}

func (e *Extractor) parseLNKPath(fpath, filename, path string, conv *converter.Converter) int {
	lnkFile, err := golnk.File(fpath)
	if err != nil {
		data, readErr := os.ReadFile(fpath)
		if readErr != nil {
			return 0
		}
		reader := bytes.NewReader(data)
		lnkFile, err = golnk.Read(reader, uint64(len(data)))
		if err != nil {
			return 0
		}
	}

	targetPath := ""
	if lnkFile.LinkInfo.LocalBasePath != "" {
		targetPath = lnkFile.LinkInfo.LocalBasePath
	} else if lnkFile.LinkInfo.LocalBasePathUnicode != "" {
		targetPath = lnkFile.LinkInfo.LocalBasePathUnicode
	}

	events := 0
	type tsEntry struct {
		value string
		desc  string
		word  string
	}

	var entries []tsEntry

	ct := lnkFile.Header.CreationTime
	if !ct.IsZero() && ct.Year() > 1970 && ct.Year() < 2100 {
		entries = append(entries, tsEntry{
			value: ct.UTC().Format("2006-01-02T15:04:05.000Z"),
			desc:  "LNK Target Created",
			word:  "created",
		})
	}

	mt := lnkFile.Header.WriteTime
	if !mt.IsZero() && mt.Year() > 1970 && mt.Year() < 2100 {
		entries = append(entries, tsEntry{
			value: mt.UTC().Format("2006-01-02T15:04:05.000Z"),
			desc:  "LNK Target Modified",
			word:  "modified",
		})
	}

	at := lnkFile.Header.AccessTime
	if !at.IsZero() && at.Year() > 1970 && at.Year() < 2100 {
		entries = append(entries, tsEntry{
			value: at.UTC().Format("2006-01-02T15:04:05.000Z"),
			desc:  "LNK Target Accessed",
			word:  "accessed",
		})
	}

	for _, ts := range entries {
		target := targetPath
		if target == "" {
			target = filename
		}
		targetName := target
		if idx := strings.LastIndex(targetName, "\\"); idx >= 0 {
			targetName = targetName[idx+1:]
		}

		msg := fmt.Sprintf("Shortcut target %s: %s", ts.word, targetName)
		if conv.AddEvent(ts.value, ts.desc, msg,
			"lnk_target", "CT-LNK",
			"CyberTriage TSK - Windows Shortcut",
			"windows:lnk:link",
			map[string]interface{}{
				"lnk_file":    filename,
				"lnk_path":    path,
				"link_target": targetPath,
			}) {
			events++
		}
	}

	return events
}
