package macos

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacUnifiedLogs invokes the bundled `unifiedlog_iterator` binary
// (mandiant/macos-UnifiedLogs project, built into the api image) against the
// extracted unified log archive at artifacts/unified_logs/. Each emitted JSON
// record becomes a `os_log` event so we keep the full retention of the log
// archive (months to years of history), not just the 7-day live snapshot.
//
// If the binary is missing OR the archive doesn't have the expected layout,
// we fall back to streaming live/unified_log_recent.ndjson which the
// collector also produces via `log show --last 24h --style ndjson`.
func processMacUnifiedLogs(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "unified_logs")
	if _, err := os.Stat(root); err != nil {
		return 0
	}

	if added, ok := runUnifiedLogIterator(em, root, ts); ok {
		return added
	}

	// Fall back to live/unified_log_recent.ndjson if available. The live file
	// lives one level up from artifactDir.
	live := filepath.Join(filepath.Dir(artifactDir), "live", "unified_log_recent.ndjson")
	if _, err := os.Stat(live); err == nil {
		return parseUnifiedLogNDJSON(em, live)
	}
	return 0
}

// runUnifiedLogIterator shells out to the mandiant Rust parser bundled in the
// final image at /usr/local/bin/unifiedlog_iterator. Returns (events, true)
// on success, (0, false) if the binary is missing or fails so callers can
// fall back to the ndjson snapshot.
func runUnifiedLogIterator(em *core.Emitter, archiveRoot, ts string) (int, bool) {
	binary := "/usr/local/bin/unifiedlog_iterator"
	if _, err := os.Stat(binary); err != nil {
		return 0, false
	}
	// Newer versions of the iterator accept --input <archive_dir> --output -
	// streaming JSONL on stdout. The archive_dir is expected to contain the
	// `Persist`, `Special`, `Signpost`, `HighVolume`, `timesync` subdirs that
	// `/var/db/diagnostics` uses.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary,
		"--input", archiveRoot,
		"--format", "jsonl")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, false
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, false
	}
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	added := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		added += emitUnifiedLogRow(em, rec, ts)
	}
	_ = ts
	return added, true
}

// parseUnifiedLogNDJSON reads the ndjson file produced by `log show
// --style ndjson` (one JSON object per line). Used as a graceful fallback
// when the Rust iterator isn't present.
func parseUnifiedLogNDJSON(em *core.Emitter, path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	added := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		added += emitUnifiedLogRow(em, rec, "")
	}
	return added
}

// emitUnifiedLogRow normalizes one record from either the Rust iterator
// (with keys: timestamp, subsystem, category, message, process, ...) or
// from `log show --style ndjson` (with keys: timestamp, processImagePath,
// subsystem, category, eventMessage, eventType, ...).
func emitUnifiedLogRow(em *core.Emitter, rec map[string]interface{}, defaultTS string) int {
	ts := pickStr(rec, "timestamp", "Timestamp", "datetime")
	if ts == "" {
		ts = defaultTS
	} else {
		ts = core.NormalizeTimestamp(ts)
	}
	if ts == "" {
		return 0
	}
	msg := pickStr(rec, "message", "eventMessage", "Message")
	subsystem := pickStr(rec, "subsystem", "Subsystem")
	category := pickStr(rec, "category", "Category")
	process := pickStr(rec, "process", "processImagePath", "Process")
	eventType := pickStr(rec, "eventType", "event_type", "logType", "level")
	traceID := pickStr(rec, "traceID", "trace_id")
	if msg == "" && process == "" {
		return 0
	}

	displayMsg := msg
	if len(displayMsg) > 1024 {
		displayMsg = displayMsg[:1024] + "..."
	}
	full := fmt.Sprintf("[%s] %s: %s", subsystem, process, displayMsg)
	attrs := map[string]interface{}{
		"subsystem":   subsystem,
		"category":    category,
		"process":     process,
		"event_type":  eventType,
		"trace_id":    traceID,
		"raw_message": msg,
	}
	if em.AddEvent(ts, "Unified Log Event", full, "os_log",
		"RR-MacOS", "ResponseRay macOS Collector - UnifiedLog",
		"darwin:unifiedlog:event", attrs) {
		return 1
	}
	return 0
}

func pickStr(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
