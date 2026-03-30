package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	chunkSize   = 100 * 1024 * 1024 // 100 MB per goroutine
	overlapSize = 50_000            // overlap between chunks for boundary safety
)

var marker = []byte(`"windowsEvent"`)

// windowsEventWrapper is the outer JSON object containing a windowsEvent field.
type windowsEventWrapper struct {
	WindowsEvent json.RawMessage `json:"windowsEvent"`
}

// extractorCheck is used to quickly read the extractor field.
type extractorCheck struct {
	Extractor string `json:"extractor"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: ct-scan-events <cache-file> [--progress] [--format=timesketch] [--hostname=NAME]\n")
		os.Exit(1)
	}

	cachePath := os.Args[1]
	showProgress := false
	formatTimesketch := false
	hostname := "unknown"
	for _, arg := range os.Args[2:] {
		switch {
		case arg == "--progress":
			showProgress = true
		case arg == "--format=timesketch":
			formatTimesketch = true
		case strings.HasPrefix(arg, "--hostname="):
			hostname = strings.TrimPrefix(arg, "--hostname=")
		}
	}

	f, err := os.Open(cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stat: %v\n", err)
		os.Exit(1)
	}
	fileSize := info.Size()

	workers := runtime.NumCPU()
	if workers > 16 {
		workers = 16
	}

	// Build work items
	type workItem struct {
		offset int64
		size   int64
	}
	var items []workItem
	for pos := int64(0); pos < fileSize; pos += int64(chunkSize) {
		readSize := int64(chunkSize) + int64(overlapSize)
		if pos+readSize > fileSize {
			readSize = fileSize - pos
		}
		items = append(items, workItem{offset: pos, size: readSize})
	}

	if showProgress {
		fmt.Fprintf(os.Stderr, "Scanning %d MB (%d chunks, %d workers)...\n",
			fileSize/(1024*1024), len(items), workers)
	}

	start := time.Now()

	// Buffered writer for stdout with mutex
	stdout := bufio.NewWriterSize(os.Stdout, 4*1024*1024)
	var mu sync.Mutex

	// Dedup set (hash of datetime+message+event_type) -- only used in timesketch mode
	var dedupSet sync.Map

	var totalEvents atomic.Int64
	var totalSkipped atomic.Int64
	var chunksCompleted atomic.Int64

	// Semaphore channel to limit concurrent goroutines
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot
		go func(it workItem) {
			defer wg.Done()
			defer func() { <-sem }() // release slot

			rawEvents := scanChunk(cachePath, it.offset, it.size, int64(chunkSize))

			var outputLines [][]byte

			if formatTimesketch {
				for _, raw := range rawEvents {
					line, err := convertWindowsEvent(json.RawMessage(raw), hostname)
					if err != nil {
						continue
					}
					// Dedup: hash key fields from the line
					key := dedupKey(line)
					if _, loaded := dedupSet.LoadOrStore(key, struct{}{}); loaded {
						totalSkipped.Add(1)
						continue
					}
					outputLines = append(outputLines, line)
				}
			} else {
				outputLines = rawEvents
			}

			if len(outputLines) > 0 {
				mu.Lock()
				for _, e := range outputLines {
					stdout.Write(e)
					stdout.WriteByte('\n')
				}
				mu.Unlock()
			}

			totalEvents.Add(int64(len(outputLines)))
			done := chunksCompleted.Add(1)

			if showProgress && done%4 == 0 {
				fmt.Fprintf(os.Stderr, "\r  Chunks: %d/%d (%d events)",
					done, len(items), totalEvents.Load())
			}
		}(item)
	}

	wg.Wait()
	stdout.Flush()

	elapsed := time.Since(start)

	if showProgress {
		fmt.Fprintf(os.Stderr, "\r  Chunks: %d/%d (%d events) in %.1fs\n",
			len(items), len(items), totalEvents.Load(), elapsed.Seconds())
	}

	// Summary to stderr (always)
	mode := "raw"
	if formatTimesketch {
		mode = "timesketch"
	}
	skipped := totalSkipped.Load()
	summary := fmt.Sprintf("ct-scan-events [%s]: %d events in %.1fs (%.0f events/s)",
		mode, totalEvents.Load(), elapsed.Seconds(),
		float64(totalEvents.Load())/elapsed.Seconds())
	if skipped > 0 {
		summary += fmt.Sprintf(", %d duplicates skipped", skipped)
	}
	fmt.Fprintln(os.Stderr, summary)
}

// scanChunk reads a portion of the cache file and extracts windowsEvent JSON objects.
// Returns a slice of JSON-encoded windowsEvent objects (each is a complete JSON line).
func scanChunk(path string, offset, readSize, chunkLimit int64) [][]byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, readSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil
	}
	buf = buf[:n]

	var results [][]byte
	searchStart := 0

	for {
		idx := bytes.Index(buf[searchStart:], marker)
		if idx == -1 {
			break
		}
		idx += searchStart

		// Only process markers within the chunk boundary (not in overlap)
		if int64(idx) >= chunkLimit {
			break
		}

		// Find the opening brace before the marker
		objStart := -1
		scanBack := idx - 1
		limit := idx - 200 // don't look too far back
		if limit < 0 {
			limit = 0
		}
		for i := scanBack; i >= limit; i-- {
			if buf[i] == '{' {
				objStart = i
				break
			}
		}
		if objStart == -1 {
			searchStart = idx + len(marker)
			continue
		}

		// Find the matching closing brace using brace counting
		objEnd := findClosingBrace(buf, objStart)
		if objEnd == -1 || objEnd > len(buf) {
			searchStart = idx + len(marker)
			continue
		}

		objBytes := buf[objStart:objEnd]
		searchStart = objEnd

		// Quick filter: check for "SystemAPI" before full parse
		if !bytes.Contains(objBytes, []byte(`"SystemAPI"`)) {
			continue
		}

		// Parse the wrapper to get the windowsEvent field
		var wrapper windowsEventWrapper
		if err := json.Unmarshal(objBytes, &wrapper); err != nil {
			continue
		}
		if wrapper.WindowsEvent == nil {
			continue
		}

		// Verify extractor == "SystemAPI"
		var ec extractorCheck
		if err := json.Unmarshal(wrapper.WindowsEvent, &ec); err != nil {
			continue
		}
		if ec.Extractor != "SystemAPI" {
			continue
		}

		// Re-encode as compact single-line JSON
		compact, err := compactJSON(wrapper.WindowsEvent)
		if err != nil {
			continue
		}
		results = append(results, compact)
	}

	return results
}

// compactJSON re-encodes raw JSON as compact single-line output.
func compactJSON(raw json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dedupKey extracts a lightweight key from a Timesketch JSONL line for deduplication.
// Uses FNV hash of datetime + timestamp_desc + message + event_type.
func dedupKey(line []byte) uint64 {
	// Fast extraction of key fields without full parse
	h := uint64(14695981039346656037) // FNV-1a offset basis
	for _, field := range [][]byte{
		[]byte(`"datetime":"`), []byte(`"message":"`), []byte(`"event_type":"`),
	} {
		idx := bytes.Index(line, field)
		if idx == -1 {
			continue
		}
		valStart := idx + len(field)
		valEnd := bytes.IndexByte(line[valStart:], '"')
		if valEnd == -1 {
			continue
		}
		for _, b := range line[valStart : valStart+valEnd] {
			h ^= uint64(b)
			h *= 1099511628211 // FNV prime
		}
	}
	return h
}

// findClosingBrace finds the matching closing brace for an opening brace at pos.
// Returns the index one past the closing brace, or -1 if not found.
func findClosingBrace(buf []byte, pos int) int {
	depth := 0
	inString := false
	escaped := false

	for i := pos; i < len(buf); i++ {
		b := buf[i]

		if escaped {
			escaped = false
			continue
		}

		if b == '\\' && inString {
			escaped = true
			continue
		}

		if b == '"' {
			inString = !inString
			continue
		}

		if inString {
			continue
		}

		if b == '{' {
			depth++
		} else if b == '}' {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}

	return -1
}
