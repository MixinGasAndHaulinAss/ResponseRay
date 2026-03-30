package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	conv "github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// StreamResult holds the output of the streaming single-pass scan.
type StreamResult struct {
	ArtifactFiles  []cache.ArtifactFile
	CollectionTime string
	FileSize       int64
	EventsAdded    int
	ItemsProcessed int64
	Stats          map[string]int64
	ArtifactsDir   string
	FilesWritten   int
	chunkBuffer    [][]byte // decoded fileChunk data awaiting a parent file section
}

// StreamingScan performs a single pass through the CyberTriage JSON cache file.
// It reads the entire file into memory and uses a custom byte-level parser for
// navigation, combined with json.Unmarshal for individual section items. This
// avoids Go's json.Decoder accumulation overhead on multi-hundred-MB base64
// fileContent strings.
//
// During the pass it:
//   - Creates timeline events (MFT, windowsEvent, process, logon, etc.)
//   - Decodes collected file content and writes native files to artifactsDir
//   - Handles chunked files (repeated chunkData keys) at byte level
func StreamingScan(cachePath, artifactsDir string, c *conv.Converter) (*StreamResult, error) {
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("read cache: %w", err)
	}

	result := &StreamResult{
		FileSize:     int64(len(data)),
		Stats:        make(map[string]int64),
		ArtifactsDir: artifactsDir,
	}

	progress.Info(fmt.Sprintf("Streaming scan: %d MB → %s", result.FileSize/(1024*1024), artifactsDir))
	start := time.Now()

	// Navigate the envelope to find cyberTriageAgentOutput
	pos := skipWS(data, 0)
	if pos >= len(data) || data[pos] != '{' {
		return nil, fmt.Errorf("expected root object")
	}
	pos++ // skip '{'

	phaseCount := 0
	for pos < len(data) && data[pos] != '}' {
		pos = skipWS(data, pos)
		if pos >= len(data) || data[pos] == '}' {
			break
		}

		keyStart, keyEnd := readString(data, pos)
		if keyStart < 0 {
			break
		}
		key := string(data[keyStart:keyEnd])
		pos = skipWS(data, keyEnd+1) // skip closing quote
		pos = skipWS(data, pos)
		if pos < len(data) && data[pos] == ':' {
			pos++
		}
		pos = skipWS(data, pos)

		if !strings.Contains(key, "cyberTriageAgentOutput") {
			pos = skipJSONValue(data, pos)
			pos = skipComma(data, pos)
			continue
		}

		// cyberTriageAgentOutput: array of phase objects
		if pos >= len(data) || data[pos] != '[' {
			pos = skipJSONValue(data, pos)
			pos = skipComma(data, pos)
			continue
		}
		pos++ // skip '['

		for pos < len(data) && data[pos] != ']' {
			pos = skipWS(data, pos)
			if pos >= len(data) || data[pos] == ']' {
				break
			}
			if data[pos] != '{' {
				pos = skipJSONValue(data, pos)
				pos = skipComma(data, pos)
				continue
			}
			pos++ // skip '{'

			// Phase object: look for cyberTriageOutputSection
			for pos < len(data) && data[pos] != '}' {
				pos = skipWS(data, pos)
				if pos >= len(data) || data[pos] == '}' {
					break
				}

				secKeyStart, secKeyEnd := readString(data, pos)
				if secKeyStart < 0 {
					break
				}
				secKey := string(data[secKeyStart:secKeyEnd])
				pos = skipWS(data, secKeyEnd+1) // closing quote
				pos = skipWS(data, pos)
				if pos < len(data) && data[pos] == ':' {
					pos++
				}
				pos = skipWS(data, pos)

				if strings.Contains(secKey, "cyberTriageOutputSection") {
					phaseCount++
					progress.Info(fmt.Sprintf("Processing phase %d...", phaseCount))
					pos = processSectionArray(data, pos, c, result)
				} else {
					pos = skipJSONValue(data, pos)
				}
				pos = skipComma(data, pos)
			}

			if pos < len(data) && data[pos] == '}' {
				pos++
			}
			pos = skipComma(data, pos)
		}

		if pos < len(data) && data[pos] == ']' {
			pos++
		}
		pos = skipComma(data, pos)
	}

	elapsed := time.Since(start)
	throughput := float64(result.FileSize) / (1024 * 1024) / elapsed.Seconds()
	progress.Info(fmt.Sprintf("Streaming scan complete: %d events, %d files written, %d items in %.1fs (%.0f MB/s)",
		result.EventsAdded, result.FilesWritten, result.ItemsProcessed,
		elapsed.Seconds(), throughput))

	for stype, count := range result.Stats {
		if count > 0 {
			progress.Info(fmt.Sprintf("  %-25s %d", stype, count))
		}
	}

	return result, nil
}

func processSectionArray(data []byte, pos int, c *conv.Converter, result *StreamResult) int {
	if pos >= len(data) || data[pos] != '[' {
		return skipJSONValue(data, pos)
	}
	pos++ // skip '['

	lastReport := time.Now()

	for pos < len(data) && data[pos] != ']' {
		pos = skipWS(data, pos)
		if pos >= len(data) || data[pos] == ']' {
			break
		}

		// Each item is { "<sectionType>": { ... } }
		if data[pos] != '{' {
			pos = skipJSONValue(data, pos)
			pos = skipComma(data, pos)
			continue
		}
		pos++ // skip '{'
		pos = skipWS(data, pos)

		if pos >= len(data) || data[pos] == '}' {
			if pos < len(data) {
				pos++
			}
			pos = skipComma(data, pos)
			continue
		}

		// Read section type key
		typeStart, typeEnd := readString(data, pos)
		if typeStart < 0 {
			pos = skipToClosingBrace(data, pos)
			pos = skipComma(data, pos)
			continue
		}
		sectionType := string(data[typeStart:typeEnd])
		pos = skipWS(data, typeEnd+1) // closing quote
		pos = skipWS(data, pos)
		if pos < len(data) && data[pos] == ':' {
			pos++
		}
		pos = skipWS(data, pos)

		// Find the inner value boundaries
		valueStart := pos
		valueEnd := skipJSONValue(data, pos)

		dispatched := dispatchSection(data[valueStart:valueEnd], sectionType, c, result)
		if dispatched {
			result.Stats[sectionType]++
		}

		pos = valueEnd
		// Skip to closing } of outer item
		pos = skipWS(data, pos)
		if pos < len(data) && data[pos] == '}' {
			pos++
		}
		pos = skipComma(data, pos)

		result.ItemsProcessed++

		if time.Since(lastReport) > 2*time.Second {
			progress.ProgressLine("Streaming: %d items (%d events, %d files)",
				result.ItemsProcessed, result.EventsAdded, result.FilesWritten)
			lastReport = time.Now()
		}
	}

	progress.ProgressDone()

	if pos < len(data) && data[pos] == ']' {
		pos++
	}
	return pos
}

func dispatchSection(raw []byte, sectionType string, c *conv.Converter, result *StreamResult) bool {
	switch sectionType {
	case "file":
		return handleFile(raw, c, result)
	case "windowsEvent":
		return handleWindowsEvent(raw, c, result)
	case "process":
		return handleProcess(raw, c, result)
	case "configItem":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertConfigItem(a) {
				return 1
			}
			return 0
		})
	case "logonSession":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertLogonSession(a) {
				return 1
			}
			return 0
		})
	case "logonData":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertLogonDataCollection(a) {
				return 1
			}
			return 0
		})
	case "userAccessedData":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertUserAccessedData(a) {
				return 1
			}
			return 0
		})
	case "userAccount":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertUserAccount(a) {
				return 1
			}
			return 0
		})
	case "nwConnectionDescriptor":
		return handleNwConnection(raw, c, result)
	case "triggeredTask":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertTriggeredTask(a) {
				return 1
			}
			return 0
		})
	case "webArtifact":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertWebArtifact(a) {
				return 1
			}
			return 0
		})
	case "attachedDevice":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			return c.ConvertAttachedDevice(a)
		})
	case "logLine":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertLogLine(a) {
				return 1
			}
			return 0
		})
	case "osConfigSetting":
		return handleGenericUnmarshal(raw, c, result, func(a conv.Artifact) int {
			if c.ConvertOSConfigSetting(a, result.CollectionTime) {
				return 1
			}
			return 0
		})
	case "fileChunk":
		return handleFileChunk(raw, result)
	case "params":
		return handleParams(raw, result)
	case "collectionInfo":
		return false
	default:
		return false
	}
}

// handleFile processes a "file" section at byte level. It extracts metadata
// fields from the raw JSON without loading fileContent/chunkData into Go strings,
// then writes collected content to disk using direct byte operations.
func handleFile(raw []byte, c *conv.Converter, result *StreamResult) bool {
	// Check if this is a collected file (quick byte scan)
	hasCollected := bytesContains(raw, []byte(`"Collected"`))

	// For MFT events, we need the full artifact map (minus fileContent).
	// Build a cleaned version without the large content fields.
	var a conv.Artifact
	if hasCollected {
		cleaned := removeContentFields(raw)
		if err := json.Unmarshal(cleaned, &a); err != nil {
			return true
		}
	} else {
		if err := json.Unmarshal(raw, &a); err != nil {
			return true
		}
	}

	status := conv.GetStr(a, "fileContentStatus")
	if status == "NotFound" {
		return true
	}

	// Create MFT events
	extractor := conv.GetStr(a, "extractor")
	if extractor == "" {
		if si := conv.GetSourceInfo(a); si != nil {
			extractor = conv.GetStr(si, "extractor")
		}
		if extractor == "" {
			if sources := conv.GetSlice(a, "sources"); len(sources) > 0 {
				extractor = conv.GetStr(sources[0], "sourceType")
			}
		}
	}
	if extractor == "TSK" || extractor == "FileSystem" {
		n := c.ConvertFileMFT(a)
		result.EventsAdded += n
	}

	// Write collected file content to artifacts directory
	if status == "Collected" && result.ArtifactsDir != "" {
		filename := conv.GetStr(a, "fileName")
		winPath := conv.GetStr(a, "path")
		if winPath == "" {
			winPath = conv.GetStr(a, "fullPath")
		}
		if filename == "" {
			return true
		}

		chunkCount := conv.GetInt(a, "chunkCount")

		content := extractFileContent(raw)
		if len(content) > 0 {
			diskPath := writeArtifact(result.ArtifactsDir, winPath, filename, content)
			if diskPath != "" {
				result.ArtifactFiles = append(result.ArtifactFiles, cache.ArtifactFile{
					Filename: filename,
					Path:     winPath,
					DiskPath: diskPath,
				})
				result.FilesWritten++
			}
		} else if chunkCount > 0 && len(result.chunkBuffer) > 0 {
			// Chunks arrive as separate fileChunk sections BEFORE the
			// file metadata. Consume the buffered chunks.
			chunks := result.chunkBuffer
			if len(chunks) > chunkCount {
				chunks = chunks[len(chunks)-chunkCount:]
			}

			var totalSize int
			for _, c := range chunks {
				totalSize += len(c)
			}
			assembled := make([]byte, 0, totalSize)
			for _, c := range chunks {
				assembled = append(assembled, c...)
			}

			diskPath := writeArtifact(result.ArtifactsDir, winPath, filename, assembled)
			if diskPath != "" {
				result.ArtifactFiles = append(result.ArtifactFiles, cache.ArtifactFile{
					Filename: filename,
					Path:     winPath,
					DiskPath: diskPath,
				})
				result.FilesWritten++
				progress.Info(fmt.Sprintf("  Assembled: %s (%d chunks, %d MB)",
					filename, len(chunks), totalSize/(1024*1024)))
			}
			result.chunkBuffer = nil
		}
	}

	return true
}

// handleFileChunk buffers a decoded "fileChunk" section. CyberTriage emits
// fileChunk entries BEFORE the parent file metadata, so we accumulate them
// and consume the buffer when a file section with chunkCount appears.
func handleFileChunk(raw []byte, result *StreamResult) bool {
	b64 := extractJSONStringValue(raw, "chunkData")
	if len(b64) == 0 {
		return true
	}

	decoded := decodeB64Chunk(b64)
	if decoded != nil {
		result.chunkBuffer = append(result.chunkBuffer, decoded)
	}
	return true
}

// extractFileContent extracts and decodes file content from raw JSON bytes.
// Handles both inline fileContent and chunked chunkData (repeated keys).
// Operates at byte level without allocating Go strings for the base64 content.
func extractFileContent(raw []byte) []byte {
	// Try chunked first (chunkData keys)
	chunks := extractAllChunkData(raw)
	if len(chunks) > 0 {
		var result []byte
		for _, chunk := range chunks {
			decoded := decodeB64Chunk(chunk)
			if decoded != nil {
				result = append(result, decoded...)
			}
		}
		return result
	}

	// Inline fileContent
	b64 := extractJSONStringValue(raw, "fileContent")
	if len(b64) == 0 {
		return nil
	}
	return decodeB64Chunk(b64)
}

// extractAllChunkData finds all "chunkData":"..." values in raw JSON bytes.
// Returns slices pointing into the original data (no allocation for the content).
func extractAllChunkData(raw []byte) [][]byte {
	marker := []byte(`"chunkData"`)
	var results [][]byte
	pos := 0

	for {
		idx := bytesIndex(raw[pos:], marker)
		if idx < 0 {
			break
		}
		pos += idx + len(marker)

		// Skip : and whitespace
		for pos < len(raw) && (raw[pos] == ':' || raw[pos] <= ' ') {
			pos++
		}
		if pos >= len(raw) || raw[pos] != '"' {
			continue
		}

		// Read the string value (just the content, not the quotes)
		start, end := readString(raw, pos)
		if start >= 0 {
			results = append(results, raw[start:end])
			pos = end + 1
		}
	}
	return results
}

// extractJSONStringValue finds a key in the raw JSON and returns its string value
// as a byte slice pointing into the original data.
func extractJSONStringValue(raw []byte, key string) []byte {
	marker := []byte(`"` + key + `"`)
	idx := bytesIndex(raw, marker)
	if idx < 0 {
		return nil
	}
	pos := idx + len(marker)

	for pos < len(raw) && (raw[pos] == ':' || raw[pos] <= ' ') {
		pos++
	}
	if pos >= len(raw) || raw[pos] != '"' {
		return nil
	}
	start, end := readString(raw, pos)
	if start < 0 {
		return nil
	}
	return raw[start:end]
}

// removeContentFields creates a copy of the JSON without fileContent and chunkData
// values, replacing them with empty strings to keep the JSON valid.
func removeContentFields(raw []byte) []byte {
	out := make([]byte, 0, len(raw)/4)
	pos := 0

	for pos < len(raw) {
		// Find next "fileContent" or "chunkData" key
		fc := bytesIndex(raw[pos:], []byte(`"fileContent"`))
		cd := bytesIndex(raw[pos:], []byte(`"chunkData"`))

		next := -1
		nextLen := 0
		if fc >= 0 && (cd < 0 || fc <= cd) {
			next = fc
			nextLen = len(`"fileContent"`)
		} else if cd >= 0 {
			next = cd
			nextLen = len(`"chunkData"`)
		}

		if next < 0 {
			out = append(out, raw[pos:]...)
			break
		}

		// Copy up to and including the key
		out = append(out, raw[pos:pos+next+nextLen]...)
		pos += next + nextLen

		// Skip : whitespace
		for pos < len(raw) && (raw[pos] == ':' || raw[pos] <= ' ') {
			pos++
		}

		// Write : ""
		out = append(out, ':', '"', '"')

		// Skip the original value
		if pos < len(raw) && raw[pos] == '"' {
			pos++ // skip opening quote
			for pos < len(raw) {
				if raw[pos] == '\\' {
					pos += 2
				} else if raw[pos] == '"' {
					pos++ // skip closing quote
					break
				} else {
					pos++
				}
			}
		} else {
			end := skipJSONValue(raw, pos)
			pos = end
		}
	}
	return out
}

func handleWindowsEvent(raw []byte, c *conv.Converter, result *StreamResult) bool {
	var we conv.Artifact
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&we); err != nil {
		return true
	}

	extractor := conv.GetStr(we, "extractor")
	if extractor != "SystemAPI" {
		if si := conv.GetSourceInfo(we); si != nil {
			extractor = conv.GetStr(si, "extractor")
		}
	}
	if extractor != "SystemAPI" {
		return true
	}

	timeVal := we["time"]
	if timeVal == nil {
		return true
	}
	var timeMs int64
	switch t := timeVal.(type) {
	case float64:
		timeMs = int64(t)
	case json.Number:
		timeMs, _ = t.Int64()
	default:
		return true
	}
	if timeMs == 0 {
		return true
	}
	dt := conv.EpochMsToISO(timeMs)

	eid := conv.GetInt(we, "eventID")

	eventLogName := conv.GetStr(we, "logName")
	if eventLogName == "" {
		if si := conv.GetSourceInfo(we); si != nil {
			eventLogName = conv.GetStr(si, "eventLogName")
		}
	}
	if eventLogName == "" {
		eventLogName = "Unknown"
	}

	recordID := conv.GetStr(we, "recordID")
	if recordID == "" {
		if si := conv.GetSourceInfo(we); si != nil {
			recordID = conv.GetStr(si, "eventLogRecordId")
		}
	}

	payload := conv.GetMap(we, "payload")
	if payload == nil {
		payload = make(map[string]interface{})
	}

	sourceName := ""
	if eventLogName == "Unknown" || eventLogName == "" {
		ch, sn := conv.InferChannel(eid)
		if ch != "" {
			eventLogName = ch
			sourceName = sn
		} else {
			sourceName = "Unknown"
		}
	} else {
		sourceName = conv.GetProviderName(eventLogName)
	}

	message := conv.BuildWindowsEventMessage(eid, eventLogName, payload)
	eventType := conv.CategorizeWindowsEvent(eid, eventLogName)

	attrs := conv.Event{
		"source_name":      sourceName,
		"channel":          eventLogName,
		"event_identifier": fmt.Sprintf("%d", eid),
		"computer_name":    c.Hostname,
	}
	if recordID != "" {
		attrs["record_number"] = recordID
	}
	for k, v := range payload {
		if v != nil {
			attrs[k] = fmt.Sprint(v)
		}
	}

	if c.AddEvent(dt, "Windows Event Log Entry", message, eventType,
		"CT-EventLog", "CyberTriage SystemAPI - "+eventLogName,
		"windows:evtx:record", attrs) {
		result.EventsAdded++
	}

	return true
}

func handleProcess(raw []byte, c *conv.Converter, result *StreamResult) bool {
	var a conv.Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return true
	}

	extractor := conv.GetStr(a, "extractor")
	if extractor == "" {
		if si := conv.GetSourceInfo(a); si != nil {
			extractor = conv.GetStr(si, "extractor")
		}
		if extractor == "" {
			if sources := conv.GetSlice(a, "sources"); len(sources) > 0 {
				extractor = conv.GetStr(sources[0], "sourceType")
			}
		}
	}

	switch extractor {
	case "LiveSnapshot":
		if c.ConvertRunningProcess(a, result.CollectionTime) {
			result.EventsAdded++
		}
	case "SystemAPI":
		if c.ConvertProcessSystemAPI(a) {
			result.EventsAdded++
		}
	default:
		if c.ConvertProcessCollection(a) {
			result.EventsAdded++
		}
	}
	return true
}

func handleNwConnection(raw []byte, c *conv.Converter, result *StreamResult) bool {
	var a conv.Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return true
	}

	extractor := conv.GetStr(a, "extractor")
	if extractor == "" {
		if si := conv.GetSourceInfo(a); si != nil {
			extractor = conv.GetStr(si, "extractor")
		}
	}

	switch extractor {
	case "LiveSnapshot":
		entryTime := conv.EpochMsFromAny(a["time"])
		if c.ConvertActiveConnection(a, entryTime, result.CollectionTime) {
			result.EventsAdded++
		}
	case "SystemAPI":
		if c.ConvertNetworkConnectionSystemAPI(a) {
			result.EventsAdded++
		}
	default:
		if c.ConvertNetworkConnectionCollection(a) {
			result.EventsAdded++
		}
	}
	return true
}

func handleGenericUnmarshal(raw []byte, c *conv.Converter, result *StreamResult, fn func(conv.Artifact) int) bool {
	var a conv.Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return true
	}
	n := fn(a)
	result.EventsAdded += n
	return true
}

func handleParams(raw []byte, result *StreamResult) bool {
	var params conv.Artifact
	if err := json.Unmarshal(raw, &params); err != nil {
		return true
	}
	if ct := conv.GetStr(params, "collectionDateTime"); ct != "" {
		result.CollectionTime = conv.NormalizeTimestamp(ct)
	}
	return true
}

// ---------------------------------------------------------------------------
// Fast byte-level JSON navigation (zero-allocation for skipped values)
// ---------------------------------------------------------------------------

func skipWS(data []byte, pos int) int {
	for pos < len(data) && data[pos] <= ' ' {
		pos++
	}
	return pos
}

func skipComma(data []byte, pos int) int {
	pos = skipWS(data, pos)
	if pos < len(data) && data[pos] == ',' {
		pos++
	}
	return skipWS(data, pos)
}

// readString reads a JSON string at pos (which should point to the opening ").
// Returns the start and end offsets of the string CONTENT (excluding quotes).
// Returns -1,-1 if not a valid string.
func readString(data []byte, pos int) (int, int) {
	if pos >= len(data) || data[pos] != '"' {
		return -1, -1
	}
	pos++ // skip opening "
	start := pos
	for pos < len(data) {
		if data[pos] == '\\' {
			pos += 2
		} else if data[pos] == '"' {
			return start, pos
		} else {
			pos++
		}
	}
	return -1, -1
}

// skipJSONValue skips past the next JSON value starting at pos.
// Returns the position after the value.
func skipJSONValue(data []byte, pos int) int {
	pos = skipWS(data, pos)
	if pos >= len(data) {
		return pos
	}

	switch data[pos] {
	case '"':
		// String: scan for closing quote
		pos++
		for pos < len(data) {
			if data[pos] == '\\' {
				pos += 2
			} else if data[pos] == '"' {
				return pos + 1
			} else {
				pos++
			}
		}
		return pos
	case '{':
		// Object
		pos++
		for {
			pos = skipWS(data, pos)
			if pos >= len(data) || data[pos] == '}' {
				if pos < len(data) {
					pos++
				}
				return pos
			}
			// Skip key
			pos = skipJSONValue(data, pos)
			// Skip :
			pos = skipWS(data, pos)
			if pos < len(data) && data[pos] == ':' {
				pos++
			}
			// Skip value
			pos = skipJSONValue(data, pos)
			// Skip comma
			pos = skipWS(data, pos)
			if pos < len(data) && data[pos] == ',' {
				pos++
			}
		}
	case '[':
		// Array
		pos++
		for {
			pos = skipWS(data, pos)
			if pos >= len(data) || data[pos] == ']' {
				if pos < len(data) {
					pos++
				}
				return pos
			}
			pos = skipJSONValue(data, pos)
			pos = skipWS(data, pos)
			if pos < len(data) && data[pos] == ',' {
				pos++
			}
		}
	default:
		// Number, true, false, null
		for pos < len(data) && data[pos] != ',' && data[pos] != '}' && data[pos] != ']' && data[pos] > ' ' {
			pos++
		}
		return pos
	}
}

// skipToClosingBrace skips to the matching } for error recovery.
func skipToClosingBrace(data []byte, pos int) int {
	depth := 1
	for pos < len(data) && depth > 0 {
		switch data[pos] {
		case '{':
			depth++
		case '}':
			depth--
		case '"':
			pos++
			for pos < len(data) && data[pos] != '"' {
				if data[pos] == '\\' {
					pos++
				}
				pos++
			}
		}
		pos++
	}
	return pos
}

// ---------------------------------------------------------------------------
// Byte search helpers
// ---------------------------------------------------------------------------

func bytesContains(data, sub []byte) bool {
	return bytesIndex(data, sub) >= 0
}

func bytesIndex(data, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	if len(data) < len(sub) {
		return -1
	}
	for i := 0; i <= len(data)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if data[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
