package converter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Event is a single Timesketch JSONL event.
type Event = map[string]interface{}

// Artifact is a CyberTriage artifact parsed from the cache file.
type Artifact = map[string]interface{}

// Converter accumulates Timesketch events and writes JSONL output.
type Converter struct {
	Hostname string
	Events   []Event
	Stats    map[string]int
	seenKeys map[uint64]struct{}
}

func New(hostname string) *Converter {
	return &Converter{
		Hostname: hostname,
		Events:   make([]Event, 0, 100_000),
		Stats:    make(map[string]int),
		seenKeys: make(map[uint64]struct{}),
	}
}

// AddEvent creates a deduplicated Timesketch event.
func (c *Converter) AddEvent(datetime, timestampDesc, message, eventType, sourceShort, sourceLong, dataType string, attributes map[string]interface{}) bool {
	if datetime == "" {
		return false
	}
	dt := NormalizeTimestamp(datetime)
	if dt == "" {
		return false
	}
	if dataType == "" {
		dataType = "ct:generic:event"
	}

	h := fnv.New64a()
	h.Write([]byte(dt))
	h.Write([]byte(timestampDesc))
	h.Write([]byte(message))
	h.Write([]byte(eventType))
	key := h.Sum64()
	if _, exists := c.seenKeys[key]; exists {
		return false
	}
	c.seenKeys[key] = struct{}{}

	event := Event{
		"datetime":       dt,
		"timestamp_desc": timestampDesc,
		"message":        message,
		"data_type":      dataType,
		"event_type":     eventType,
		"source_short":   sourceShort,
		"source_long":    sourceLong,
		"host_name":      c.Hostname,
	}
	for k, v := range attributes {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		event[k] = v
	}

	c.Events = append(c.Events, event)
	c.Stats[eventType]++
	return true
}

// AppendRawEvent adds a pre-built event (e.g. from the Go scanner) without re-processing.
func (c *Converter) AppendRawEvent(event Event) {
	c.Events = append(c.Events, event)
	if et, ok := event["event_type"].(string); ok {
		c.Stats[et]++
	}
}

// WriteJSONL writes all events to a JSONL file and returns the count.
func (c *Converter) WriteJSONL(path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 4*1024*1024)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for _, event := range c.Events {
		if err := enc.Encode(event); err != nil {
			return 0, fmt.Errorf("encoding event: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	return len(c.Events), nil
}

// GetSummary returns the event type counts.
func (c *Converter) GetSummary() map[string]int {
	return c.Stats
}

// EventCount returns the total accumulated events.
func (c *Converter) EventCount() int {
	return len(c.Events)
}

// CountByType returns the count for a specific event type.
func (c *Converter) CountByType(eventType string) int {
	return c.Stats[eventType]
}

// ---------------------------------------------------------------------------
// Timestamp utilities
// ---------------------------------------------------------------------------

var (
	reTimestampFrac   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(\d+)(Z|[+-]\d{2}:?\d{2})?`)
	reTimestampNoFrac = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?$`)
)

// NormalizeTimestamp converts various timestamp formats to Timesketch ISO 8601 with millisecond precision.
func NormalizeTimestamp(ts string) string {
	if ts == "" {
		return ""
	}
	if m := reTimestampFrac.FindStringSubmatch(ts); m != nil {
		base := strings.Replace(m[1], " ", "T", 1)
		frac := m[2]
		if len(frac) > 3 {
			frac = frac[:3]
		}
		for len(frac) < 3 {
			frac += "0"
		}
		return base + "." + frac + "Z"
	}
	if m := reTimestampNoFrac.FindStringSubmatch(ts); m != nil {
		base := strings.Replace(m[1], " ", "T", 1)
		return base + ".000Z"
	}
	return ts
}

// EpochMsToISO converts epoch milliseconds to ISO 8601.
func EpochMsToISO(ms int64) string {
	if ms == 0 {
		return ""
	}
	t := time.Unix(ms/1000, (ms%1000)*1_000_000).UTC()
	return t.Format("2006-01-02T15:04:05.000") + "Z"
}

// EpochMsFromAny converts an interface{} (float64, string, json.Number) to ISO.
func EpochMsFromAny(v interface{}) string {
	switch t := v.(type) {
	case float64:
		return EpochMsToISO(int64(t))
	case int64:
		return EpochMsToISO(t)
	case int:
		return EpochMsToISO(int64(t))
	case json.Number:
		n, _ := t.Int64()
		return EpochMsToISO(n)
	case string:
		if t == "" || t == "0" {
			return ""
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return EpochMsToISO(n)
		}
		return NormalizeTimestamp(t)
	case nil:
		return ""
	}
	return ""
}

// FiletimeToISO converts Windows FILETIME (100ns since 1601) to ISO 8601.
func FiletimeToISO(ft int64) string {
	if ft == 0 {
		return ""
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return ""
	}
	unixNano := (ft - epochDiff) * 100
	t := time.Unix(0, unixNano).UTC()
	return t.Format("2006-01-02T15:04:05.000") + "Z"
}

// ---------------------------------------------------------------------------
// Artifact helper functions
// ---------------------------------------------------------------------------

// GetStr safely extracts a string from an artifact map.
func GetStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// GetInt safely extracts an int from an artifact map.
func GetInt(m map[string]interface{}, key string) int {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// GetInt64 safely extracts an int64.
func GetInt64(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

// GetMap safely extracts a nested map.
func GetMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if sub, ok := v.(map[string]interface{}); ok {
			return sub
		}
	}
	return nil
}

// GetSlice safely extracts a slice of maps from an artifact map.
func GetSlice(m map[string]interface{}, key string) []map[string]interface{} {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if arr, ok := v.([]interface{}); ok {
		var result []map[string]interface{}
		for _, item := range arr {
			if sub, ok := item.(map[string]interface{}); ok {
				result = append(result, sub)
			}
		}
		return result
	}
	return nil
}

// GetSourceInfo extracts sourceInfo with fallback to sources[0] for
// types that inconsistently use singular vs array source fields.
func GetSourceInfo(a Artifact) map[string]interface{} {
	si := GetMap(a, "sourceInfo")
	if si != nil {
		return si
	}
	if sources := GetSlice(a, "sources"); len(sources) > 0 {
		return sources[0]
	}
	return nil
}

// ExtractAnalysisAttrs extracts analysisResults from a CyberTriage artifact
// and adds ct_significance, ct_analysis_type, ct_justification, and
// mitre_attack_ids as standard Timesketch attributes.
func ExtractAnalysisAttrs(a Artifact, attrs map[string]interface{}) {
	results, ok := a["analysisResults"]
	if !ok || results == nil {
		return
	}
	arr, ok := results.([]interface{})
	if !ok || len(arr) == 0 {
		return
	}

	var significances, analysisTypes, justifications, mitreIDs []string
	for _, item := range arr {
		r, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if sig := GetStr(r, "significance"); sig != "" {
			significances = append(significances, sig)
		}
		if at := GetStr(r, "analysisType"); at != "" {
			analysisTypes = append(analysisTypes, at)
		}
		if j := GetStr(r, "justification"); j != "" {
			justifications = append(justifications, j)
		}
		if ids, ok := r["mitreAttackIds"].([]interface{}); ok {
			for _, id := range ids {
				if s, ok := id.(string); ok && s != "" {
					mitreIDs = append(mitreIDs, s)
				}
			}
		}
	}

	if len(significances) > 0 {
		attrs["ct_significance"] = strings.Join(significances, ",")
	}
	if len(analysisTypes) > 0 {
		attrs["ct_analysis_type"] = strings.Join(analysisTypes, ",")
	}
	if len(justifications) > 0 {
		attrs["ct_justification"] = strings.Join(justifications, " | ")
	}
	if len(mitreIDs) > 0 {
		attrs["mitre_attack_ids"] = strings.Join(mitreIDs, ",")
	}
}

// AddEventFromArtifact is like AddEvent but also extracts analysisResults
// from the source CyberTriage artifact and attaches them as Timesketch attributes.
func (c *Converter) AddEventFromArtifact(a Artifact, datetime, timestampDesc, message, eventType, sourceShort, sourceLong, dataType string, attributes map[string]interface{}) bool {
	ExtractAnalysisAttrs(a, attributes)
	return c.AddEvent(datetime, timestampDesc, message, eventType, sourceShort, sourceLong, dataType, attributes)
}

// FormatBytes formats byte count for human display.
func FormatBytes(b int64) string {
	switch {
	case b >= 1073741824:
		return fmt.Sprintf("%.1fGB", float64(b)/1073741824)
	case b >= 1048576:
		return fmt.Sprintf("%.1fMB", float64(b)/1048576)
	case b >= 1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	}
	return fmt.Sprintf("%dB", b)
}
