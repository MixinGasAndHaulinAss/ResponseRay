package collectoringest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
)

// Event is a free-form JSON line. Field names match what the backend ingester
// (backend/internal/ingest) reads off each line of timeline.jsonl, plus
// arbitrary extra attributes that get preserved in the events.data column.
type Event map[string]interface{}

// Emitter accumulates events in memory and writes them all out as JSONL at
// the end of a run. Events are deduplicated by (datetime, timestamp_desc,
// message, event_type) so calling AddEvent twice for the same logical event
// is a no-op.
//
// Events are kept in memory because a typical macOS collector produces well
// under 100k timeline events; if that ever changes we can swap this for a
// streaming writer, but right now keeping them in memory means we can preserve
// dedupe semantics without a second pass.
type Emitter struct {
	hostname string
	events   []Event
	seen     map[uint64]struct{}
	stats    map[string]int
}

// NewEmitter constructs an Emitter that stamps every event with the given
// hostname.
func NewEmitter(hostname string) *Emitter {
	return &Emitter{
		hostname: hostname,
		events:   make([]Event, 0, 4096),
		seen:     make(map[uint64]struct{}, 4096),
		stats:    make(map[string]int),
	}
}

// AddEvent appends a normalized timeline event. Returns true if the event was
// added (false if it was a duplicate or lacked a parseable datetime).
//
// The signature matches the ct-to-timesketch Converter.AddEvent so existing
// per-platform parsers can be ported with minimal change.
func (e *Emitter) AddEvent(datetime, timestampDesc, message, eventType, sourceShort, sourceLong, dataType string, attrs map[string]interface{}) bool {
	if datetime == "" {
		return false
	}
	dt := NormalizeTimestamp(datetime)
	if dt == "" {
		return false
	}
	if dataType == "" {
		dataType = "rr:generic:event"
	}

	h := fnv.New64a()
	h.Write([]byte(dt))
	h.Write([]byte{0})
	h.Write([]byte(timestampDesc))
	h.Write([]byte{0})
	h.Write([]byte(message))
	h.Write([]byte{0})
	h.Write([]byte(eventType))
	key := h.Sum64()
	if _, dup := e.seen[key]; dup {
		return false
	}
	e.seen[key] = struct{}{}

	ev := Event{
		"datetime":       dt,
		"timestamp_desc": timestampDesc,
		"message":        message,
		"data_type":      dataType,
		"event_type":     eventType,
		"source_short":   sourceShort,
		"source_long":    sourceLong,
		"host_name":      e.hostname,
	}
	for k, v := range attrs {
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		ev[k] = v
	}
	e.events = append(e.events, ev)
	e.stats[eventType]++
	return true
}

// Count returns the total number of unique events accumulated.
func (e *Emitter) Count() int { return len(e.events) }

// CountByType returns the per-event-type counter.
func (e *Emitter) CountByType(eventType string) int { return e.stats[eventType] }

// Stats returns a copy of the per-event-type counters.
func (e *Emitter) Stats() map[string]int {
	out := make(map[string]int, len(e.stats))
	for k, v := range e.stats {
		out[k] = v
	}
	return out
}

// WriteJSONL serializes all accumulated events to the given file path, one
// JSON object per line.
func (e *Emitter) WriteJSONL(path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 4*1024*1024)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for _, ev := range e.events {
		if err := enc.Encode(ev); err != nil {
			return 0, fmt.Errorf("encode event: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return 0, fmt.Errorf("flush: %w", err)
	}
	return len(e.events), nil
}

// copyAttrs returns a shallow copy of an attribute map. Used by parsers that
// want to emit the same event under two different (datetime, timestamp_desc)
// pairs (e.g. file mtime AND collection time) without aliasing the map.
func copyAttrs(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
