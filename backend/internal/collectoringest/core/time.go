package core

import (
	"regexp"
	"strings"
	"time"
)

// The backend ingester (backend/internal/ingest) parses datetime via RFC3339,
// "2006-01-02T15:04:05.000Z", and a couple of fallbacks. We standardize on
// ISO 8601 with millisecond precision in UTC ("2006-01-02T15:04:05.000Z") so
// every emitted event lands in a known-good shape regardless of source.
var (
	reTSWithFrac = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(\d+)(Z|[+-]\d{2}:?\d{2})?`)
	reTSNoFrac   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(Z|[+-]\d{2}:?\d{2})?$`)
)

// NormalizeTimestamp coerces common timestamp string shapes into
// "YYYY-MM-DDTHH:MM:SS.mmmZ" suitable for the events table. Returns "" if the
// input is unparseable.
func NormalizeTimestamp(ts string) string {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return ""
	}
	if m := reTSWithFrac.FindStringSubmatch(ts); m != nil {
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
	if m := reTSNoFrac.FindStringSubmatch(ts); m != nil {
		base := strings.Replace(m[1], " ", "T", 1)
		return base + ".000Z"
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05.000") + "Z"
	}
	return ""
}

// EpochToISO converts a Unix epoch (seconds) to ISO 8601 ms UTC.
func EpochToISO(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// FileMtimeISO returns the modtime of a file in ISO 8601 ms UTC.
func FileMtimeISO(modTime time.Time) string {
	return modTime.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}
