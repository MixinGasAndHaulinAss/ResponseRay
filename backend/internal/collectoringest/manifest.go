// Package collectoringest converts a ResponseRay Collector output directory
// (macOS / Linux / ESXi for now) directly into the timeline.jsonl format the
// existing backend ingester consumes. It is the in-process replacement for
// piping our own collector archives through ct-to-timesketch.
//
// ct-to-timesketch is intentionally not imported from here -- that tool's job
// is converting CyberTriage CT captures, not parsing ResponseRay-native
// collector output.
package collectoringest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest mirrors the manifest.json written by every ResponseRay collector.
// Only the fields we use during ingestion are decoded; the rest is ignored.
type Manifest struct {
	CollectorVersion          string  `json:"collector_version"`
	Platform                  string  `json:"platform,omitempty"`
	Hostname                  string  `json:"hostname"`
	OsVersion                 string  `json:"os_version"`
	Domain                    string  `json:"domain"`
	CollectionTimestamp       string  `json:"collection_timestamp"`
	CollectionDurationSeconds float64 `json:"collection_duration_seconds"`
}

// ParseManifest reads manifest.json from a collector output directory.
func ParseManifest(dirPath string) (*Manifest, error) {
	p := filepath.Join(dirPath, "manifest.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest.json: %w", err)
	}
	if m.Hostname == "" {
		m.Hostname = "unknown"
	}
	return &m, nil
}
