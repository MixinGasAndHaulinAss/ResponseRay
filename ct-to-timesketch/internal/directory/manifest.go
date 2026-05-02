package directory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Manifest represents the collector's manifest.json output.
//
// Platform/VssUsed/VssPath are added in 2026.4.26.1 to support cross-platform
// collections (windows, linux, macos, esxi). They are optional for backwards
// compatibility with older Windows-only manifests.
type Manifest struct {
	CollectorVersion          string            `json:"collector_version"`
	Platform                  string            `json:"platform,omitempty"`
	Hostname                  string            `json:"hostname"`
	OsVersion                 string            `json:"os_version"`
	Domain                    string            `json:"domain"`
	CollectionTimestamp       string            `json:"collection_timestamp"`
	CollectionDurationSeconds float64           `json:"collection_duration_seconds"`
	UserProfiles              []string          `json:"user_profiles"`
	TotalFiles                int               `json:"total_files"`
	TotalBytes                int64             `json:"total_bytes"`
	VssUsed                   bool              `json:"vss_used,omitempty"`
	VssPath                   string            `json:"vss_path,omitempty"`
	CollectorResults          []CollectorResult `json:"collector_results"`
	Files                     []FileEntry       `json:"files"`
}

// CollectorResult holds the result of a single collector module.
type CollectorResult struct {
	Name           string `json:"name"`
	FilesCollected int    `json:"files_collected"`
	BytesCollected int64  `json:"bytes_collected"`
	ElapsedMs      int64  `json:"elapsed_ms"`
	Error          string `json:"error,omitempty"`
}

// FileEntry describes a single collected file.
type FileEntry struct {
	OriginalPath string `json:"original_path"`
	RelativePath string `json:"relative_path"`
	Category     string `json:"category"`
	Size         int64  `json:"size"`
}

// ParseManifest reads and parses a manifest.json file from the collector output directory.
func ParseManifest(dirPath string) (*Manifest, error) {
	manifestPath := filepath.Join(dirPath, "manifest.json")
	data, err := os.ReadFile(manifestPath)
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
	if m.Platform == "" {
		m.Platform = "windows"
	}

	return &m, nil
}
