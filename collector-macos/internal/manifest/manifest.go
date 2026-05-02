package manifest

import (
	"encoding/json"
	"os"
)

type Manifest struct {
	CollectorVersion          string            `json:"collector_version"`
	Platform                  string            `json:"platform"`
	Hostname                  string            `json:"hostname"`
	OsVersion                 string            `json:"os_version"`
	Domain                    string            `json:"domain"`
	CollectionTimestamp       string            `json:"collection_timestamp"`
	CollectionDurationSeconds float64           `json:"collection_duration_seconds"`
	UserProfiles              []string          `json:"user_profiles"`
	TotalFiles                int               `json:"total_files"`
	TotalBytes                int64             `json:"total_bytes"`
	CollectorResults          []CollectorResult `json:"collector_results"`
	Files                     []FileEntry       `json:"files"`
}

type CollectorResult struct {
	Name           string `json:"name"`
	FilesCollected int    `json:"files_collected"`
	BytesCollected int64  `json:"bytes_collected"`
	ElapsedMs      int64  `json:"elapsed_ms"`
	Error          string `json:"error,omitempty"`
}

type FileEntry struct {
	OriginalPath string `json:"original_path"`
	RelativePath string `json:"relative_path"`
	Category     string `json:"category"`
	Size         int64  `json:"size"`
}

func (m *Manifest) Save(path string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
