package cache

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ArtifactFile represents a native file written to the artifacts directory.
type ArtifactFile struct {
	Filename string
	Path     string // original Windows path
	DiskPath string // local filesystem path
}

// CollectedFile is a file entry with its content loaded.
type CollectedFile struct {
	Filename   string
	Path       string
	ContentB64 []byte // legacy: raw base64 content
	Content    []byte // legacy: fully decoded binary content
	Context    []byte // legacy: surrounding context
	DiskPath   string // artifact-backed mode: path to native file on disk
}

// Index catalogs collected files for downstream extractors.
// In streaming mode, it wraps an artifacts directory where native files live on disk.
type Index struct {
	ArtifactsDir  string
	ArtifactFiles []ArtifactFile
	FileSize      int64
}

// GetCollectedFiles returns files matching optional filename and path regex patterns.
// Files are resolved from the artifacts directory by matching against the
// original filename and Windows path stored during the streaming scan.
func (idx *Index) GetCollectedFiles(filenamePattern, pathPattern string) ([]CollectedFile, error) {
	var fnRe, pathRe *regexp.Regexp
	if filenamePattern != "" {
		var err error
		fnRe, err = regexp.Compile("(?i)" + filenamePattern)
		if err != nil {
			return nil, err
		}
	}
	if pathPattern != "" {
		var err error
		pathRe, err = regexp.Compile("(?i)" + pathPattern)
		if err != nil {
			return nil, err
		}
	}

	var result []CollectedFile
	for _, af := range idx.ArtifactFiles {
		if fnRe != nil && !fnRe.MatchString(af.Filename) {
			continue
		}
		if pathRe != nil && !pathRe.MatchString(af.Path) {
			continue
		}
		result = append(result, CollectedFile{
			Filename: af.Filename,
			Path:     af.Path,
			DiskPath: af.DiskPath,
		})
	}
	return result, nil
}

// ScanArtifactDir walks the artifacts directory and populates ArtifactFiles
// from existing files on disk. Returns the number of files discovered.
func (idx *Index) ScanArtifactDir() (int, error) {
	if idx.ArtifactsDir == "" {
		return 0, nil
	}
	info, err := os.Stat(idx.ArtifactsDir)
	if err != nil || !info.IsDir() {
		return 0, err
	}
	idx.ArtifactFiles = nil
	err = filepath.Walk(idx.ArtifactsDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(idx.ArtifactsDir, path)
		winPath := strings.ReplaceAll(rel, "/", "\\")
		idx.ArtifactFiles = append(idx.ArtifactFiles, ArtifactFile{
			Filename: fi.Name(),
			Path:     winPath,
			DiskPath: path,
		})
		return nil
	})
	return len(idx.ArtifactFiles), err
}

// GetFileCount returns the count of collected files matching a pattern.
func (idx *Index) GetFileCount(filenamePattern string) int {
	if filenamePattern == "" {
		return len(idx.ArtifactFiles)
	}
	re, err := regexp.Compile("(?i)" + filenamePattern)
	if err != nil {
		return 0
	}
	count := 0
	for _, af := range idx.ArtifactFiles {
		if re.MatchString(af.Filename) {
			count++
		}
	}
	return count
}

