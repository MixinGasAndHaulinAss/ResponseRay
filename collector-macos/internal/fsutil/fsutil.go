// Package fsutil contains shared file-copy and JSON-write helpers for the macOS collector.
package fsutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/responseray/collector-macos/internal/manifest"
)

const MaxSingleFileBytes = 500 * 1024 * 1024

type Context struct {
	OutputDir   string
	Hostname    string
	IncludeMem  bool
	mu          sync.Mutex
	files       []manifest.FileEntry
	totalBytes  int64
}

func NewContext(outputDir, hostname string, includeMem bool) *Context {
	return &Context{OutputDir: outputDir, Hostname: hostname, IncludeMem: includeMem}
}

func (c *Context) Files() []manifest.FileEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]manifest.FileEntry, len(c.files))
	copy(out, c.files)
	return out
}

func (c *Context) TotalBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalBytes
}

func (c *Context) Add(entry manifest.FileEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files = append(c.files, entry)
	c.totalBytes += entry.Size
}

func (c *Context) CaptureFile(srcPath, relPath, category string) bool {
	info, err := os.Stat(srcPath)
	if err != nil || info.IsDir() {
		return false
	}
	if info.Size() > MaxSingleFileBytes {
		return false
	}
	dest := filepath.Join(c.OutputDir, relPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return false
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return false
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return false
	}
	defer out.Close()
	written, err := io.Copy(out, in)
	if err != nil || written == 0 {
		os.Remove(dest)
		return false
	}
	c.Add(manifest.FileEntry{
		OriginalPath: srcPath,
		RelativePath: filepath.ToSlash(relPath),
		Category:     category,
		Size:         written,
	})
	return true
}

func (c *Context) CaptureGlob(rootDir string, predicate func(path string, info fs.FileInfo) bool,
	relPathFor func(path string) string, category string) (count int) {
	if _, err := os.Stat(rootDir); err != nil {
		return 0
	}
	_ = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ferr := d.Info()
		if ferr != nil {
			return nil
		}
		if predicate != nil && !predicate(path, info) {
			return nil
		}
		rel := relPathFor(path)
		if c.CaptureFile(path, rel, category) {
			count++
		}
		return nil
	})
	return count
}

func (c *Context) WriteJSON(relPath, category string, value interface{}) (int64, error) {
	dest := filepath.Join(c.OutputDir, relPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	f, err := os.Create(dest)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return 0, err
	}
	info, err := os.Stat(dest)
	if err != nil {
		return 0, err
	}
	c.Add(manifest.FileEntry{
		OriginalPath: dest,
		RelativePath: filepath.ToSlash(relPath),
		Category:     category,
		Size:         info.Size(),
	})
	return info.Size(), nil
}

func FormatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	suffix := []string{"KB", "MB", "GB", "TB"}[exp]
	return fmt.Sprintf("%.1f %s", float64(n)/float64(div), suffix)
}
