package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// FileSystemCollector enumerates the root filesystem and writes a JSONL of MACB timestamps,
// matching what FileSystemCollector does on Windows. The walk skips pseudo-filesystems and
// (by default) the user's home media to keep size manageable.
type FileSystemCollector struct{}

func (c *FileSystemCollector) Name() string { return "FileSystem" }
func (c *FileSystemCollector) Description() string {
	return "Recursive walk of / with MACB timestamps written to JSONL"
}

var skipRoots = []string{
	"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
	"/var/cache", "/var/lib/docker/overlay2", "/var/lib/containers",
	"/snap", "/var/lib/snapd",
}

func (c *FileSystemCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	dest := filepath.Join(ctx.OutputDir, "live/filesystem.jsonl")
	if err := mkdirParent(dest); err != nil {
		r.Error = err.Error()
		return r
	}
	f, err := openFile(dest)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer f.Close()

	count := 0
	_ = filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		for _, skip := range skipRoots {
			if path == skip || strings.HasPrefix(path, skip+"/") {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}

		info, ferr := d.Info()
		if ferr != nil {
			return nil
		}

		entry := fileEntry(path, info)
		f.WriteString(entry)
		f.WriteString("\n")
		count++
		return nil
	})

	if size, err := fileSize(dest); err == nil {
		r.FilesCollected = count
		r.BytesCollected = size
		registerFile(ctx, dest, "live/filesystem.jsonl", "file_timeline", size)
	}

	r.Elapsed = time.Since(start)
	return r
}

type MemoryCollector struct{}

func (c *MemoryCollector) Name() string { return "Memory" }
func (c *MemoryCollector) Description() string {
	return "/proc/kcore, /proc/iomem, swap files (--include-memory)"
}

func (c *MemoryCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	if !ctx.IncludeMem {
		return r
	}

	if ctx.CaptureFile("/proc/iomem", "artifacts/memory/iomem", "memory") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/proc/meminfo", "artifacts/memory/meminfo", "memory") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/proc/swaps", "artifacts/memory/swaps", "memory") {
		r.FilesCollected++
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
