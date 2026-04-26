//go:build linux

package collectors

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
	"github.com/responseray/collector-linux/internal/manifest"
)

// fileEntry returns a JSON-encoded file timeline entry compatible with what the Windows
// FileSystemCollector produces, with platform-specific MACB timestamps from stat_t.
func fileEntry(path string, info fs.FileInfo) string {
	stat, _ := info.Sys().(*syscall.Stat_t)

	entry := map[string]any{
		"path":     path,
		"size":     info.Size(),
		"mode":     info.Mode().String(),
		"is_dir":   info.IsDir(),
		"modified": info.ModTime().UTC().Format(time.RFC3339),
	}
	if stat != nil {
		entry["uid"] = stat.Uid
		entry["gid"] = stat.Gid
		entry["accessed"] = time.Unix(int64(stat.Atim.Sec), int64(stat.Atim.Nsec)).UTC().Format(time.RFC3339)
		entry["changed"] = time.Unix(int64(stat.Ctim.Sec), int64(stat.Ctim.Nsec)).UTC().Format(time.RFC3339)
		entry["inode"] = stat.Ino
		entry["nlink"] = stat.Nlink
	}
	b, _ := json.Marshal(entry)
	return string(b)
}

func mkdirParent(p string) error {
	return os.MkdirAll(filepath.Dir(p), 0o755)
}

func openFile(p string) (*os.File, error) {
	return os.Create(p)
}

func fileSize(p string) (int64, error) {
	info, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// registerFile records an already-written file in the manifest list.
func registerFile(ctx *fsutil.Context, abs, rel, category string, size int64) {
	ctx.Add(manifest.FileEntry{
		OriginalPath: abs,
		RelativePath: filepath.ToSlash(rel),
		Category:     category,
		Size:         size,
	})
}
