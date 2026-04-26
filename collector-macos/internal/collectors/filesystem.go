//go:build darwin

package collectors

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
	"github.com/responseray/collector-macos/internal/manifest"
)

// FileSystemCollector walks several high-value directories and emits a
// JSON file timeline (path, sizes, mtime/atime/ctime, mode, uid/gid).
type FileSystemCollector struct{}

func (FileSystemCollector) Name() string { return "FileSystemEnum" }

type fileEntry struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	MTime string `json:"mtime"`
	ATime string `json:"atime"`
	CTime string `json:"ctime"`
	BTime string `json:"btime,omitempty"`
}

func (FileSystemCollector) Run(ctx *fsutil.Context) error {
	roots := []string{
		"/private/etc",
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/usr/local/bin",
		"/usr/local/sbin",
		"/Applications",
		"/Library/Application Support",
		"/private/var/log",
		"/private/var/db",
		"/private/var/tmp",
		"/tmp",
	}
	for _, home := range userHomes() {
		roots = append(roots, home)
	}

	excludePrefixes := []string{
		"/System/Library/Caches",
		"/Library/Caches",
		"/private/var/folders",
		"/Volumes",
		"/private/var/db/uuidtext",
		"/private/var/db/diagnostics",
	}

	dest := filepath.Join(ctx.OutputDir, "live/filesystem_timeline.ndjson")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	count := 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) {
					return nil
				}
				return nil
			}
			for _, p := range excludePrefixes {
				if strings.HasPrefix(path, p) {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
			if d.IsDir() {
				return nil
			}
			info, ferr := d.Info()
			if ferr != nil {
				return nil
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			fe := fileEntry{
				Path:  path,
				Size:  info.Size(),
				Mode:  info.Mode().String(),
				UID:   st.Uid,
				GID:   st.Gid,
				MTime: time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec).UTC().Format(time.RFC3339Nano),
				ATime: time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec).UTC().Format(time.RFC3339Nano),
				CTime: time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UTC().Format(time.RFC3339Nano),
				BTime: time.Unix(st.Birthtimespec.Sec, st.Birthtimespec.Nsec).UTC().Format(time.RFC3339Nano),
			}
			_ = enc.Encode(fe)
			count++
			return nil
		})
	}
	if info, err := os.Stat(dest); err == nil {
		ctx.Add(manifest.FileEntry{
			OriginalPath: dest,
			RelativePath: "live/filesystem_timeline.ndjson",
			Category:     "filesystem_timeline",
			Size:         info.Size(),
		})
	}
	return nil
}
