package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// MemoryCollector is opt-in (--include-memory). It captures swap/sleep image files;
// macOS makes /dev/mem and /dev/kmem unavailable to user space, so live RAM
// imaging requires a kernel extension which we deliberately do not bundle here.
type MemoryCollector struct{}

func (MemoryCollector) Name() string { return "MemoryArtifacts" }

func (MemoryCollector) Run(ctx *fsutil.Context) error {
	if !ctx.IncludeMem {
		return nil
	}
	files := []string{
		"/private/var/vm/sleepimage",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/memory", filepath.Base(f)), "memory")
	}
	ctx.CaptureGlob("/private/var/vm",
		func(path string, info fs.FileInfo) bool {
			lower := strings.ToLower(filepath.Base(path))
			return strings.HasPrefix(lower, "swapfile") && info.Size() < fsutil.MaxSingleFileBytes
		},
		func(path string) string {
			return filepath.Join("artifacts/memory", filepath.Base(path))
		},
		"memory_swap",
	)
	return nil
}
