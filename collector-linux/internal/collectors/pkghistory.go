package collectors

import (
	"io/fs"
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// PkgHistoryCollector captures package manager history and repository sources.
// Covers APT, YUM, DNF sources and history logs for forensic analysis.
type PkgHistoryCollector struct{}

func (c *PkgHistoryCollector) Name() string { return "PkgHistory" }
func (c *PkgHistoryCollector) Description() string {
	return "Package manager history and sources (APT, YUM, DNF)"
}

func (c *PkgHistoryCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	// APT sources
	aptSources := []string{
		"/etc/apt/sources.list",
	}
	for _, f := range aptSources {
		if ctx.CaptureFile(f, "artifacts/pkg_sources/apt/"+filepath.Base(f), "pkg_sources") {
			r.FilesCollected++
		}
	}

	// APT sources.list.d
	if info, err := stat("/etc/apt/sources.list.d"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/apt/sources.list.d", nil,
			func(p string) string {
				return "artifacts/pkg_sources/apt/sources.list.d/" + filepath.Base(p)
			}, "pkg_sources")
		r.FilesCollected += count
	}

	// APT preferences
	if ctx.CaptureFile("/etc/apt/preferences", "artifacts/pkg_sources/apt/preferences", "pkg_sources") {
		r.FilesCollected++
	}
	if info, err := stat("/etc/apt/preferences.d"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/apt/preferences.d", nil,
			func(p string) string {
				return "artifacts/pkg_sources/apt/preferences.d/" + filepath.Base(p)
			}, "pkg_sources")
		r.FilesCollected += count
	}

	// APT history logs (detailed install/remove history)
	if info, err := stat("/var/log/apt"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/var/log/apt",
			func(p string, info fs.FileInfo) bool {
				return info.Size() < fsutil.MaxSingleFileBytes
			},
			func(p string) string {
				rel, _ := filepath.Rel("/var/log/apt", p)
				return "artifacts/pkg_history/apt/" + rel
			}, "pkg_history")
		r.FilesCollected += count
	}

	// DPKG log
	if ctx.CaptureFile("/var/log/dpkg.log", "artifacts/pkg_history/dpkg.log", "pkg_history") {
		r.FilesCollected++
	}

	// YUM repos
	if info, err := stat("/etc/yum.repos.d"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/yum.repos.d", nil,
			func(p string) string {
				return "artifacts/pkg_sources/yum/" + filepath.Base(p)
			}, "pkg_sources")
		r.FilesCollected += count
	}
	if ctx.CaptureFile("/etc/yum.conf", "artifacts/pkg_sources/yum/yum.conf", "pkg_sources") {
		r.FilesCollected++
	}

	// DNF repos (often symlinked to yum.repos.d, but can be separate)
	if info, err := stat("/etc/dnf"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/dnf",
			func(p string, info fs.FileInfo) bool {
				return !info.IsDir() && info.Size() < fsutil.MaxSingleFileBytes
			},
			func(p string) string {
				rel, _ := filepath.Rel("/etc/dnf", p)
				return "artifacts/pkg_sources/dnf/" + rel
			}, "pkg_sources")
		r.FilesCollected += count
	}

	// YUM/DNF history via commands
	for _, cmd := range []struct {
		name string
		args []string
	}{
		{"yum_history", []string{"yum", "history", "list", "all"}},
		{"dnf_history", []string{"dnf", "history", "list", "--all"}},
		{"apt_history", []string{"apt-get", "changelog", "--print-uris"}},
		{"zypper_history", []string{"zypper", "history"}},
	} {
		if out, err := runCmd(cmd.args...); err == nil && len(out) > 0 {
			_ = writeText(ctx, "live/pkg_"+cmd.name+".txt", out, "pkg_history")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
