package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// SystemLogCollector grabs /var/log non-binary log trees plus journald exports.
type SystemLogCollector struct{}

func (c *SystemLogCollector) Name() string { return "SystemLogs" }
func (c *SystemLogCollector) Description() string {
	return "Generic /var/log files (syslog, messages, dmesg, kern, dpkg, yum, etc.) and journald"
}

func (c *SystemLogCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	skipDirs := []string{"/var/log/journal"}
	count := ctx.CaptureGlob("/var/log",
		func(path string, info fs.FileInfo) bool {
			if info.Size() > fsutil.MaxSingleFileBytes {
				return false
			}
			for _, sd := range skipDirs {
				if strings.HasPrefix(path, sd) {
					return false
				}
			}
			name := strings.ToLower(filepath.Base(path))
			if strings.HasSuffix(name, ".log") || strings.Contains(name, "syslog") ||
				strings.Contains(name, "messages") || strings.Contains(name, "dmesg") ||
				strings.Contains(name, "boot") || strings.Contains(name, "kern") ||
				strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".xz") ||
				strings.Contains(name, "yum") || strings.Contains(name, "dnf") ||
				strings.Contains(name, "apt") || strings.Contains(name, "dpkg") ||
				strings.Contains(name, "Xorg") {
				return true
			}
			return false
		},
		func(path string) string {
			rel, _ := filepath.Rel("/var/log", path)
			return filepath.Join("artifacts/syslog", rel)
		},
		"syslog",
	)
	r.FilesCollected += count

	if out, err := runCmd("journalctl", "--no-pager", "-o", "json", "--since", "30 days ago"); err == nil {
		_ = writeText(ctx, "live/journal_30d.jsonl", out, "syslog")
		r.FilesCollected++
	}
	if out, err := runCmd("dmesg", "-T"); err == nil {
		_ = writeText(ctx, "live/dmesg.txt", out, "syslog")
		r.FilesCollected++
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
