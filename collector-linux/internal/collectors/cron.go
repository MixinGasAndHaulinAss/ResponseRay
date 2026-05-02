package collectors

import (
	"io/fs"
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type CronCollector struct{}

func (c *CronCollector) Name() string { return "Cron" }
func (c *CronCollector) Description() string {
	return "/etc/cron*, /var/spool/cron/, anacron, at jobs, systemd timers"
}

func (c *CronCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	roots := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/anacrontab",
		"/var/spool/cron",
		"/var/spool/atjobs",
		"/var/spool/atspool",
		"/var/spool/anacron",
	}
	for _, root := range roots {
		info, err := stat(root)
		if err != nil {
			continue
		}
		if info.IsDir() {
			count := ctx.CaptureGlob(root,
				func(string, fs.FileInfo) bool { return true },
				func(p string) string {
					rel, _ := filepath.Rel(filepath.Dir(root), p)
					return filepath.Join("artifacts/cron", rel)
				},
				"cron")
			r.FilesCollected += count
		} else {
			if ctx.CaptureFile(root, "artifacts/cron/"+filepath.Base(root), "cron") {
				r.FilesCollected++
			}
		}
	}

	if out, err := runCmd("systemctl", "list-timers", "--all", "--no-pager"); err == nil {
		_ = writeText(ctx, "live/systemd_timers.txt", out, "cron")
		r.FilesCollected++
	}
	if out, err := runCmd("atq"); err == nil {
		_ = writeText(ctx, "live/atq.txt", out, "cron")
		r.FilesCollected++
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
