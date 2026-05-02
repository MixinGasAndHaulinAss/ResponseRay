package collectors

import (
	"io/fs"
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type SystemdCollector struct{}

func (c *SystemdCollector) Name() string { return "Systemd" }
func (c *SystemdCollector) Description() string {
	return "Service unit files, drop-ins, enabled services, list-units output"
}

func (c *SystemdCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	roots := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/run/systemd/system",
		"/etc/init.d",
		"/etc/init",
		"/etc/rc.d",
	}
	for _, root := range roots {
		count := ctx.CaptureGlob(root,
			func(p string, info fs.FileInfo) bool {
				if info.Size() > 5*1024*1024 {
					return false
				}
				return true
			},
			func(p string) string {
				rel, _ := filepath.Rel(filepath.Dir(root), p)
				return filepath.Join("artifacts/systemd", rel)
			},
			"systemd")
		r.FilesCollected += count
	}

	for _, h := range userHomes() {
		root := filepath.Join(h.Home, ".config/systemd")
		count := ctx.CaptureGlob(root,
			func(string, fs.FileInfo) bool { return true },
			func(p string) string {
				rel, _ := filepath.Rel(root, p)
				return filepath.Join("artifacts/systemd/user-units", h.User, rel)
			},
			"systemd")
		r.FilesCollected += count
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"list-units", []string{"systemctl", "list-units", "--all", "--no-pager", "--no-legend"}},
		{"list-unit-files", []string{"systemctl", "list-unit-files", "--no-pager", "--no-legend"}},
		{"failed", []string{"systemctl", "--failed", "--no-pager"}},
		{"enabled", []string{"systemctl", "list-unit-files", "--state=enabled", "--no-pager"}},
		{"running", []string{"systemctl", "list-units", "--state=running", "--no-pager"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/systemctl_"+c.name+".txt", out, "systemd")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
