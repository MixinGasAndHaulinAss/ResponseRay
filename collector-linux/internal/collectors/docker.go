package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type DockerCollector struct{}

func (c *DockerCollector) Name() string        { return "Docker" }
func (c *DockerCollector) Description() string { return "Docker container/image inventory if dockerd is installed" }

func (c *DockerCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	for _, cmd := range []struct {
		name string
		args []string
	}{
		{"version", []string{"docker", "version", "--format", "json"}},
		{"info", []string{"docker", "info", "--format", "json"}},
		{"ps_-a", []string{"docker", "ps", "-a", "--no-trunc", "--format", "json"}},
		{"images", []string{"docker", "images", "-a", "--no-trunc", "--format", "json"}},
		{"network_ls", []string{"docker", "network", "ls", "--format", "json"}},
		{"volume_ls", []string{"docker", "volume", "ls", "--format", "json"}},
		{"podman_ps_-a", []string{"podman", "ps", "-a", "--format", "json"}},
		{"crictl_pods", []string{"crictl", "pods"}},
	} {
		if out, err := runCmd(cmd.args...); err == nil {
			_ = writeText(ctx, "live/docker_"+cmd.name+".json", out, "docker")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

type AuditdCollector struct{}

func (c *AuditdCollector) Name() string        { return "Auditd" }
func (c *AuditdCollector) Description() string { return "auditd rules, /var/log/audit/audit.log*, ausearch summaries" }

func (c *AuditdCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	files := []string{
		"/etc/audit/auditd.conf",
		"/etc/audit/rules.d",
		"/etc/audit/audit.rules",
	}
	for _, f := range files {
		info, err := stat(f)
		if err != nil {
			continue
		}
		if info.IsDir() {
			ctx.CaptureGlob(f, nil, func(p string) string { return "artifacts/auditd" + p }, "auditd")
		} else {
			ctx.CaptureFile(f, "artifacts/auditd"+f, "auditd")
			r.FilesCollected++
		}
	}

	if out, err := runCmd("auditctl", "-l"); err == nil {
		_ = writeText(ctx, "live/auditctl_-l.txt", out, "auditd")
		r.FilesCollected++
	}
	if out, err := runCmd("aureport", "--summary"); err == nil {
		_ = writeText(ctx, "live/aureport_summary.txt", out, "auditd")
		r.FilesCollected++
	}

	count := ctx.CaptureGlob("/var/log/audit", nil,
		func(p string) string { return "artifacts/auditd/log/" + p[len("/var/log/audit/"):] }, "auditd")
	r.FilesCollected += count

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
