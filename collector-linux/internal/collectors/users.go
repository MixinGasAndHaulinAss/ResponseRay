package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type UserCollector struct{}

func (c *UserCollector) Name() string        { return "Users" }
func (c *UserCollector) Description() string { return "/etc/passwd, /etc/shadow (hashes redacted ok), /etc/group, /etc/sudoers, sudoers.d" }

func (c *UserCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	files := []string{
		"/etc/passwd",
		"/etc/passwd-",
		"/etc/group",
		"/etc/group-",
		"/etc/shadow",
		"/etc/shadow-",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/login.defs",
		"/etc/security/access.conf",
		"/etc/security/limits.conf",
		"/etc/pam.d",
	}
	for _, f := range files {
		if info, err := stat(f); err == nil {
			if info.IsDir() {
				ctx.CaptureGlob(f, nil, func(p string) string { return "artifacts/users/" + p[1:] }, "users")
				r.FilesCollected++
			} else {
				if ctx.CaptureFile(f, "artifacts/users/"+f[1:], "users") {
					r.FilesCollected++
				}
			}
		}
	}

	if info, err := stat("/etc/sudoers.d"); err == nil && info.IsDir() {
		ctx.CaptureGlob("/etc/sudoers.d", nil, func(p string) string { return "artifacts/users/sudoers.d/" + p[len("/etc/sudoers.d/"):] }, "users")
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

type LogonCollector struct{}

func (c *LogonCollector) Name() string        { return "Logons" }
func (c *LogonCollector) Description() string { return "who, w, last, lastlog, current sessions" }

func (c *LogonCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"who_-a", []string{"who", "-a"}},
		{"w", []string{"w"}},
		{"lastlog", []string{"lastlog"}},
		{"last_-Fxw", []string{"last", "-Fxw"}},
		{"loginctl_list-sessions", []string{"loginctl", "list-sessions"}},
		{"loginctl_list-users", []string{"loginctl", "list-users"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/logons_"+c.name+".txt", out, "logons")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
