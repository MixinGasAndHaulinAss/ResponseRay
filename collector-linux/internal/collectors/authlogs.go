package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// AuthLogCollector captures /var/log/auth.log, secure, lastlog, wtmp, btmp, faillog, journal exports.
type AuthLogCollector struct{}

func (c *AuthLogCollector) Name() string        { return "AuthLogs" }
func (c *AuthLogCollector) Description() string { return "Authentication logs: auth.log, secure, wtmp, btmp, lastlog, journal" }

func (c *AuthLogCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	directFiles := []string{
		"/var/log/wtmp",
		"/var/log/btmp",
		"/var/log/lastlog",
		"/var/log/faillog",
		"/var/log/tallylog",
		"/var/log/sudo.log",
	}
	for _, f := range directFiles {
		if ctx.CaptureFile(f, "artifacts/auth/"+filepath.Base(f), "auth_log") {
			r.FilesCollected++
		}
	}

	logRoots := []string{"/var/log"}
	prefixes := []string{"auth.log", "secure", "audit", "kerberos.log", "sudo.log"}

	for _, root := range logRoots {
		count := ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				name := filepath.Base(path)
				for _, p := range prefixes {
					if strings.HasPrefix(name, p) {
						return true
					}
				}
				return false
			},
			func(path string) string {
				rel, _ := filepath.Rel(root, path)
				return filepath.Join("artifacts/auth", rel)
			},
			"auth_log",
		)
		r.FilesCollected += count
	}

	if out, err := runCmd("journalctl", "-u", "ssh.service", "--no-pager", "-o", "short-iso"); err == nil {
		dest := "live/journal_ssh.txt"
		_ = writeText(ctx, dest, out, "auth_log")
		r.FilesCollected++
	}
	if out, err := runCmd("journalctl", "_COMM=sshd", "--no-pager", "-o", "json"); err == nil {
		dest := "live/journal_sshd.jsonl"
		_ = writeText(ctx, dest, out, "auth_log")
		r.FilesCollected++
	}
	if out, err := runCmd("last", "-Fwx"); err == nil {
		_ = writeText(ctx, "live/last.txt", out, "auth_log")
		r.FilesCollected++
	}
	if out, err := runCmd("lastb", "-Fwx"); err == nil {
		_ = writeText(ctx, "live/lastb.txt", out, "auth_log")
		r.FilesCollected++
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
