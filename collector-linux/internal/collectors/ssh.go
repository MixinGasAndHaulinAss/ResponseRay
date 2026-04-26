package collectors

import (
	"io/fs"
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type SSHCollector struct{}

func (c *SSHCollector) Name() string        { return "SSH" }
func (c *SSHCollector) Description() string { return "sshd_config, ssh_config, host keys, per-user authorized_keys, known_hosts, ssh config" }

func (c *SSHCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	system := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/ssh/sshd_config.d",
		"/etc/ssh/ssh_config.d",
	}
	for _, s := range system {
		if info, err := stat(s); err == nil {
			if info.IsDir() {
				count := ctx.CaptureGlob(s,
					func(string, fs.FileInfo) bool { return true },
					func(p string) string {
						rel, _ := filepath.Rel("/etc/ssh", p)
						return filepath.Join("artifacts/ssh/system", rel)
					},
					"ssh")
				r.FilesCollected += count
			} else {
				if ctx.CaptureFile(s, "artifacts/ssh/system/"+filepath.Base(s), "ssh") {
					r.FilesCollected++
				}
			}
		}
	}

	hostKeys := []string{
		"/etc/ssh/ssh_host_rsa_key.pub",
		"/etc/ssh/ssh_host_dsa_key.pub",
		"/etc/ssh/ssh_host_ecdsa_key.pub",
		"/etc/ssh/ssh_host_ed25519_key.pub",
		"/etc/ssh/moduli",
	}
	for _, k := range hostKeys {
		if ctx.CaptureFile(k, "artifacts/ssh/system/"+filepath.Base(k), "ssh") {
			r.FilesCollected++
		}
	}

	for _, h := range userHomes() {
		userSshDir := filepath.Join(h.Home, ".ssh")
		count := ctx.CaptureGlob(userSshDir,
			func(path string, info fs.FileInfo) bool {
				name := filepath.Base(path)
				return name == "authorized_keys" || name == "authorized_keys2" ||
					name == "known_hosts" || name == "known_hosts2" || name == "config" ||
					name == "environment" ||
					filepath.Ext(name) == ".pub"
			},
			func(path string) string {
				rel, _ := filepath.Rel(userSshDir, path)
				return filepath.Join("artifacts/ssh/users", h.User, rel)
			},
			"ssh",
		)
		r.FilesCollected += count
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

func stat(p string) (fs.FileInfo, error) {
	return statFn(p)
}
