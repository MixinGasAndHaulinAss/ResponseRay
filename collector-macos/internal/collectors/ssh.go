package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type SSHCollector struct{}

func (SSHCollector) Name() string { return "SSH" }

func (SSHCollector) Run(ctx *fsutil.Context) error {
	systemFiles := []string{
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/ssh/ssh_known_hosts",
	}
	for _, f := range systemFiles {
		ctx.CaptureFile(f, filepath.Join("artifacts/ssh/system", filepath.Base(f)), "ssh")
	}
	ctx.CaptureGlob("/etc/ssh/sshd_config.d",
		func(path string, info fs.FileInfo) bool { return strings.HasSuffix(strings.ToLower(path), ".conf") },
		func(path string) string {
			rel, _ := filepath.Rel("/etc/ssh", path)
			return filepath.Join("artifacts/ssh/system", rel)
		},
		"ssh",
	)

	homes := append([]string{"/var/root"}, userHomes()...)
	userFiles := []string{"authorized_keys", "known_hosts", "config", "id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_dsa.pub"}
	for _, home := range homes {
		user := usernameFromHome(home)
		for _, name := range userFiles {
			src := filepath.Join(home, ".ssh", name)
			rel := filepath.Join("artifacts/ssh/users", user, name)
			ctx.CaptureFile(src, rel, "ssh")
		}
	}
	return nil
}
