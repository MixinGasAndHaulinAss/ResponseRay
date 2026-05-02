package collectors

import (
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type PersistenceCollector struct{}

func (c *PersistenceCollector) Name() string { return "Persistence" }
func (c *PersistenceCollector) Description() string {
	return "Autostart locations: rc.local, init.d, .bashrc, profile.d, autostart desktop entries, ld.so.preload"
}

func (c *PersistenceCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	system := []string{
		"/etc/rc.local",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/zsh/zshenv",
		"/etc/zsh/zprofile",
		"/etc/zsh/zshrc",
		"/etc/zsh/zlogin",
		"/etc/zsh/zlogout",
		"/etc/csh.cshrc",
		"/etc/csh.login",
		"/etc/skel/.bashrc",
		"/etc/skel/.profile",
		"/etc/skel/.bash_profile",
		"/etc/ld.so.conf",
		"/etc/ld.so.preload",
		"/etc/profile.d",
		"/etc/xdg/autostart",
		"/etc/X11/xinit/xinitrc",
		"/etc/inittab",
	}
	for _, f := range system {
		info, err := stat(f)
		if err != nil {
			continue
		}
		if info.IsDir() {
			ctx.CaptureGlob(f, nil,
				func(p string) string {
					rel, _ := filepath.Rel(filepath.Dir(f), p)
					return filepath.Join("artifacts/persistence", rel)
				}, "persistence")
		} else {
			ctx.CaptureFile(f, "artifacts/persistence/"+filepath.Base(f), "persistence")
			r.FilesCollected++
		}
	}

	dotfiles := []string{
		".bashrc", ".bash_profile", ".bash_logout", ".bash_login",
		".profile", ".zshrc", ".zprofile", ".zlogin",
		".cshrc", ".tcshrc", ".kshrc",
		".vimrc", ".tmux.conf", ".screenrc",
		".gitconfig",
	}
	for _, h := range userHomes() {
		for _, df := range dotfiles {
			if ctx.CaptureFile(filepath.Join(h.Home, df),
				filepath.Join("artifacts/persistence/users", h.User, df), "persistence") {
				r.FilesCollected++
			}
		}

		autostart := filepath.Join(h.Home, ".config/autostart")
		ctx.CaptureGlob(autostart, nil,
			func(p string) string {
				rel, _ := filepath.Rel(autostart, p)
				return filepath.Join("artifacts/persistence/users", h.User, "autostart", rel)
			}, "persistence")
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
