package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// PersistenceCollector grabs cron tabs, periodic, at jobs, login/logout hooks,
// kernel extensions metadata, and system extensions plists.
type PersistenceCollector struct{}

func (PersistenceCollector) Name() string { return "Persistence" }

func (PersistenceCollector) Run(ctx *fsutil.Context) error {
	dirs := []string{
		"/etc/periodic",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/at",
		"/usr/lib/cron/tabs",
		"/var/cron/tabs",
	}
	for _, d := range dirs {
		ctx.CaptureGlob(d,
			func(path string, info fs.FileInfo) bool { return info.Size() < 4*1024*1024 },
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/persistence", rel)
			},
			"persistence",
		)
	}

	files := []string{
		"/etc/crontab",
		"/etc/launchd.conf",
		"/etc/rc.common",
		"/etc/rc.local",
		"/etc/profile",
		"/etc/zshrc",
		"/etc/bashrc",
		"/etc/zprofile",
		"/etc/zshenv",
		"/etc/csh.cshrc",
		"/etc/csh.login",
		"/etc/csh.logout",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/persistence", strings.TrimPrefix(f, "/")), "persistence")
	}

	// Per-user shell init.
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		userInits := []string{".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
			".zshrc", ".zprofile", ".zlogin", ".zlogout", ".zshenv",
			".profile", ".cshrc", ".login", ".logout", ".tcshrc", ".inputrc"}
		for _, name := range userInits {
			src := filepath.Join(home, name)
			ctx.CaptureFile(src, filepath.Join("artifacts/persistence/users", user, name), "persistence")
		}
		// Login hooks.
		ctx.CaptureFile(filepath.Join(home, "Library", "Preferences", "com.apple.loginwindow.plist"),
			filepath.Join("artifacts/persistence/users", user, "com.apple.loginwindow.plist"), "persistence")
	}

	// Kernel extensions and system extensions metadata only (binaries skipped to keep size sane).
	ctx.CaptureGlob("/Library/Extensions",
		func(path string, info fs.FileInfo) bool {
			lower := strings.ToLower(path)
			return strings.HasSuffix(lower, "info.plist") && info.Size() < 1*1024*1024
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/persistence", rel)
		},
		"kext",
	)
	ctx.CaptureGlob("/Library/SystemExtensions",
		func(path string, info fs.FileInfo) bool { return strings.HasSuffix(path, ".plist") && info.Size() < 1*1024*1024 },
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/persistence", rel)
		},
		"system_extension",
	)
	return nil
}
