package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// ApplicationLogsCollector grabs known application log directories (Adobe, Microsoft, Zoom, Slack, Teams, etc.).
type ApplicationLogsCollector struct{}

func (ApplicationLogsCollector) Name() string { return "ApplicationLogs" }

type appLogTarget struct {
	relativeFromHome string
	category         string
}

func (ApplicationLogsCollector) Run(ctx *fsutil.Context) error {
	systemRoots := []struct {
		path     string
		category string
	}{
		{"/Library/Logs", "system_app_logs"},
		{"/private/var/log/com.apple.xpc.launchd", "launchd_logs"},
	}
	for _, r := range systemRoots {
		ctx.CaptureGlob(r.path,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(filepath.Base(path))
				return (strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".gz")) &&
					info.Size() < 100*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/app_logs", rel)
			},
			r.category,
		)
	}

	for _, home := range userHomes() {
		user := usernameFromHome(home)
		root := filepath.Join(home, "Library", "Logs")
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(filepath.Base(path))
				return (strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".ips")) &&
					info.Size() < 100*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel(root, path)
				return filepath.Join("artifacts/app_logs/users", user, rel)
			},
			"user_app_logs",
		)
	}
	return nil
}
