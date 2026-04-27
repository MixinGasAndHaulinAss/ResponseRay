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
	logSuffix := func(path string) bool {
		lower := strings.ToLower(filepath.Base(path))
		return strings.HasSuffix(lower, ".log") ||
			strings.HasSuffix(lower, ".log.0") ||
			strings.HasSuffix(lower, ".log.1") ||
			strings.HasSuffix(lower, ".out") ||
			strings.HasSuffix(lower, ".err") ||
			strings.HasSuffix(lower, ".txt") ||
			strings.HasSuffix(lower, ".gz") ||
			strings.HasSuffix(lower, ".ips") ||
			strings.HasSuffix(lower, ".diag")
	}

	systemRoots := []struct {
		path     string
		category string
	}{
		{"/Library/Logs", "system_app_logs"},
		{"/private/var/log/com.apple.xpc.launchd", "launchd_logs"},
		{"/private/var/log", "var_log"},
		{"/var/log", "var_log_alt"},
		{"/usr/local/var/log", "usr_local_var_log"},
		{"/opt/homebrew/var/log", "homebrew_var_log_arm"},
		{"/opt/homebrew/Library/Logs", "homebrew_lib_log_arm"},
		{"/usr/local/var/postgres", "postgres_data"},
		{"/usr/local/var/mysql", "mysql_data"},
		{"/usr/local/var/log/nginx", "nginx_log"},
		{"/opt/homebrew/var/log/nginx", "nginx_log_arm"},
		{"/usr/local/var/log/mongodb", "mongodb_log"},
		{"/opt/homebrew/var/log/mongodb", "mongodb_log_arm"},
		{"/var/log/apache2", "apache_log"},
		{"/Library/Application Support/AnyDesk", "anydesk"},
		{"/Library/Application Support/TeamViewer", "teamviewer"},
		{"/Library/Application Support/Sophos", "sophos"},
		{"/Library/Application Support/Splashtop", "splashtop"},
		{"/Library/Application Support/Parallels", "parallels"},
	}
	for _, r := range systemRoots {
		ctx.CaptureGlob(r.path,
			func(path string, info fs.FileInfo) bool {
				return logSuffix(path) && info.Size() < 200*1024*1024
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
				return logSuffix(path) && info.Size() < 200*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel(root, path)
				return filepath.Join("artifacts/app_logs/users", user, rel)
			},
			"user_app_logs",
		)

		// Per-user Application Support log directories for the apps the
		// Binalyze KB calls out specifically.
		userAppRoots := []struct {
			rel      string
			category string
		}{
			{"Library/Application Support/AnyDesk", "anydesk_user"},
			{"Library/Application Support/TeamViewer", "teamviewer_user"},
			{"Library/Application Support/Splashtop", "splashtop_user"},
			{"Library/Application Support/Parallels", "parallels_user"},
			{"Library/Application Support/discord/Local Storage/leveldb", "discord_user"},
			{"Library/Application Support/discord/logs", "discord_user_logs"},
			{"Library/Group Containers/group.com.docker", "docker_user"},
			{"Library/Containers/com.docker.docker/Data/log", "docker_logs"},
			{"Library/Logs/Docker", "docker_logs_alt"},
		}
		for _, r := range userAppRoots {
			full := filepath.Join(home, r.rel)
			ctx.CaptureGlob(full,
				func(path string, info fs.FileInfo) bool {
					return logSuffix(path) && info.Size() < 200*1024*1024
				},
				func(path string) string {
					rel, _ := filepath.Rel(home, path)
					return filepath.Join("artifacts/app_logs/users", user, rel)
				},
				r.category,
			)
		}
	}
	return nil
}
