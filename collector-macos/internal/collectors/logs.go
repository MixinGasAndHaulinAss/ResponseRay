package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// UnifiedLogCollector exports unified log archives + a recent log show snapshot.
type UnifiedLogCollector struct{}

func (UnifiedLogCollector) Name() string { return "UnifiedLogs" }

func (UnifiedLogCollector) Run(ctx *fsutil.Context) error {
	// Raw unified log binary stores - frequently locked but copyable when running as root.
	roots := []string{
		"/var/db/diagnostics",
		"/var/db/uuidtext",
	}
	for _, root := range roots {
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				return info.Size() < fsutil.MaxSingleFileBytes
			},
			func(path string) string {
				rel, err := filepath.Rel("/", path)
				if err != nil {
					rel = strings.TrimPrefix(path, "/")
				}
				return filepath.Join("artifacts/unified_logs", rel)
			},
			"unified_logs",
		)
	}

	// Recent (last 24h) parsed snapshot via `log show` for forensic timeline value.
	if v, err := runCmd(120*time.Second, "log", "show", "--predicate",
		`processImagePath CONTAINS "Login" OR eventMessage CONTAINS "auth" OR eventMessage CONTAINS "ssh" OR eventMessage CONTAINS "screensaver" OR eventMessage CONTAINS "Volume"`,
		"--last", "24h", "--style", "ndjson"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/unified_log_recent.ndjson"), v)
	}
	if v, err := runCmd(60*time.Second, "log", "stats"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/unified_log_stats.txt"), v)
	}
	return nil
}

// LegacyLogCollector copies classic /var/log text logs.
type LegacyLogCollector struct{}

func (LegacyLogCollector) Name() string { return "LegacyLogs" }

func (LegacyLogCollector) Run(ctx *fsutil.Context) error {
	patterns := []string{
		"/var/log/system.log",
		"/var/log/install.log",
		"/var/log/secure.log",
		"/var/log/auth.log",
		"/var/log/wifi.log",
		"/var/log/apache2/access_log",
		"/var/log/apache2/error_log",
		"/var/log/cups",
		"/var/log/DiagnosticMessages",
		"/var/log/displaypolicyd.log",
		"/var/log/fsck_apfs.log",
		"/var/log/fsck_apfs_error.log",
		"/var/log/fsck_hfs.log",
		"/var/log/com.apple.xpc.launchd",
		"/var/log/asl.log",
		"/var/log/appfirewall.log",
		"/var/log/daily.out",
		"/var/log/weekly.out",
		"/var/log/monthly.out",
	}
	for _, p := range patterns {
		ctx.CaptureGlob(p,
			func(path string, info fs.FileInfo) bool { return true },
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/var_log", rel)
			},
			"var_log",
		)
		ctx.CaptureFile(p, filepath.Join("artifacts/var_log", strings.TrimPrefix(p, "/")), "var_log")
	}
	// Rotated copies (.0, .1, .gz) by walking /var/log shallowly.
	ctx.CaptureGlob("/var/log",
		func(path string, info fs.FileInfo) bool {
			name := strings.ToLower(filepath.Base(path))
			if info.Size() > 100*1024*1024 {
				return false
			}
			return strings.HasSuffix(name, ".log") ||
				strings.HasSuffix(name, ".gz") ||
				strings.HasSuffix(name, ".0") ||
				strings.HasSuffix(name, ".1") ||
				strings.HasSuffix(name, ".out")
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/var_log", rel)
		},
		"var_log_rotated",
	)
	return nil
}

// ASLLogCollector copies legacy Apple System Log database files.
type ASLLogCollector struct{}

func (ASLLogCollector) Name() string { return "ASLLogs" }

func (ASLLogCollector) Run(ctx *fsutil.Context) error {
	ctx.CaptureGlob("/var/log/asl",
		func(path string, info fs.FileInfo) bool {
			name := strings.ToLower(filepath.Base(path))
			return strings.HasSuffix(name, ".asl") || strings.HasSuffix(name, ".asldb")
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts", rel)
		},
		"asl",
	)
	if v, err := runCmd(60*time.Second, "syslog", "-T", "utc", "-d", "1"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/syslog_recent.txt"), v)
	}
	return nil
}
