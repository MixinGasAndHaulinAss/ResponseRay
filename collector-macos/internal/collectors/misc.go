package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// CrashReportCollector grabs ips/crash files from Diagnostic Reports for system + users.
type CrashReportCollector struct{}

func (CrashReportCollector) Name() string { return "CrashReports" }

func (CrashReportCollector) Run(ctx *fsutil.Context) error {
	roots := []string{
		"/Library/Logs/DiagnosticReports",
		"/var/log/DiagnosticMessages",
	}
	for _, r := range roots {
		ctx.CaptureGlob(r,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				return (strings.HasSuffix(lower, ".ips") || strings.HasSuffix(lower, ".crash") ||
					strings.HasSuffix(lower, ".diag") || strings.HasSuffix(lower, ".panic") ||
					strings.HasSuffix(lower, ".spin") || strings.HasSuffix(lower, ".hang") ||
					strings.HasSuffix(lower, ".shutdownStall") || strings.HasSuffix(lower, ".synced")) &&
					info.Size() < 50*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/crashes", rel)
			},
			"crashes",
		)
	}
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		root := filepath.Join(home, "Library", "Logs", "DiagnosticReports")
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				return (strings.HasSuffix(lower, ".ips") || strings.HasSuffix(lower, ".crash") ||
					strings.HasSuffix(lower, ".diag")) && info.Size() < 50*1024*1024
			},
			func(path string) string {
				return filepath.Join("artifacts/crashes/users", user, filepath.Base(path))
			},
			"crashes_user",
		)
	}
	return nil
}

// InstallHistoryCollector grabs the receipts and InstallHistory.plist.
type InstallHistoryCollector struct{}

func (InstallHistoryCollector) Name() string { return "InstallHistory" }

func (InstallHistoryCollector) Run(ctx *fsutil.Context) error {
	files := []string{
		"/Library/Receipts/InstallHistory.plist",
		"/private/var/log/install.log",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/install_history", filepath.Base(f)), "install_history")
	}
	ctx.CaptureGlob("/private/var/db/receipts",
		func(path string, info fs.FileInfo) bool {
			lower := strings.ToLower(path)
			return (strings.HasSuffix(lower, ".bom") || strings.HasSuffix(lower, ".plist")) && info.Size() < 5*1024*1024
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/install_history", rel)
		},
		"install_history_receipts",
	)
	if v, err := runCmd(60*time.Second, "softwareupdate", "--history", "--all"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/softwareupdate_history.txt"), v)
	}
	return nil
}

// TimeMachineCollector pulls Time Machine status / backup metadata.
type TimeMachineCollector struct{}

func (TimeMachineCollector) Name() string { return "TimeMachine" }

func (TimeMachineCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	if v, err := runCmd(30*time.Second, "tmutil", "status"); err == nil {
		out["status"] = v
	}
	if v, err := runCmd(30*time.Second, "tmutil", "destinationinfo"); err == nil {
		out["destinationinfo"] = v
	}
	if v, err := runCmd(30*time.Second, "tmutil", "listbackups"); err == nil {
		out["listbackups"] = v
	}
	if v, err := runCmd(30*time.Second, "tmutil", "latestbackup"); err == nil {
		out["latestbackup"] = v
	}
	if _, err := ctx.WriteJSON("live/timemachine.json", "timemachine", out); err != nil {
		return err
	}
	plist := "/Library/Preferences/com.apple.TimeMachine.plist"
	ctx.CaptureFile(plist, "artifacts/timemachine/com.apple.TimeMachine.plist", "timemachine")
	return nil
}

// WirelessCollector grabs Wi-Fi history + configurations.
type WirelessCollector struct{}

func (WirelessCollector) Name() string { return "Wireless" }

func (WirelessCollector) Run(ctx *fsutil.Context) error {
	files := []string{
		"/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
		"/Library/Preferences/SystemConfiguration/com.apple.wifi.message-tracer.plist",
		"/Library/Preferences/SystemConfiguration/preferences.plist",
		"/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
		"/Library/Preferences/com.apple.bluetoothd.plist",
		"/Library/Preferences/com.apple.Bluetooth.plist",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/wireless", filepath.Base(f)), "wireless")
	}
	if v, err := runCmd(15*time.Second, "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/airport_status.txt"), v)
	}
	if v, err := runCmd(15*time.Second, "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/airport_scan.txt"), v)
	}
	return nil
}

// RecentItemsCollector copies recently used app and document plists.
type RecentItemsCollector struct{}

func (RecentItemsCollector) Name() string { return "RecentItems" }

func (RecentItemsCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		root := filepath.Join(home, "Library", "Preferences")
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(filepath.Base(path))
				return (strings.HasPrefix(lower, "com.apple.recent") ||
					strings.HasPrefix(lower, "com.apple.spotlight") ||
					strings.HasPrefix(lower, "com.apple.dock") ||
					strings.HasPrefix(lower, "com.apple.finder") ||
					strings.HasPrefix(lower, "com.apple.systempreferences") ||
					strings.HasPrefix(lower, "com.apple.preview")) &&
					strings.HasSuffix(lower, ".plist") && info.Size() < 4*1024*1024
			},
			func(path string) string {
				return filepath.Join("artifacts/recent_items/users", user, filepath.Base(path))
			},
			"recent_items",
		)
		// Per-app sfl2 (Shared File List) - holds recents.
		root2 := filepath.Join(home, "Library", "Application Support", "com.apple.sharedfilelist")
		ctx.CaptureGlob(root2,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				return (strings.HasSuffix(lower, ".sfl2") || strings.HasSuffix(lower, ".sfl3")) && info.Size() < 4*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel(root2, path)
				return filepath.Join("artifacts/recent_items/users", user, "sharedfilelist", rel)
			},
			"recent_items",
		)
	}
	return nil
}

// SpotlightCollector copies .Spotlight-V100 store metadata only.
type SpotlightCollector struct{}

func (SpotlightCollector) Name() string { return "Spotlight" }

func (SpotlightCollector) Run(ctx *fsutil.Context) error {
	if v, err := runCmd(15*time.Second, "mdutil", "-sav"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/mdutil_status.txt"), v)
	}
	return nil
}

// FSEventsCollector copies fseventsd records (file system event log).
type FSEventsCollector struct{}

func (FSEventsCollector) Name() string { return "FSEvents" }

func (FSEventsCollector) Run(ctx *fsutil.Context) error {
	root := "/.fseventsd"
	ctx.CaptureGlob(root,
		func(path string, info fs.FileInfo) bool {
			return info.Size() < 50*1024*1024
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/fsevents", rel)
		},
		"fsevents",
	)
	return nil
}

// AuditdCollector copies BSM audit logs and config.
type AuditdCollector struct{}

func (AuditdCollector) Name() string { return "Auditd" }

func (AuditdCollector) Run(ctx *fsutil.Context) error {
	configs := []string{
		"/etc/security/audit_control",
		"/etc/security/audit_class",
		"/etc/security/audit_event",
		"/etc/security/audit_user",
		"/etc/security/audit_warn",
	}
	for _, f := range configs {
		ctx.CaptureFile(f, filepath.Join("artifacts/auditd", filepath.Base(f)), "auditd")
	}
	ctx.CaptureGlob("/var/audit",
		func(path string, info fs.FileInfo) bool {
			return info.Size() < 200*1024*1024
		},
		func(path string) string {
			rel, _ := filepath.Rel("/", path)
			return filepath.Join("artifacts/auditd", rel)
		},
		"auditd_logs",
	)
	if v, err := runCmd(30*time.Second, "praudit", "-l", "/var/audit/current"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/praudit_current.txt"), v)
	}
	return nil
}
