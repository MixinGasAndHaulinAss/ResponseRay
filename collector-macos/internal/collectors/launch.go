package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// LaunchCollector copies all Launch Agents/Daemons (system and per-user) and
// emits a flat JSON manifest of them so analysts can scan persistence quickly.
type LaunchCollector struct{}

func (LaunchCollector) Name() string { return "LaunchAgentsDaemons" }

func (LaunchCollector) Run(ctx *fsutil.Context) error {
	systemRoots := []string{
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
	}
	for _, r := range systemRoots {
		ctx.CaptureGlob(r,
			func(path string, info fs.FileInfo) bool {
				return strings.HasSuffix(strings.ToLower(path), ".plist") && info.Size() < 4*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/launch", rel)
			},
			"launch_system",
		)
	}

	for _, home := range userHomes() {
		user := usernameFromHome(home)
		root := filepath.Join(home, "Library", "LaunchAgents")
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				return strings.HasSuffix(strings.ToLower(path), ".plist") && info.Size() < 4*1024*1024
			},
			func(path string) string {
				return filepath.Join("artifacts/launch/users", user, "LaunchAgents", filepath.Base(path))
			},
			"launch_user",
		)
	}

	if v, err := runCmd(30*time.Second, "launchctl", "list"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/launchctl_list.txt"), v)
	}
	if v, err := runCmd(30*time.Second, "launchctl", "print", "system"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/launchctl_print_system.txt"), v)
	}
	return nil
}

// LoginItemsCollector enumerates per-user login items.
type LoginItemsCollector struct{}

func (LoginItemsCollector) Name() string { return "LoginItems" }

func (LoginItemsCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		// Modern (macOS 13+) Background Items DB.
		bg := filepath.Join(home, "Library", "Application Support", "com.apple.backgroundtaskmanagementagent", "backgrounditems.btm")
		ctx.CaptureFile(bg, filepath.Join("artifacts/login_items/users", user, "backgrounditems.btm"), "login_items")

		// Legacy login items plist (10.13 era).
		legacy := filepath.Join(home, "Library", "Preferences", "com.apple.loginitems.plist")
		ctx.CaptureFile(legacy, filepath.Join("artifacts/login_items/users", user, "com.apple.loginitems.plist"), "login_items")
	}

	if v, err := runCmd(20*time.Second, "osascript", "-e",
		`tell application "System Events" to get the name of every login item`); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/login_items_names.txt"), v)
	}
	if v, err := runCmd(30*time.Second, "sfltool", "dumpbtm"); err == nil {
		_ = writeText(filepath.Join(ctx.OutputDir, "live/sfltool_dumpbtm.txt"), v)
	}
	return nil
}
