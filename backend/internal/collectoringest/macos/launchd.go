package macos

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacLaunchPlistsRich opens every captured LaunchDaemon / LaunchAgent
// .plist under artifacts/launch and emits one detailed startup_item event
// per plist with the parsed Label, ProgramArguments, RunAtLoad, etc. It
// supersedes the older mtime-only `processMacLaunchPlists` (kept for
// back-compat by being a no-op when this path is wired in).
func processMacLaunchPlistsRich(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "launch")
	if _, err := exists(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".plist") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		var origin, scope, user string
		switch {
		case strings.HasPrefix(filepath.ToSlash(rel), "users/"):
			scope = "user"
			parts := strings.Split(filepath.ToSlash(rel), "/")
			if len(parts) >= 4 {
				user = parts[1]
				origin = "/Users/" + user + "/Library/" + strings.Join(parts[2:], "/")
			} else {
				origin = "/" + strings.ReplaceAll(filepath.ToSlash(rel), "\\", "/")
			}
		default:
			scope = "system"
			origin = "/" + filepath.ToSlash(rel)
		}

		var label, program string
		var args []string
		var runAtLoad, keepAlive, disabled bool
		var watchPaths []string
		var startInterval int64
		var startCalendar interface{}
		var environment map[string]interface{}
		var workingDir string

		if m, perr := core.ReadPlist(path); perr == nil {
			label = core.PlistString(m, "Label")
			program = core.PlistString(m, "Program")
			args = core.PlistStringArray(m, "ProgramArguments")
			runAtLoad = core.PlistBool(m, "RunAtLoad")
			keepAlive = core.PlistBool(m, "KeepAlive")
			disabled = core.PlistBool(m, "Disabled")
			watchPaths = core.PlistStringArray(m, "WatchPaths")
			workingDir = core.PlistString(m, "WorkingDirectory")
			if v, ok := m["StartInterval"]; ok {
				if iv, ok := asInt64(v); ok {
					startInterval = iv
				}
			}
			if v, ok := m["StartCalendarInterval"]; ok {
				startCalendar = v
			}
			if v, ok := m["EnvironmentVariables"]; ok {
				if mv, ok := v.(map[string]interface{}); ok {
					environment = mv
				}
			}
		}
		if label == "" {
			label = strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
		}
		mtime := core.FileMtimeISO(info.ModTime())

		exec := program
		if exec == "" && len(args) > 0 {
			exec = args[0]
		}
		runAt := "load"
		switch {
		case keepAlive:
			runAt = "keepAlive"
		case startInterval > 0:
			runAt = fmt.Sprintf("interval=%ds", startInterval)
		case startCalendar != nil:
			runAt = "calendar"
		case len(watchPaths) > 0:
			runAt = "watchPaths"
		}

		msg := fmt.Sprintf("LaunchAgent/Daemon: %s -> %s", label, exec)
		attrs := map[string]interface{}{
			"config_type":     "LaunchAgentDaemon",
			"description":     label,
			"label":           label,
			"program":         program,
			"executable":      exec,
			"arguments":       args,
			"run_at_load":     runAtLoad,
			"keep_alive":      keepAlive,
			"disabled":        disabled,
			"watch_paths":     watchPaths,
			"start_interval":  startInterval,
			"start_calendar":  startCalendar,
			"working_dir":     workingDir,
			"environment":     environment,
			"plist_path":      origin,
			"plist_size":      info.Size(),
			"location":        origin,
			"scope":           scope,
			"username":        user,
			"trigger":         runAt,
			"artifact_path":   filepath.ToSlash(filepath.Join("launch", rel)),
		}
		if em.AddEvent(mtime, "Plist Modified", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - LaunchAgents/Daemons",
			"darwin:launchd:plist", attrs) {
			added++
		}
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - LaunchAgents/Daemons",
			"darwin:launchd:plist", core.CopyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}
