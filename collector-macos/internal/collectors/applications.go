package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// ApplicationsCollector enumerates installed apps + their Info.plist files
// without copying any executables.
type ApplicationsCollector struct{}

func (ApplicationsCollector) Name() string { return "Applications" }

func (ApplicationsCollector) Run(ctx *fsutil.Context) error {
	infoRoots := []string{"/Applications", "/System/Applications"}
	for _, root := range infoRoots {
		ctx.CaptureGlob(root,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				if !strings.HasSuffix(lower, "/contents/info.plist") {
					return false
				}
				if info.Size() > 4*1024*1024 {
					return false
				}
				return true
			},
			func(path string) string {
				rel, _ := filepath.Rel("/", path)
				return filepath.Join("artifacts/applications", rel)
			},
			"applications",
		)
	}
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		ctx.CaptureGlob(filepath.Join(home, "Applications"),
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				return strings.HasSuffix(lower, "/contents/info.plist") && info.Size() < 4*1024*1024
			},
			func(path string) string {
				rel, _ := filepath.Rel(home, path)
				return filepath.Join("artifacts/applications/users", user, rel)
			},
			"applications_user",
		)
	}

	out := map[string]interface{}{}
	if v, err := runCmd(60*time.Second, "system_profiler", "SPApplicationsDataType"); err == nil {
		out["system_profiler_apps"] = v
	}
	if v, err := runCmd(30*time.Second, "pkgutil", "--pkgs"); err == nil {
		out["pkgutil_pkgs"] = v
	}
	if v, err := runCmd(60*time.Second, "system_profiler", "SPInstallHistoryDataType"); err == nil {
		out["install_history"] = v
	}
	if _, err := ctx.WriteJSON("live/applications.json", "applications", out); err != nil {
		return err
	}
	return nil
}
