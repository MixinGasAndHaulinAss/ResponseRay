package collectors

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// BrowserCollector covers Safari, Chrome, Firefox, Edge, Brave, Opera, Vivaldi, Arc.
type BrowserCollector struct{}

func (BrowserCollector) Name() string { return "Browsers" }

func (BrowserCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)

		// Safari
		safariFiles := []string{
			"Library/Safari/History.db",
			"Library/Safari/History.db-wal",
			"Library/Safari/History.db-shm",
			"Library/Safari/Bookmarks.plist",
			"Library/Safari/Downloads.plist",
			"Library/Safari/TopSites.plist",
			"Library/Safari/RecentlyClosedTabs.plist",
			"Library/Safari/LastSession.plist",
			"Library/Safari/Extensions/Extensions.plist",
			"Library/Safari/CloudTabs.db",
			"Library/Safari/UserNotificationPermissions.plist",
			"Library/Safari/PerSitePreferences.db",
			"Library/Cookies/Cookies.binarycookies",
		}
		for _, rel := range safariFiles {
			src := filepath.Join(home, rel)
			ctx.CaptureFile(src, filepath.Join("artifacts/browsers/safari", user, filepath.Base(rel)), "safari")
		}

		// Chromium-family roots: each has profiles like "Default", "Profile 1", etc.
		chromiumRoots := map[string]string{
			"chrome":   "Library/Application Support/Google/Chrome",
			"chromium": "Library/Application Support/Chromium",
			"edge":     "Library/Application Support/Microsoft Edge",
			"brave":    "Library/Application Support/BraveSoftware/Brave-Browser",
			"opera":    "Library/Application Support/com.operasoftware.Opera",
			"vivaldi":  "Library/Application Support/Vivaldi",
			"arc":      "Library/Application Support/Arc",
			"yandex":   "Library/Application Support/Yandex/YandexBrowser",
		}
		chromiumFiles := []string{"History", "History-journal", "Cookies", "Cookies-journal",
			"Login Data", "Login Data-journal", "Web Data", "Web Data-journal",
			"Bookmarks", "Bookmarks.bak", "Preferences", "Secure Preferences",
			"Top Sites", "Visited Links", "Last Session", "Last Tabs", "Current Session", "Current Tabs",
			"Shortcuts", "Favicons", "Network Action Predictor", "QuotaManager",
		}
		for browserName, base := range chromiumRoots {
			root := filepath.Join(home, base)
			if _, err := os.Stat(root); err != nil {
				continue
			}
			ctx.CaptureGlob(root,
				func(path string, info fs.FileInfo) bool {
					name := filepath.Base(path)
					for _, want := range chromiumFiles {
						if name == want {
							return info.Size() < fsutil.MaxSingleFileBytes
						}
					}
					if name == "manifest.json" && strings.Contains(path, "/Extensions/") {
						return info.Size() < 1*1024*1024
					}
					return false
				},
				func(path string) string {
					rel, _ := filepath.Rel(root, path)
					return filepath.Join("artifacts/browsers", browserName, user, rel)
				},
				"chromium_"+browserName,
			)
		}

		// Firefox profiles (each .default-* under Profiles/).
		firefoxRoot := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
		ctx.CaptureGlob(firefoxRoot,
			func(path string, info fs.FileInfo) bool {
				name := filepath.Base(path)
				switch name {
				case "places.sqlite", "places.sqlite-wal", "places.sqlite-shm",
					"cookies.sqlite", "formhistory.sqlite", "permissions.sqlite",
					"downloads.sqlite", "favicons.sqlite", "key4.db", "logins.json",
					"prefs.js", "user.js", "extensions.json", "addons.json",
					"sessionstore.jsonlz4", "addonStartup.json.lz4", "containers.json":
					return info.Size() < fsutil.MaxSingleFileBytes
				}
				return false
			},
			func(path string) string {
				rel, _ := filepath.Rel(firefoxRoot, path)
				return filepath.Join("artifacts/browsers/firefox", user, rel)
			},
			"firefox",
		)
	}
	return nil
}
