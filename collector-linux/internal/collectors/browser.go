package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type BrowserCollector struct{}

func (c *BrowserCollector) Name() string        { return "Browser" }
func (c *BrowserCollector) Description() string { return "Per-user Firefox/Chrome/Chromium/Brave/Vivaldi browser artifacts" }

func (c *BrowserCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	chromiumProfileFiles := map[string]bool{
		"History": true, "History-journal": true,
		"Cookies": true, "Login Data": true, "Login Data For Account": true,
		"Web Data": true, "Bookmarks": true, "Top Sites": true,
		"Network Action Predictor": true, "Shortcuts": true, "Favicons": true,
		"Visited Links": true, "Preferences": true, "Secure Preferences": true,
		"Last Session": true, "Last Tabs": true, "Current Session": true, "Current Tabs": true,
	}

	firefoxFiles := map[string]bool{
		"places.sqlite": true, "places.sqlite-wal": true,
		"cookies.sqlite": true, "formhistory.sqlite": true, "downloads.sqlite": true,
		"permissions.sqlite": true, "logins.json": true, "key4.db": true,
		"signons.sqlite": true, "favicons.sqlite": true, "addons.json": true,
		"extensions.json": true, "prefs.js": true, "sessionstore.jsonlz4": true,
		"handlers.json": true,
	}

	chromiumRoots := []string{
		".config/google-chrome",
		".config/chromium",
		".config/BraveSoftware/Brave-Browser",
		".config/vivaldi",
		".config/microsoft-edge",
		".config/opera",
	}

	for _, h := range userHomes() {
		for _, root := range chromiumRoots {
			browserDir := filepath.Join(h.Home, root)
			info, err := stat(browserDir)
			if err != nil || !info.IsDir() {
				continue
			}

			ctx.CaptureFile(filepath.Join(browserDir, "Local State"),
				filepath.Join("artifacts/browser", filepath.Base(root), h.User, "Local State"), "browser")

			profiles, _ := filepath.Glob(filepath.Join(browserDir, "*"))
			for _, profileDir := range profiles {
				pinfo, perr := stat(profileDir)
				if perr != nil || !pinfo.IsDir() {
					continue
				}
				profileName := filepath.Base(profileDir)
				if profileName == "Crashpad" || profileName == "ShaderCache" ||
					profileName == "GraphiteDawnCache" || profileName == "PnaclTranslationCache" ||
					profileName == "Subresource Filter" || profileName == "Safe Browsing" {
					continue
				}

				ctx.CaptureGlob(profileDir,
					func(p string, info fs.FileInfo) bool {
						return chromiumProfileFiles[filepath.Base(p)]
					},
					func(p string) string {
						rel, _ := filepath.Rel(profileDir, p)
						return filepath.Join("artifacts/browser", filepath.Base(root), h.User, profileName, rel)
					},
					"browser")

				extDir := filepath.Join(profileDir, "Extensions")
				ctx.CaptureGlob(extDir,
					func(p string, info fs.FileInfo) bool { return strings.HasSuffix(p, "manifest.json") },
					func(p string) string {
						rel, _ := filepath.Rel(extDir, p)
						return filepath.Join("artifacts/browser", filepath.Base(root), h.User, profileName, "Extensions", rel)
					},
					"browser_extension")
			}
		}

		ffRoot := filepath.Join(h.Home, ".mozilla/firefox")
		profiles, _ := filepath.Glob(filepath.Join(ffRoot, "*.*"))
		for _, profileDir := range profiles {
			pinfo, perr := stat(profileDir)
			if perr != nil || !pinfo.IsDir() {
				continue
			}
			profileName := filepath.Base(profileDir)
			ctx.CaptureGlob(profileDir,
				func(p string, info fs.FileInfo) bool { return firefoxFiles[filepath.Base(p)] },
				func(p string) string {
					rel, _ := filepath.Rel(profileDir, p)
					return filepath.Join("artifacts/browser/firefox", h.User, profileName, rel)
				},
				"browser")
		}
	}

	r.FilesCollected = len(ctx.Files())
	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
