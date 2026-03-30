package browser

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"

	_ "modernc.org/sqlite"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "browser" }
func (e *Extractor) Description() string { return "Chrome, Edge, Firefox browser history" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}

	added := 0

	// Chrome/Edge History files
	chromFiles, _ := idx.GetCollectedFiles(`History$`, "")
	for _, f := range chromFiles {
		n, err := parseChromium(f, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("Browser history %s: %v", f.Path, err))
			continue
		}
		added += n
	}

	// Firefox places.sqlite
	ffFiles, _ := idx.GetCollectedFiles(`places\.sqlite$`, "")
	for _, f := range ffFiles {
		n, err := parseFirefox(f, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("Firefox history %s: %v", f.Path, err))
			continue
		}
		added += n
	}

	progress.Info(fmt.Sprintf("Browser: %d history entries", added))
	return added, nil
}

func parseChromium(f cache.CollectedFile, conv *converter.Converter) (int, error) {
	dbPath, cleanup, err := resolveDBPath(f, "chrome-history-*.db")
	if err != nil {
		return 0, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	// Chromium stores timestamps as microseconds since 1601-01-01
	const chromEpochDiff = 11644473600000000 // microseconds

	rows, err := db.Query(`
		SELECT url, title, last_visit_time, visit_count
		FROM urls
		WHERE last_visit_time > 0
		ORDER BY last_visit_time DESC
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var url, title string
		var lastVisit int64
		var visitCount int
		if err := rows.Scan(&url, &title, &lastVisit, &visitCount); err != nil {
			continue
		}

		// Convert Chromium timestamp to epoch ms
		unixUs := lastVisit - chromEpochDiff
		if unixUs < 0 {
			continue
		}
		ts := converter.EpochMsToISO(unixUs / 1000)
		if ts == "" {
			continue
		}

		browser := "Chrome"
		if strings.Contains(f.Path, "Edge") || strings.Contains(f.Path, "edge") {
			browser = "Edge"
		}

		userID := extractUser(f.Filename)

		msg := fmt.Sprintf("%s: %s", browser, url)
		if title != "" {
			msg = fmt.Sprintf("%s: %s (%s)", browser, title, url)
		}

		if conv.AddEvent(ts, "URL Last Visited", msg, "browser_history",
			"CT-Browser", "CyberTriage Browser - "+browser,
			"chrome:history:page_visited", map[string]interface{}{
				"url":         url,
				"title":       title,
				"visit_count": visitCount,
				"browser":     browser,
				"user_id":     userID,
				"source_path": f.Path,
			}) {
			added++
		}
	}
	return added, nil
}

func parseFirefox(f cache.CollectedFile, conv *converter.Converter) (int, error) {
	dbPath, cleanup, err := resolveDBPath(f, "firefox-places-*.db")
	if err != nil {
		return 0, err
	}
	if cleanup != nil {
		defer cleanup()
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	// Firefox stores timestamps as microseconds since Unix epoch
	rows, err := db.Query(`
		SELECT p.url, p.title, h.visit_date, p.visit_count
		FROM moz_places p
		JOIN moz_historyvisits h ON p.id = h.place_id
		WHERE h.visit_date > 0
		ORDER BY h.visit_date DESC
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var url, title string
		var visitDate int64
		var visitCount int
		if err := rows.Scan(&url, &title, &visitDate, &visitCount); err != nil {
			continue
		}

		ts := converter.EpochMsToISO(visitDate / 1000) // μs to ms
		if ts == "" {
			continue
		}

		msg := fmt.Sprintf("Firefox: %s", url)
		if title != "" {
			msg = fmt.Sprintf("Firefox: %s (%s)", title, url)
		}

		if conv.AddEvent(ts, "URL Visited", msg, "browser_history",
			"CT-Browser", "CyberTriage Browser - Firefox",
			"firefox:places:page_visited", map[string]interface{}{
				"url":         url,
				"title":       title,
				"visit_count": visitCount,
				"browser":     "Firefox",
				"source_path": f.Path,
			}) {
			added++
		}
	}
	return added, nil
}

// extractUser pulls the username from collector-style filenames like "lsteese_Default_History".
func extractUser(filename string) string {
	if idx := strings.Index(filename, "_"); idx > 0 {
		return filename[:idx]
	}
	return ""
}

func resolveDBPath(f cache.CollectedFile, tmpPattern string) (string, func(), error) {
	if f.DiskPath != "" {
		return f.DiskPath, nil, nil
	}
	decoded, err := extractors.GetFileContent(f)
	if err != nil || len(decoded) == 0 {
		return "", nil, err
	}
	tmpFile, err := writeTempDB(decoded, tmpPattern)
	if err != nil {
		return "", nil, err
	}
	return tmpFile, func() { os.Remove(tmpFile) }, nil
}

func writeTempDB(data []byte, pattern string) (string, error) {
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return tmp.Name(), nil
}
