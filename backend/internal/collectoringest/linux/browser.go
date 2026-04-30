package linux

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/responseray/internal/collectoringest/core"
	_ "modernc.org/sqlite"
)

// processLinuxBrowsers parses browser artifacts from artifacts/browser/.
func processLinuxBrowsers(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "browser")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	total := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := strings.ToLower(d.Name())
		switch base {
		case "history":
			total += parseChromiumHistory(em, path, ts)
		case "cookies":
			total += parseChromiumCookies(em, path, ts)
		case "login data":
			total += parseChromiumLogins(em, path, ts)
		case "bookmarks":
			total += parseChromiumBookmarks(em, path, ts)
		case "places.sqlite":
			total += parseFirefoxHistory(em, path, ts)
		case "cookies.sqlite":
			total += parseFirefoxCookies(em, path, ts)
		case "logins.json":
			total += parseFirefoxLogins(em, path, ts)
		}
		return nil
	})
	return total
}

func parseChromiumHistory(em *core.Emitter, path, ts string) int {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer db.Close()

	added := 0
	browser := detectBrowserFromPath(path)

	// Parse URL visits
	rows, err := db.Query(`
		SELECT urls.url, urls.title, visits.visit_time, urls.visit_count
		FROM urls
		JOIN visits ON urls.id = visits.url
		ORDER BY visits.visit_time DESC
		LIMIT 10000
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	for rows.Next() {
		var url, title string
		var visitTime int64
		var visitCount int
		if err := rows.Scan(&url, &title, &visitTime, &visitCount); err != nil {
			continue
		}
		dt := chromiumTimeToISO(visitTime)
		if dt == "" {
			dt = ts
		}
		display := url
		if len(display) > 150 {
			display = display[:150] + "..."
		}
		msg := fmt.Sprintf("Web visit: %s", display)
		if title != "" {
			msg = fmt.Sprintf("Web visit: %s (%s)", title, display)
		}
		if em.AddEvent(dt, "Web History Entry", msg, "web_history",
			"RR-Linux", "ResponseRay Linux Collector - "+browser,
			"linux:browser:history", map[string]interface{}{
				"url":         url,
				"title":       title,
				"visit_count": visitCount,
				"browser":     browser,
			}) {
			added++
		}
	}

	// Parse downloads
	dlRows, err := db.Query(`
		SELECT target_path, tab_url, start_time, end_time, total_bytes, state
		FROM downloads
		ORDER BY start_time DESC
		LIMIT 5000
	`)
	if err == nil {
		defer dlRows.Close()
		for dlRows.Next() {
			var targetPath, tabURL string
			var startTime, endTime, totalBytes int64
			var state int
			if err := dlRows.Scan(&targetPath, &tabURL, &startTime, &endTime, &totalBytes, &state); err != nil {
				continue
			}
			dt := chromiumTimeToISO(startTime)
			if dt == "" {
				dt = ts
			}
			msg := fmt.Sprintf("Downloaded: %s from %s", filepath.Base(targetPath), tabURL)
			if em.AddEvent(dt, "File Downloaded", msg, "web_download",
				"RR-Linux", "ResponseRay Linux Collector - "+browser,
				"linux:browser:download", map[string]interface{}{
					"file_path":   targetPath,
					"source_url":  tabURL,
					"total_bytes": totalBytes,
					"state":       state,
					"browser":     browser,
				}) {
				added++
			}
		}
	}

	return added
}

func parseChromiumCookies(em *core.Emitter, path, ts string) int {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer db.Close()

	added := 0
	browser := detectBrowserFromPath(path)

	rows, err := db.Query(`
		SELECT host_key, name, path, creation_utc, last_access_utc, expires_utc, is_secure, is_httponly
		FROM cookies
		ORDER BY last_access_utc DESC
		LIMIT 5000
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	for rows.Next() {
		var hostKey, name, cookiePath string
		var creation, lastAccess, expires int64
		var isSecure, isHttpOnly int
		if err := rows.Scan(&hostKey, &name, &cookiePath, &creation, &lastAccess, &expires, &isSecure, &isHttpOnly); err != nil {
			continue
		}
		dt := chromiumTimeToISO(lastAccess)
		if dt == "" {
			dt = ts
		}
		msg := fmt.Sprintf("Cookie: %s on %s", name, hostKey)
		if em.AddEvent(dt, "Web Cookie", msg, "web_cookie",
			"RR-Linux", "ResponseRay Linux Collector - "+browser,
			"linux:browser:cookie", map[string]interface{}{
				"host":        hostKey,
				"name":        name,
				"path":        cookiePath,
				"is_secure":   isSecure == 1,
				"is_httponly": isHttpOnly == 1,
				"browser":     browser,
			}) {
			added++
		}
	}
	return added
}

func parseChromiumLogins(em *core.Emitter, path, ts string) int {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer db.Close()

	added := 0
	browser := detectBrowserFromPath(path)

	rows, err := db.Query(`
		SELECT origin_url, username_value, date_created, date_last_used, times_used
		FROM logins
		ORDER BY date_last_used DESC
		LIMIT 2000
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	for rows.Next() {
		var originURL, username string
		var dateCreated, dateLastUsed int64
		var timesUsed int
		if err := rows.Scan(&originURL, &username, &dateCreated, &dateLastUsed, &timesUsed); err != nil {
			continue
		}
		dt := chromiumTimeToISO(dateLastUsed)
		if dt == "" {
			dt = ts
		}
		msg := fmt.Sprintf("Saved login: %s @ %s", username, originURL)
		if em.AddEvent(dt, "Web Login Saved", msg, "web_login",
			"RR-Linux", "ResponseRay Linux Collector - "+browser,
			"linux:browser:login", map[string]interface{}{
				"url":        originURL,
				"username":   username,
				"times_used": timesUsed,
				"browser":    browser,
			}) {
			added++
		}
	}
	return added
}

func parseChromiumBookmarks(em *core.Emitter, path, ts string) int {
	// Bookmarks are JSON, not SQLite - skip for now or parse JSON
	return 0
}

func parseFirefoxHistory(em *core.Emitter, path, ts string) int {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer db.Close()

	added := 0

	rows, err := db.Query(`
		SELECT url, title, visit_count, last_visit_date
		FROM moz_places
		WHERE last_visit_date IS NOT NULL
		ORDER BY last_visit_date DESC
		LIMIT 10000
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	for rows.Next() {
		var url, title string
		var visitCount int
		var lastVisit sql.NullInt64
		if err := rows.Scan(&url, &title, &visitCount, &lastVisit); err != nil {
			continue
		}
		dt := ts
		if lastVisit.Valid && lastVisit.Int64 > 0 {
			dt = firefoxTimeToISO(lastVisit.Int64)
		}
		display := url
		if len(display) > 150 {
			display = display[:150] + "..."
		}
		msg := fmt.Sprintf("Web visit: %s", display)
		if title != "" {
			msg = fmt.Sprintf("Web visit: %s (%s)", title, display)
		}
		if em.AddEvent(dt, "Web History Entry", msg, "web_history",
			"RR-Linux", "ResponseRay Linux Collector - Firefox",
			"linux:browser:history", map[string]interface{}{
				"url":         url,
				"title":       title,
				"visit_count": visitCount,
				"browser":     "Firefox",
			}) {
			added++
		}
	}
	return added
}

func parseFirefoxCookies(em *core.Emitter, path, ts string) int {
	db, err := openSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer db.Close()

	added := 0

	rows, err := db.Query(`
		SELECT host, name, path, lastAccessed, creationTime, isSecure, isHttpOnly
		FROM moz_cookies
		ORDER BY lastAccessed DESC
		LIMIT 5000
	`)
	if err != nil {
		return 0
	}
	defer rows.Close()

	for rows.Next() {
		var host, name, cookiePath string
		var lastAccessed, creationTime int64
		var isSecure, isHttpOnly int
		if err := rows.Scan(&host, &name, &cookiePath, &lastAccessed, &creationTime, &isSecure, &isHttpOnly); err != nil {
			continue
		}
		dt := ts
		if lastAccessed > 0 {
			dt = firefoxTimeToISO(lastAccessed)
		}
		msg := fmt.Sprintf("Cookie: %s on %s", name, host)
		if em.AddEvent(dt, "Web Cookie", msg, "web_cookie",
			"RR-Linux", "ResponseRay Linux Collector - Firefox",
			"linux:browser:cookie", map[string]interface{}{
				"host":        host,
				"name":        name,
				"path":        cookiePath,
				"is_secure":   isSecure == 1,
				"is_httponly": isHttpOnly == 1,
				"browser":     "Firefox",
			}) {
			added++
		}
	}
	return added
}

func parseFirefoxLogins(em *core.Emitter, path, ts string) int {
	// logins.json is JSON, not SQLite - skip for now
	return 0
}

func openSQLiteReadOnly(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+path+"?mode=ro&_busy_timeout=5000&immutable=1")
}

func chromiumTimeToISO(t int64) string {
	if t <= 0 {
		return ""
	}
	// Chromium uses microseconds since Jan 1, 1601
	const chromiumEpochOffset = 11644473600000000 // microseconds between 1601 and 1970
	unixMicro := t - chromiumEpochOffset
	if unixMicro < 0 {
		return ""
	}
	sec := unixMicro / 1000000
	ms := (unixMicro % 1000000) / 1000
	tm := time.Unix(sec, 0).UTC()
	return fmt.Sprintf("%s.%03dZ", tm.Format("2006-01-02T15:04:05"), ms)
}

func firefoxTimeToISO(t int64) string {
	if t <= 0 {
		return ""
	}
	// Firefox uses microseconds since Unix epoch
	sec := t / 1000000
	ms := (t % 1000000) / 1000
	tm := time.Unix(sec, 0).UTC()
	return fmt.Sprintf("%s.%03dZ", tm.Format("2006-01-02T15:04:05"), ms)
}

func detectBrowserFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "chrome"):
		return "Chrome"
	case strings.Contains(lower, "chromium"):
		return "Chromium"
	case strings.Contains(lower, "brave"):
		return "Brave"
	case strings.Contains(lower, "vivaldi"):
		return "Vivaldi"
	case strings.Contains(lower, "edge"):
		return "Edge"
	case strings.Contains(lower, "opera"):
		return "Opera"
	case strings.Contains(lower, "firefox"):
		return "Firefox"
	default:
		return "Unknown"
	}
}
