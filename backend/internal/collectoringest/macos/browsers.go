package macos

import (
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacBrowsers walks artifacts/browsers/<browser>/<user>/... and emits
// per-row events from the captured SQLite databases. We support:
//
//   Chromium-family (chrome / chromium / edge / brave / opera / vivaldi /
//   arc / yandex):
//     History  -> web_history (urls/visits) + web_download (downloads)
//     Cookies  -> web_cookie
//     Login Data -> web_login
//
//   Safari:
//     History.db -> web_history (history_items / history_visits)
//     Downloads.plist is handled by the plist parser elsewhere.
//
//   Firefox:
//     places.sqlite -> web_history (moz_places / moz_historyvisits) +
//                      web_download (moz_annos with anno=downloads/destinationFileURI)
//     cookies.sqlite -> web_cookie
//     formhistory.sqlite -> form_history
//     downloads.sqlite -> web_download
func processMacBrowsers(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "browsers")
	if _, err := exists(root); err != nil {
		return 0
	}

	added := 0

	chromiumFamily := map[string]bool{
		"chrome": true, "chromium": true, "edge": true, "brave": true,
		"opera": true, "vivaldi": true, "arc": true, "yandex": true,
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 {
			return nil
		}
		browser := parts[0]
		user := parts[1]

		switch {
		case browser == "safari":
			switch base {
			case "History.db":
				added += parseSafariHistory(em, path, user, ts)
			}
		case browser == "firefox":
			switch base {
			case "places.sqlite":
				added += parseFirefoxPlaces(em, path, user, ts)
			case "cookies.sqlite":
				added += parseFirefoxCookies(em, path, user, ts)
			case "formhistory.sqlite":
				added += parseFirefoxFormHistory(em, path, user, ts)
			case "downloads.sqlite":
				added += parseFirefoxDownloads(em, path, user, ts)
			}
		case chromiumFamily[browser]:
			switch base {
			case "History":
				added += parseChromiumHistory(em, path, browser, user, ts)
			case "Cookies":
				added += parseChromiumCookies(em, path, browser, user, ts)
			case "Login Data":
				added += parseChromiumLoginData(em, path, browser, user, ts)
			}
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Safari History.db (since macOS 10.10)
// ---------------------------------------------------------------------------

func parseSafariHistory(em *core.Emitter, path, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "history_visits") || !core.HasTable(db, "history_items") {
		return 0
	}
	q := `SELECT v.visit_time, i.url, i.domain_expansion, v.title, v.load_successful
	FROM history_visits v
	JOIN history_items i ON v.history_item = i.id`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var visitTime float64
		var url string
		var domain, title sql.NullString
		var loadOK sql.NullInt64
		if err := rows.Scan(&visitTime, &url, &domain, &title, &loadOK); err != nil {
			continue
		}
		t := core.IsoFromTime(core.SafariMacAbsoluteToTime(visitTime))
		if t == "" {
			t = defaultTS
		}
		msg := url
		if title.Valid && title.String != "" {
			msg = title.String + " (" + url + ")"
		}
		attrs := map[string]interface{}{
			"browser":     "safari",
			"username":    user,
			"url":         url,
			"title":       title.String,
			"domain":      domain.String,
			"load_ok":     loadOK.Int64,
			"profile":     "default",
			"visit_count": nil,
		}
		if em.AddEvent(t, "Web Page Visited", msg, "web_history",
			"RR-MacOS", "ResponseRay macOS Collector - Safari History",
			"darwin:browser:safari:history", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Chromium-family History (urls / visits / downloads)
// ---------------------------------------------------------------------------

func parseChromiumHistory(em *core.Emitter, path, browser, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "urls") || !core.HasTable(db, "visits") {
		return 0
	}
	added := 0

	// Visits joined to URLs.
	q := `SELECT v.visit_time, u.url, u.title, u.visit_count, u.typed_count, v.transition
	FROM visits v JOIN urls u ON v.url = u.id`
	rows, err := db.Query(q)
	if err == nil {
		for rows.Next() {
			var vt int64
			var url, title sql.NullString
			var visitCount, typedCount, transition sql.NullInt64
			if err := rows.Scan(&vt, &url, &title, &visitCount, &typedCount, &transition); err != nil {
				continue
			}
			t := core.IsoFromTime(core.ChromeWebkitToTime(vt))
			if t == "" {
				t = defaultTS
			}
			msg := url.String
			if title.Valid && title.String != "" {
				msg = title.String + " (" + url.String + ")"
			}
			attrs := map[string]interface{}{
				"browser":     browser,
				"username":    user,
				"url":         url.String,
				"title":       title.String,
				"visit_count": visitCount.Int64,
				"typed_count": typedCount.Int64,
				"transition":  transition.Int64,
			}
			if em.AddEvent(t, "Web Page Visited", msg, "web_history",
				"RR-MacOS", "ResponseRay macOS Collector - "+browser+" History",
				"darwin:browser:"+browser+":history", attrs) {
				added++
			}
		}
		rows.Close()
	}

	// Downloads.
	if core.HasTable(db, "downloads") {
		dq := `SELECT start_time, end_time, target_path, tab_url, mime_type, total_bytes, state
		FROM downloads`
		rows, err := db.Query(dq)
		if err == nil {
			for rows.Next() {
				var startT, endT, totalBytes sql.NullInt64
				var targetPath, tabURL, mime sql.NullString
				var state sql.NullInt64
				if err := rows.Scan(&startT, &endT, &targetPath, &tabURL, &mime, &totalBytes, &state); err != nil {
					continue
				}
				t := core.IsoFromTime(core.ChromeWebkitToTime(startT.Int64))
				if t == "" {
					t = defaultTS
				}
				msg := fmt.Sprintf("Download: %s <- %s", targetPath.String, tabURL.String)
				attrs := map[string]interface{}{
					"browser":      browser,
					"username":     user,
					"target_path":  targetPath.String,
					"source_url":   tabURL.String,
					"mime_type":    mime.String,
					"total_bytes":  totalBytes.Int64,
					"state":        state.Int64,
				}
				if em.AddEvent(t, "File Downloaded", msg, "web_download",
					"RR-MacOS", "ResponseRay macOS Collector - "+browser+" Downloads",
					"darwin:browser:"+browser+":download", attrs) {
					added++
				}
			}
			rows.Close()
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Chromium-family Cookies
// ---------------------------------------------------------------------------

func parseChromiumCookies(em *core.Emitter, path, browser, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "cookies") {
		return 0
	}
	q := `SELECT creation_utc, host_key, name, path, expires_utc, is_secure, is_httponly
	FROM cookies`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var creation, expires sql.NullInt64
		var hostKey, name, cookiePath sql.NullString
		var isSecure, isHTTPOnly sql.NullInt64
		if err := rows.Scan(&creation, &hostKey, &name, &cookiePath, &expires, &isSecure, &isHTTPOnly); err != nil {
			continue
		}
		t := core.IsoFromTime(core.ChromeWebkitToTime(creation.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := fmt.Sprintf("Cookie %s on %s", name.String, hostKey.String)
		attrs := map[string]interface{}{
			"browser":     browser,
			"username":    user,
			"host":        hostKey.String,
			"name":        name.String,
			"path":        cookiePath.String,
			"expires_utc": expires.Int64,
			"is_secure":   isSecure.Int64,
			"is_httponly": isHTTPOnly.Int64,
		}
		if em.AddEvent(t, "Cookie Created", msg, "web_cookie",
			"RR-MacOS", "ResponseRay macOS Collector - "+browser+" Cookies",
			"darwin:browser:"+browser+":cookie", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Chromium-family Login Data (encrypted password vault metadata)
// ---------------------------------------------------------------------------

func parseChromiumLoginData(em *core.Emitter, path, browser, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "logins") {
		return 0
	}
	q := `SELECT origin_url, action_url, username_value, signon_realm,
		date_created, date_last_used, times_used FROM logins`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var origin, action, username, realm sql.NullString
		var created, lastUsed, timesUsed sql.NullInt64
		if err := rows.Scan(&origin, &action, &username, &realm, &created, &lastUsed, &timesUsed); err != nil {
			continue
		}
		t := core.IsoFromTime(core.ChromeWebkitToTime(created.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := fmt.Sprintf("Login saved: %s @ %s", username.String, origin.String)
		attrs := map[string]interface{}{
			"browser":      browser,
			"username":     user,
			"origin_url":   origin.String,
			"action_url":   action.String,
			"login_user":   username.String,
			"signon_realm": realm.String,
			"times_used":   timesUsed.Int64,
			"last_used":    core.IsoFromTime(core.ChromeWebkitToTime(lastUsed.Int64)),
		}
		if em.AddEvent(t, "Web Login Saved", msg, "web_login",
			"RR-MacOS", "ResponseRay macOS Collector - "+browser+" Login Data",
			"darwin:browser:"+browser+":login", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Firefox places.sqlite (history)
// ---------------------------------------------------------------------------

func parseFirefoxPlaces(em *core.Emitter, path, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "moz_places") || !core.HasTable(db, "moz_historyvisits") {
		return 0
	}
	q := `SELECT v.visit_date, p.url, p.title, p.visit_count, p.typed, v.visit_type
	FROM moz_historyvisits v JOIN moz_places p ON v.place_id = p.id`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()
	added := 0
	for rows.Next() {
		var visitDate sql.NullInt64
		var url, title sql.NullString
		var visitCount, typed, visitType sql.NullInt64
		if err := rows.Scan(&visitDate, &url, &title, &visitCount, &typed, &visitType); err != nil {
			continue
		}
		t := core.IsoFromTime(core.FirefoxPRTimeToTime(visitDate.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := url.String
		if title.Valid && title.String != "" {
			msg = title.String + " (" + url.String + ")"
		}
		attrs := map[string]interface{}{
			"browser":     "firefox",
			"username":    user,
			"url":         url.String,
			"title":       title.String,
			"visit_count": visitCount.Int64,
			"typed":       typed.Int64,
			"visit_type":  visitType.Int64,
		}
		if em.AddEvent(t, "Web Page Visited", msg, "web_history",
			"RR-MacOS", "ResponseRay macOS Collector - Firefox places",
			"darwin:browser:firefox:history", attrs) {
			added++
		}
	}
	return added
}

func parseFirefoxCookies(em *core.Emitter, path, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "moz_cookies") {
		return 0
	}
	q := `SELECT host, name, path, expiry, isSecure, isHttpOnly, creationTime
	FROM moz_cookies`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()
	added := 0
	for rows.Next() {
		var host, name, cookiePath sql.NullString
		var expiry, isSecure, isHTTPOnly, created sql.NullInt64
		if err := rows.Scan(&host, &name, &cookiePath, &expiry, &isSecure, &isHTTPOnly, &created); err != nil {
			continue
		}
		t := core.IsoFromTime(core.FirefoxPRTimeToTime(created.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := fmt.Sprintf("Cookie %s on %s", name.String, host.String)
		attrs := map[string]interface{}{
			"browser":     "firefox",
			"username":    user,
			"host":        host.String,
			"name":        name.String,
			"path":        cookiePath.String,
			"expiry":      expiry.Int64,
			"is_secure":   isSecure.Int64,
			"is_httponly": isHTTPOnly.Int64,
		}
		if em.AddEvent(t, "Cookie Created", msg, "web_cookie",
			"RR-MacOS", "ResponseRay macOS Collector - Firefox Cookies",
			"darwin:browser:firefox:cookie", attrs) {
			added++
		}
	}
	return added
}

func parseFirefoxFormHistory(em *core.Emitter, path, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "moz_formhistory") {
		return 0
	}
	q := `SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()
	added := 0
	for rows.Next() {
		var field, val sql.NullString
		var timesUsed, firstUsed, lastUsed sql.NullInt64
		if err := rows.Scan(&field, &val, &timesUsed, &firstUsed, &lastUsed); err != nil {
			continue
		}
		t := core.IsoFromTime(core.FirefoxPRTimeToTime(lastUsed.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := fmt.Sprintf("Form value: %s = %s", field.String, val.String)
		if em.AddEvent(t, "Form Field Filled", msg, "form_history",
			"RR-MacOS", "ResponseRay macOS Collector - Firefox FormHistory",
			"darwin:browser:firefox:form", map[string]interface{}{
				"browser":    "firefox",
				"username":   user,
				"field_name": field.String,
				"value":      val.String,
				"times_used": timesUsed.Int64,
				"first_used": core.IsoFromTime(core.FirefoxPRTimeToTime(firstUsed.Int64)),
			}) {
			added++
		}
	}
	return added
}

func parseFirefoxDownloads(em *core.Emitter, path, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "moz_downloads") {
		return 0
	}
	q := `SELECT name, source, target, startTime, endTime, state, currBytes, maxBytes FROM moz_downloads`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()
	added := 0
	for rows.Next() {
		var name, source, target sql.NullString
		var startT, endT, state, curr, max sql.NullInt64
		if err := rows.Scan(&name, &source, &target, &startT, &endT, &state, &curr, &max); err != nil {
			continue
		}
		t := core.IsoFromTime(core.FirefoxPRTimeToTime(startT.Int64))
		if t == "" {
			t = defaultTS
		}
		msg := fmt.Sprintf("Download: %s <- %s", target.String, source.String)
		if em.AddEvent(t, "File Downloaded", msg, "web_download",
			"RR-MacOS", "ResponseRay macOS Collector - Firefox Downloads",
			"darwin:browser:firefox:download", map[string]interface{}{
				"browser":     "firefox",
				"username":    user,
				"name":        name.String,
				"source_url":  source.String,
				"target_path": target.String,
				"state":       state.Int64,
				"total_bytes": max.Int64,
			}) {
			added++
		}
	}
	return added
}
