package macos

import (
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacKnowledgeC walks artifacts/knowledgec/{system,users/<u>}/knowledgeC.db
// and emits per-row events for the highest-value streams in ZOBJECT:
//   - /app/usage           -> application_usage
//   - /app/inFocus         -> application_focus
//   - /app/intents         -> app_intent
//   - /device/isLocked     -> device_locked / device_unlocked
//   - /display/isBacklit   -> display_on / display_off
//   - /battery/percentage  -> battery_level
//
// knowledgeC is a CoreDuet SQLite database that records device-level events,
// most notably *exact* application launch / focus durations even after the
// app is uninstalled or the user clears their browsing history. It is one of
// the highest-value forensic artifacts on macOS / iOS.
func processMacKnowledgeC(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "knowledgec")
	if _, err := exists(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "knowledgeC.db" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		user := ""
		scope := "system"
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) >= 3 && parts[0] == "users" {
			scope = "user"
			user = parts[1]
		}
		added += parseKnowledgeC(em, path, scope, user, ts)
		return nil
	})
	return added
}

func parseKnowledgeC(em *core.Emitter, path, scope, user, defaultTS string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "ZOBJECT") {
		return 0
	}

	// Streams of interest. Each row in ZOBJECT belongs to a stream identified
	// by ZSTREAMNAME. Times are stored as Mac absolute time (seconds since
	// 2001-01-01 UTC) in ZSTARTDATE / ZENDDATE / ZCREATIONDATE.
	streams := []string{
		"/app/usage",
		"/app/inFocus",
		"/app/intents",
		"/app/activity",
		"/app/webUsage",
		"/device/isLocked",
		"/display/isBacklit",
		"/battery/percentage",
		"/portrait/topic",
		"/safari/history",
	}

	added := 0
	for _, stream := range streams {
		added += knowledgeCStream(em, db, stream, path, scope, user, defaultTS)
	}
	return added
}

func knowledgeCStream(em *core.Emitter, db *sql.DB, stream, path, scope, user, defaultTS string) int {
	q := `SELECT
		Z_PK,
		ZSTREAMNAME,
		ZVALUESTRING,
		ZVALUEINTEGER,
		ZVALUEDOUBLE,
		ZSECONDSFROMGMT,
		ZSTARTDATE,
		ZENDDATE,
		ZCREATIONDATE
	FROM ZOBJECT WHERE ZSTREAMNAME = ?`
	rows, err := db.Query(q, stream)
	if err != nil {
		return 0
	}
	defer rows.Close()

	eventTypeFor := func(stream string) (string, string) {
		switch stream {
		case "/app/usage":
			return "application_usage", "App Used"
		case "/app/inFocus":
			return "application_focus", "App In Focus"
		case "/app/intents":
			return "app_intent", "App Intent"
		case "/app/activity":
			return "app_activity", "App Activity"
		case "/app/webUsage":
			return "web_usage", "Web Usage"
		case "/device/isLocked":
			return "device_lock", "Device Lock State"
		case "/display/isBacklit":
			return "display_state", "Display Backlit State"
		case "/battery/percentage":
			return "battery_level", "Battery Level"
		case "/portrait/topic":
			return "device_topic", "Device Topic"
		case "/safari/history":
			return "web_history", "Safari Browsing History"
		default:
			return "device_event", stream
		}
	}
	etype, edesc := eventTypeFor(stream)

	added := 0
	for rows.Next() {
		var pk int64
		var sname string
		var vstr sql.NullString
		var vint sql.NullInt64
		var vdouble sql.NullFloat64
		var secsFromGMT sql.NullInt64
		var zstart, zend, zcreate sql.NullFloat64
		if err := rows.Scan(&pk, &sname, &vstr, &vint, &vdouble, &secsFromGMT, &zstart, &zend, &zcreate); err != nil {
			continue
		}

		eventTime := defaultTS
		if zstart.Valid && zstart.Float64 > 0 {
			if iso := core.IsoFromTime(core.AppleAbsoluteToTime(zstart.Float64)); iso != "" {
				eventTime = iso
			}
		} else if zcreate.Valid && zcreate.Float64 > 0 {
			if iso := core.IsoFromTime(core.AppleAbsoluteToTime(zcreate.Float64)); iso != "" {
				eventTime = iso
			}
		}
		endTime := ""
		if zend.Valid && zend.Float64 > 0 {
			endTime = core.IsoFromTime(core.AppleAbsoluteToTime(zend.Float64))
		}

		var msg string
		switch stream {
		case "/app/usage", "/app/inFocus", "/app/intents", "/app/activity":
			bundle := vstr.String
			msg = fmt.Sprintf("App used: %s", bundle)
		case "/device/isLocked":
			state := "unlocked"
			if vint.Valid && vint.Int64 == 1 {
				state = "locked"
			}
			msg = "Device " + state
			if state == "locked" {
				etype = "device_locked"
			} else {
				etype = "device_unlocked"
			}
		case "/display/isBacklit":
			state := "off"
			if vint.Valid && vint.Int64 == 1 {
				state = "on"
			}
			msg = "Display " + state
			if state == "on" {
				etype = "display_on"
			} else {
				etype = "display_off"
			}
		case "/battery/percentage":
			pct := 0.0
			if vdouble.Valid {
				pct = vdouble.Float64
			}
			msg = fmt.Sprintf("Battery %.0f%%", pct*100)
		case "/safari/history":
			msg = "Safari history: " + vstr.String
		default:
			msg = stream + ": " + vstr.String
		}

		attrs := map[string]interface{}{
			"stream":       stream,
			"value_string": vstr.String,
			"value_int":    asNullInt64(vint),
			"value_double": asNullFloat64(vdouble),
			"start_time":   eventTime,
			"end_time":     endTime,
			"scope":        scope,
			"username":     user,
		}
		if em.AddEvent(eventTime, edesc, msg, etype,
			"RR-MacOS", "ResponseRay macOS Collector - knowledgeC.db",
			"darwin:knowledgec:"+strings.TrimPrefix(stream, "/"), attrs) {
			added++
		}
	}
	return added
}

func asNullInt64(v sql.NullInt64) interface{} {
	if v.Valid {
		return v.Int64
	}
	return nil
}
func asNullFloat64(v sql.NullFloat64) interface{} {
	if v.Valid {
		return v.Float64
	}
	return nil
}
