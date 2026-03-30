package timeline

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"

	_ "modernc.org/sqlite"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "timeline" }
func (e *Extractor) Description() string { return "Windows Timeline (ActivitiesCache.db)" }

// Activity type names
var activityTypes = map[int]string{
	5:  "Open File/Document",
	6:  "App In Focus",
	10: "Clipboard",
	11: "System Settings",
	16: "App Launch",
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`ActivitiesCache\.db$`, "")
	if err != nil {
		return 0, err
	}

	added := 0
	for _, f := range files {
		dbPath, cleanup, err := resolveTimelineDB(f)
		if err != nil || dbPath == "" {
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			continue
		}

		n, err := parseActivities(db, conv)
		db.Close()
		if err != nil {
			progress.Warning(fmt.Sprintf("Timeline DB: %v", err))
			continue
		}
		added += n
	}

	progress.Info(fmt.Sprintf("Timeline: %d activity entries", added))
	return added, nil
}

func resolveTimelineDB(f cache.CollectedFile) (string, func(), error) {
	if f.DiskPath != "" {
		return f.DiskPath, nil, nil
	}
	decoded, err := extractors.GetFileContent(f)
	if err != nil || len(decoded) == 0 {
		return "", nil, err
	}
	tmpFile, err := writeTempDB(decoded, "timeline-*.db")
	if err != nil {
		return "", nil, err
	}
	return tmpFile, func() { os.Remove(tmpFile) }, nil
}

func parseActivities(db *sql.DB, conv *converter.Converter) (int, error) {
	rows, err := db.Query(`
		SELECT AppId, ActivityType, LastModifiedTime, StartTime, EndTime,
		       CreatedInCloud, Tag, Group_, PackageIdHash, ActivityStatus
		FROM Activity
		WHERE LastModifiedTime > 0
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var appIDRaw sql.NullString
		var actType int
		var lastMod, startTime, endTime sql.NullFloat64
		var cloud sql.NullInt64
		var tag, group_, pkgHash sql.NullString
		var status sql.NullInt64

		if err := rows.Scan(&appIDRaw, &actType, &lastMod, &startTime, &endTime,
			&cloud, &tag, &group_, &pkgHash, &status); err != nil {
			continue
		}

		// Parse timestamp (stored as FILETIME or Unix seconds depending on version)
		var ts string
		if lastMod.Valid && lastMod.Float64 > 0 {
			val := int64(lastMod.Float64)
			if val > 100000000000 {
				// FILETIME
				ts = converter.FiletimeToISO(val)
			} else {
				// Unix seconds
				ts = converter.EpochMsToISO(val * 1000)
			}
		}
		if ts == "" {
			continue
		}

		// Parse AppId JSON to get application name
		app := "Unknown"
		if appIDRaw.Valid {
			app = parseAppID(appIDRaw.String)
		}

		actTypeStr := activityTypes[actType]
		if actTypeStr == "" {
			actTypeStr = fmt.Sprintf("Type-%d", actType)
		}

		entry := converter.Artifact{
			"timestamp":         ts,
			"application":       app,
			"activity_type":     actType,
			"activity_type_str": actTypeStr,
		}
		if tag.Valid {
			entry["tag"] = tag.String
		}
		if group_.Valid {
			entry["group"] = group_.String
		}

		if actType == 6 {
			// User engaged
			var duration int
			if startTime.Valid && endTime.Valid && endTime.Float64 > startTime.Float64 {
				duration = int(endTime.Float64 - startTime.Float64)
			}
			entry["duration_seconds"] = duration
			if conv.ConvertTimelineUserEngaged(entry) {
				added++
			}
		} else {
			if conv.ConvertTimelineGeneric(entry) {
				added++
			}
		}
	}
	return added, nil
}

func parseAppID(raw string) string {
	// AppId is a JSON array of objects with "application" and "platform" fields
	var appIDs []map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &appIDs); err != nil {
		return raw
	}
	for _, entry := range appIDs {
		if app, ok := entry["application"].(string); ok && app != "" {
			return app
		}
	}
	return raw
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
