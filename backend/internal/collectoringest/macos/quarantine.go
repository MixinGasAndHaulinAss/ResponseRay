package macos

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacQuarantineDB parses each captured QuarantineEventsV2 SQLite
// database under artifacts/quarantine/<user>/ and emits one file_downloaded
// event per row. The quarantine DB records the URL, agent and timestamp
// macOS attaches to any file delivered through Gatekeeper-aware programs
// (browsers, mail clients, AirDrop, etc.).
//
// This replaces the older walk-only `processMacQuarantine` which just emitted
// a single "file captured" event per database without cracking it open.
func processMacQuarantineDB(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "quarantine")
	if _, err := exists(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		// File is named "com.apple.LaunchServices.QuarantineEventsV2" — check Contains not HasPrefix
		if !strings.Contains(base, "QuarantineEventsV2") {
			return nil
		}
		if strings.HasSuffix(base, "-wal") || strings.HasSuffix(base, "-shm") || strings.HasSuffix(base, "-journal") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		user := ""
		if parts := strings.Split(filepath.ToSlash(rel), "/"); len(parts) >= 2 {
			user = parts[0]
		}
		added += parseQuarantineDB(em, path, user, ts)
		return nil
	})
	return added
}

func parseQuarantineDB(em *core.Emitter, path, user, ts string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "LSQuarantineEvent") {
		return 0
	}

	q := `SELECT
		LSQuarantineEventIdentifier,
		LSQuarantineTimeStamp,
		LSQuarantineAgentName,
		LSQuarantineAgentBundleIdentifier,
		LSQuarantineDataURLString,
		LSQuarantineSenderName,
		LSQuarantineSenderAddress,
		LSQuarantineTypeNumber,
		LSQuarantineOriginTitle,
		LSQuarantineOriginURLString,
		LSQuarantineOriginAlias
	FROM LSQuarantineEvent`
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		var id, agentName, agentBundle, dataURL, senderName, senderAddr, originTitle, originURL string
		var ts2 float64
		var typeNum int64
		var alias interface{}
		if err := rows.Scan(&id, &ts2, &agentName, &agentBundle, &dataURL, &senderName, &senderAddr, &typeNum, &originTitle, &originURL, &alias); err != nil {
			continue
		}
		t := core.IsoFromTime(core.AppleAbsoluteToTime(ts2))
		if t == "" {
			t = ts
		}
		msg := fmt.Sprintf("Download: %s (via %s)", dataURL, agentName)
		attrs := map[string]interface{}{
			"event_id":       id,
			"agent_name":     agentName,
			"agent_bundle":   agentBundle,
			"data_url":       dataURL,
			"origin_url":     originURL,
			"origin_title":   originTitle,
			"sender_name":    senderName,
			"sender_address": senderAddr,
			"type_number":    typeNum,
			"username":       user,
			"db_path":        filepath.Base(path),
		}
		if em.AddEvent(t, "Quarantine: File Downloaded", msg, "file_downloaded",
			"RR-MacOS", "ResponseRay macOS Collector - QuarantineEventsV2",
			"darwin:quarantine:event", attrs) {
			added++
		}
	}
	return added
}
