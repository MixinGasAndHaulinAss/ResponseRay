package macos

import (
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processMacTCC walks artifacts/tcc/{system,users/<u>}/TCC.db files and emits
// one tcc_grant event per row in `access`. The TCC database mediates which
// applications have been granted (or denied) access to user data and devices
// like the camera, microphone, full-disk access, accessibility, etc.
func processMacTCC(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "tcc")
	if _, err := exists(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "TCC.db" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		scope := "system"
		user := ""
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) >= 3 && parts[0] == "users" {
			scope = "user"
			user = parts[1]
		}
		added += parseTCCDatabase(em, path, scope, user, ts)
		return nil
	})
	return added
}

func parseTCCDatabase(em *core.Emitter, path, scope, user, ts string) int {
	db, cleanup, err := core.OpenSQLiteReadOnly(path)
	if err != nil {
		return 0
	}
	defer cleanup()
	if !core.HasTable(db, "access") {
		return 0
	}

	// Schema differs across macOS versions. Build column list dynamically and
	// SELECT only the columns that exist.
	cols := tccColumns(db)
	have := map[string]bool{}
	for _, c := range cols {
		have[c] = true
	}
	wanted := []string{
		"service", "client", "client_type", "auth_value", "auth_reason",
		"auth_version", "csreq", "policy_id", "indirect_object_identifier",
		"indirect_object_identifier_type", "flags", "last_modified",
		"pid", "pid_version", "boot_uuid",
	}
	selectCols := []string{}
	for _, c := range wanted {
		if have[c] {
			selectCols = append(selectCols, c)
		}
	}
	if len(selectCols) == 0 {
		return 0
	}

	q := "SELECT " + strings.Join(selectCols, ", ") + " FROM access"
	rows, err := db.Query(q)
	if err != nil {
		return 0
	}
	defer rows.Close()

	added := 0
	for rows.Next() {
		holders := make([]interface{}, len(selectCols))
		ptrs := make([]interface{}, len(selectCols))
		for i := range holders {
			ptrs[i] = &holders[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := map[string]interface{}{}
		for i, c := range selectCols {
			row[c] = sqlValue(holders[i])
		}

		eventTime := ts
		if v, ok := row["last_modified"]; ok {
			if epoch, ok := asInt64(v); ok && epoch > 0 {
				eventTime = core.EpochToISO(epoch)
			}
		}

		service := strings.TrimPrefix(asString(row["service"]), "kTCC")
		client := asString(row["client"])
		auth := tccAuthLabel(asInt64Default(row["auth_value"], 0))

		msg := fmt.Sprintf("TCC grant: %s -> %s = %s", client, service, auth)
		if scope == "user" && user != "" {
			msg += " (user " + user + ")"
		}
		attrs := map[string]interface{}{
			"setting":    "tcc_grant",
			"service":    asString(row["service"]),
			"service_short": service,
			"client":     client,
			"client_type": row["client_type"],
			"auth_value": row["auth_value"],
			"auth_label": auth,
			"auth_reason": row["auth_reason"],
			"flags":      row["flags"],
			"last_modified": row["last_modified"],
			"scope":      scope,
			"username":   user,
			"db_path":    filepath.Base(path),
		}
		if em.AddEvent(eventTime, "TCC Grant Modified", msg, "tcc_grant",
			"RR-MacOS", "ResponseRay macOS Collector - TCC.db",
			"darwin:tcc:access", attrs) {
			added++
		}
	}
	return added
}

func tccColumns(db *sql.DB) []string {
	rows, err := db.Query("PRAGMA table_info(access)")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		cols = append(cols, name)
	}
	return cols
}

func tccAuthLabel(v int64) string {
	switch v {
	case 0:
		return "denied"
	case 1:
		return "unknown"
	case 2:
		return "allowed"
	case 3:
		return "limited"
	case 4:
		return "added_modified_by_user"
	default:
		return fmt.Sprintf("auth_%d", v)
	}
}
