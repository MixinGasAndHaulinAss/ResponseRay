// Package core - SQLite read helpers used by platform-specific raw-file
// parsers. Built on modernc.org/sqlite (pure-Go, CGO_ENABLED=0 friendly).
package core

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// OpenSQLiteReadOnly opens a copy of the database in read-only mode. Many of
// the macOS / browser SQLite databases we ingest are likely WAL-mode and may
// have a `-wal`/`-shm` sidecar; we therefore copy the main file plus any
// sidecars into a private temp directory before opening, to avoid corrupting
// or being blocked by the original.
func OpenSQLiteReadOnly(path string) (*sql.DB, func(), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, func() {}, err
	}
	tmpDir, err := os.MkdirTemp("", "rr-sqlite-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	base := filepath.Base(path)
	dst := filepath.Join(tmpDir, base)
	if err := copyFile(path, dst); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("copy main: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		s := path + suffix
		if _, err := os.Stat(s); err == nil {
			_ = copyFile(s, dst+suffix)
		}
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", dst)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		cleanup()
		return nil, func() {}, fmt.Errorf("ping: %w", err)
	}
	return db, func() { _ = db.Close(); cleanup() }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// HasTable reports whether the given table exists in the open SQLite database.
func HasTable(db *sql.DB, name string) bool {
	var n string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return err == nil && strings.EqualFold(n, name)
}

// AppleAbsoluteToTime converts an Apple "Mac absolute time" double (seconds
// since 2001-01-01 UTC) to a time.Time. Returns zero time on NaN/invalid.
func AppleAbsoluteToTime(secs float64) time.Time {
	if secs == 0 || secs != secs { // NaN check
		return time.Time{}
	}
	epoch := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	return epoch.Add(time.Duration(secs * float64(time.Second)))
}

// ChromeWebkitToTime converts a Chrome/Chromium WebKit timestamp (microseconds
// since 1601-01-01 UTC) to time.Time. Returns zero on invalid input.
func ChromeWebkitToTime(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return epoch.Add(time.Duration(us) * time.Microsecond)
}

// FirefoxPRTimeToTime converts Mozilla PRTime (microseconds since Unix epoch)
// to time.Time.
func FirefoxPRTimeToTime(us int64) time.Time {
	if us <= 0 {
		return time.Time{}
	}
	return time.UnixMicro(us)
}

// SafariMacAbsoluteToTime is a convenience alias for Safari history (which
// stores Mac-absolute seconds as a double).
func SafariMacAbsoluteToTime(secs float64) time.Time { return AppleAbsoluteToTime(secs) }

// ErrNoTable is returned when an expected table is missing from the database.
var ErrNoTable = errors.New("expected table not present")

// IsoFromTime renders a time.Time in the ISO 8601 millisecond UTC format
// expected by the rest of the ingest pipeline. Returns "" for zero times.
func IsoFromTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
