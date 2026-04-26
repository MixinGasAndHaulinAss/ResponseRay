package collectors

import (
	"path/filepath"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// QuarantineCollector copies LaunchServices QuarantineEventsV2 dbs.
type QuarantineCollector struct{}

func (QuarantineCollector) Name() string { return "Quarantine" }

func (QuarantineCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		base := filepath.Join(home, "Library", "Preferences")
		files := []string{
			"com.apple.LaunchServices.QuarantineEventsV2",
			"com.apple.LaunchServices.QuarantineEventsV2-shm",
			"com.apple.LaunchServices.QuarantineEventsV2-wal",
		}
		for _, f := range files {
			src := filepath.Join(base, f)
			ctx.CaptureFile(src, filepath.Join("artifacts/quarantine", user, f), "quarantine")
		}
	}
	return nil
}

// TCCCollector copies system + per-user TCC.db (Transparency, Consent, Control).
type TCCCollector struct{}

func (TCCCollector) Name() string { return "TCC" }

func (TCCCollector) Run(ctx *fsutil.Context) error {
	systemTCC := []string{
		"/Library/Application Support/com.apple.TCC/TCC.db",
		"/Library/Application Support/com.apple.TCC/TCC.db-shm",
		"/Library/Application Support/com.apple.TCC/TCC.db-wal",
	}
	for _, f := range systemTCC {
		ctx.CaptureFile(f, filepath.Join("artifacts/tcc/system", filepath.Base(f)), "tcc_system")
	}
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		base := filepath.Join(home, "Library", "Application Support", "com.apple.TCC")
		files := []string{"TCC.db", "TCC.db-shm", "TCC.db-wal"}
		for _, f := range files {
			src := filepath.Join(base, f)
			ctx.CaptureFile(src, filepath.Join("artifacts/tcc/users", user, f), "tcc_user")
		}
	}
	return nil
}

// KnowledgeCCollector copies the macOS knowledgeC.db (app/screen-time analytics).
type KnowledgeCCollector struct{}

func (KnowledgeCCollector) Name() string { return "KnowledgeC" }

func (KnowledgeCCollector) Run(ctx *fsutil.Context) error {
	systemKC := []string{
		"/private/var/db/CoreDuet/Knowledge/knowledgeC.db",
		"/private/var/db/CoreDuet/Knowledge/knowledgeC.db-shm",
		"/private/var/db/CoreDuet/Knowledge/knowledgeC.db-wal",
	}
	for _, f := range systemKC {
		ctx.CaptureFile(f, filepath.Join("artifacts/knowledgec/system", filepath.Base(f)), "knowledgec_system")
	}
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		base := filepath.Join(home, "Library", "Application Support", "Knowledge")
		files := []string{"knowledgeC.db", "knowledgeC.db-shm", "knowledgeC.db-wal"}
		for _, f := range files {
			src := filepath.Join(base, f)
			ctx.CaptureFile(src, filepath.Join("artifacts/knowledgec/users", user, f), "knowledgec_user")
		}
	}
	return nil
}
