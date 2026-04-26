package collectors

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/responseray/collector-macos/internal/fsutil"
)

// MailCollector collects Mail.app metadata (Envelope Index, mailbox plists)
// without copying the full message store, which is typically huge.
type MailCollector struct{}

func (MailCollector) Name() string { return "Mail" }

func (MailCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		mailRoot := filepath.Join(home, "Library", "Mail")
		ctx.CaptureGlob(mailRoot,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(filepath.Base(path))
				switch {
				case strings.HasPrefix(lower, "envelope index"):
					return info.Size() < fsutil.MaxSingleFileBytes
				case lower == "mailboxes.plist", lower == "smartmailboxes.plist", lower == "rules.plist", lower == "signatures.plist":
					return info.Size() < 4*1024*1024
				case lower == "info.plist" && strings.Contains(path, "/V"):
					return info.Size() < 1*1024*1024
				}
				return false
			},
			func(path string) string {
				rel, _ := filepath.Rel(home, path)
				return filepath.Join("artifacts/mail", user, rel)
			},
			"mail",
		)
		mailPrefs := filepath.Join(home, "Library", "Containers", "com.apple.mail", "Data", "Library", "Preferences")
		ctx.CaptureGlob(mailPrefs,
			func(path string, info fs.FileInfo) bool {
				lower := strings.ToLower(path)
				return strings.HasSuffix(lower, ".plist") && info.Size() < 4*1024*1024
			},
			func(path string) string {
				return filepath.Join("artifacts/mail/containers", user, filepath.Base(path))
			},
			"mail_prefs",
		)
	}
	return nil
}

// MessagesCollector copies iMessage chat databases.
type MessagesCollector struct{}

func (MessagesCollector) Name() string { return "Messages" }

func (MessagesCollector) Run(ctx *fsutil.Context) error {
	for _, home := range userHomes() {
		user := usernameFromHome(home)
		base := filepath.Join(home, "Library", "Messages")
		files := []string{"chat.db", "chat.db-wal", "chat.db-shm"}
		for _, f := range files {
			src := filepath.Join(base, f)
			ctx.CaptureFile(src, filepath.Join("artifacts/messages", user, f), "messages")
		}
		ctx.CaptureGlob(filepath.Join(base, "Attachments"),
			func(path string, info fs.FileInfo) bool { return info.Size() < 10*1024*1024 },
			func(path string) string {
				rel, _ := filepath.Rel(base, path)
				return filepath.Join("artifacts/messages", user, rel)
			},
			"messages_attachments",
		)
	}
	return nil
}
