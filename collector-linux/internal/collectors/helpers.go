package collectors

import (
	"os"
	"path/filepath"

	"github.com/responseray/collector-linux/internal/fsutil"
	"github.com/responseray/collector-linux/internal/manifest"
)

// writeText writes the given content to relPath under ctx.OutputDir and registers it in
// the manifest. Returns the size on disk or 0 on failure.
func writeText(ctx *fsutil.Context, relPath, content, category string) int64 {
	dest := filepath.Join(ctx.OutputDir, relPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0
	}
	if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
		return 0
	}
	info, err := os.Stat(dest)
	if err != nil {
		return 0
	}
	ctx.Add(manifest.FileEntry{
		OriginalPath: dest,
		RelativePath: filepath.ToSlash(relPath),
		Category:     category,
		Size:         info.Size(),
	})
	return info.Size()
}

// userHomes returns a list of (username, home) pairs from /etc/passwd. Filters out service
// accounts whose home is /nonexistent or /sbin/nologin pseudo paths.
func userHomes() []struct {
	User string
	Home string
} {
	out := []struct {
		User string
		Home string
	}{}

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return out
	}
	defer f.Close()

	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 4096)
	for {
		n, _ := f.Read(tmp)
		if n == 0 {
			break
		}
		buf = append(buf, tmp[:n]...)
	}

	for _, line := range splitLines(string(buf)) {
		parts := splitFields(line, ':', 7)
		if len(parts) < 7 {
			continue
		}
		user := parts[0]
		home := parts[5]
		if home == "" || home == "/" || home == "/nonexistent" {
			continue
		}
		if _, err := os.Stat(home); err != nil {
			continue
		}
		out = append(out, struct {
			User string
			Home string
		}{User: user, Home: home})
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func splitFields(s string, sep rune, max int) []string {
	out := make([]string, 0, max)
	cur := ""
	count := 0
	for _, r := range s {
		if r == sep && count < max-1 {
			out = append(out, cur)
			cur = ""
			count++
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
