package collectors

import (
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type ShellHistoryCollector struct{}

func (c *ShellHistoryCollector) Name() string { return "ShellHistory" }
func (c *ShellHistoryCollector) Description() string {
	return "Per-user .bash_history, .zsh_history, .fish_history, .python_history, .lesshst, .viminfo, .mysql_history, .psql_history"
}

func (c *ShellHistoryCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	files := []string{
		".bash_history",
		".zsh_history",
		".fish_history",
		".history",
		".python_history",
		".lesshst",
		".viminfo",
		".mysql_history",
		".psql_history",
		".sqlite_history",
		".node_repl_history",
		".rediscli_history",
		".local/share/fish/fish_history",
	}

	for _, h := range userHomes() {
		for _, hf := range files {
			src := filepath.Join(h.Home, hf)
			rel := filepath.Join("artifacts/shell_history", h.User, filepath.Base(hf))
			if ctx.CaptureFile(src, rel, "shell_history") {
				r.FilesCollected++
			}
		}
	}
	if ctx.CaptureFile("/root/.bash_history", "artifacts/shell_history/root/.bash_history", "shell_history") {
		r.FilesCollected++
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
