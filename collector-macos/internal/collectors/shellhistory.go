package collectors

import (
	"path/filepath"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type ShellHistoryCollector struct{}

func (ShellHistoryCollector) Name() string { return "ShellHistory" }

func (ShellHistoryCollector) Run(ctx *fsutil.Context) error {
	candidates := []string{
		".bash_history",
		".zsh_history",
		".sh_history",
		".history",
		".lesshst",
		".viminfo",
		".python_history",
		".node_repl_history",
		".psql_history",
		".mysql_history",
		".sqlite_history",
		".rediscli_history",
		".irb_history",
	}

	homes := append([]string{"/var/root"}, userHomes()...)
	for _, home := range homes {
		user := usernameFromHome(home)
		for _, name := range candidates {
			src := filepath.Join(home, name)
			rel := filepath.Join("artifacts/shell_history", user, name)
			ctx.CaptureFile(src, rel, "shell_history")
		}
	}
	return nil
}
