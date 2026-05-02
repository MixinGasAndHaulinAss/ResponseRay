package collectors

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type ProcessCollector struct{}

func (c *ProcessCollector) Name() string { return "Processes" }
func (c *ProcessCollector) Description() string {
	return "Running processes (ps), per-PID /proc snapshot, lsof open files"
}

func (c *ProcessCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	if out, err := runCmd("ps", "-eo", "pid,ppid,user,group,start,time,pcpu,pmem,stat,wchan:32,cmd"); err == nil {
		_ = writeText(ctx, "live/processes_ps.txt", out, "processes")
		r.FilesCollected++
	}
	if out, err := runCmd("ps", "auxf"); err == nil {
		_ = writeText(ctx, "live/processes_tree.txt", out, "processes")
		r.FilesCollected++
	}
	if out, err := runCmd("lsof", "-n", "-P"); err == nil {
		_ = writeText(ctx, "live/lsof.txt", out, "processes")
		r.FilesCollected++
	}
	if out, err := runCmd("lsof", "-i", "-n", "-P"); err == nil {
		_ = writeText(ctx, "live/lsof_network.txt", out, "processes")
		r.FilesCollected++
	}

	procs := []map[string]any{}
	dirEntries, err := os.ReadDir("/proc")
	if err == nil {
		for _, d := range dirEntries {
			if !d.IsDir() {
				continue
			}
			pid := d.Name()
			if !isAllDigits(pid) {
				continue
			}
			snap := procSnapshot("/proc/"+pid, timestamp)
			if snap == nil {
				continue
			}
			procs = append(procs, snap)
		}
	}
	if size, err := ctx.WriteJSON("live/processes.json", "processes", procs); err == nil {
		r.FilesCollected++
		r.BytesCollected += size
	}

	r.Elapsed = time.Since(start)
	return r
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

func procSnapshot(procDir, timestamp string) map[string]any {
	pid := filepath.Base(procDir)
	cmdline, _ := os.ReadFile(filepath.Join(procDir, "cmdline"))
	status, _ := os.ReadFile(filepath.Join(procDir, "status"))
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	cwd, _ := os.Readlink(filepath.Join(procDir, "cwd"))
	root, _ := os.Readlink(filepath.Join(procDir, "root"))

	statusMap := parseProcStatus(string(status))
	envBytes, _ := os.ReadFile(filepath.Join(procDir, "environ"))

	return map[string]any{
		"pid":                  pid,
		"name":                 statusMap["Name"],
		"state":                statusMap["State"],
		"ppid":                 statusMap["PPid"],
		"uid":                  statusMap["Uid"],
		"gid":                  statusMap["Gid"],
		"cmdline":              normalizeCmdline(cmdline),
		"exe":                  exe,
		"cwd":                  cwd,
		"root":                 root,
		"environ":              normalizeCmdline(envBytes),
		"collection_timestamp": timestamp,
	}
}

func parseProcStatus(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		out[line[:idx]] = strings.TrimSpace(line[idx+1:])
	}
	return out
}

func normalizeCmdline(b []byte) string {
	for i := range b {
		if b[i] == 0 {
			b[i] = ' '
		}
	}
	return strings.TrimSpace(string(b))
}

// satisfy the unused import if io/fs ever gets dropped accidentally
var _ fs.DirEntry = (*emptyDirEntry)(nil)

type emptyDirEntry struct{}

func (emptyDirEntry) Name() string               { return "" }
func (emptyDirEntry) IsDir() bool                { return false }
func (emptyDirEntry) Type() fs.FileMode          { return 0 }
func (emptyDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
