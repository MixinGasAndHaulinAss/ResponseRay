package collectors

import (
	"os/exec"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// SystemInfoCollector captures /etc/os-release, /etc/hostname, /etc/timezone, kernel version,
// uptime, and uname output.
type SystemInfoCollector struct{}

func (c *SystemInfoCollector) Name() string { return "SystemInfo" }
func (c *SystemInfoCollector) Description() string {
	return "Distro release, hostname, kernel, uptime, timezone"
}

func (c *SystemInfoCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	files := []string{
		"/etc/os-release",
		"/etc/lsb-release",
		"/etc/hostname",
		"/etc/timezone",
		"/etc/machine-id",
		"/etc/issue",
		"/etc/redhat-release",
		"/etc/debian_version",
		"/proc/version",
		"/proc/cmdline",
		"/proc/meminfo",
		"/proc/cpuinfo",
		"/proc/uptime",
		"/proc/sys/kernel/hostname",
	}
	for _, f := range files {
		if ctx.CaptureFile(f, "artifacts/system/"+strings.TrimPrefix(f, "/"), "system_info") {
			r.FilesCollected++
		}
	}

	info := map[string]any{
		"collection_timestamp": timestamp,
		"hostname":             ctx.Hostname,
	}
	for _, cmd := range []struct {
		key  string
		args []string
	}{
		{"uname_-a", []string{"uname", "-a"}},
		{"uptime", []string{"uptime"}},
		{"date", []string{"date", "-u"}},
		{"timedatectl", []string{"timedatectl"}},
		{"locale", []string{"locale"}},
		{"who_-a", []string{"who", "-a"}},
		{"id", []string{"id"}},
	} {
		out, _ := runCmd(cmd.args...)
		info[cmd.key] = out
	}
	if size, err := ctx.WriteJSON("live/system_info.json", "system_info", info); err == nil {
		r.FilesCollected++
		r.BytesCollected += size
	}

	r.Elapsed = time.Since(start)
	return r
}

func runCmd(args ...string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
