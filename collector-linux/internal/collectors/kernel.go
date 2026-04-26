package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type KernelCollector struct{}

func (c *KernelCollector) Name() string        { return "Kernel" }
func (c *KernelCollector) Description() string { return "Loaded kernel modules, sysctl, dmesg, tainted kernel detection" }

func (c *KernelCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	files := []string{
		"/proc/modules",
		"/proc/kallsyms",
		"/proc/sys/kernel/tainted",
		"/proc/sys/kernel/randomize_va_space",
		"/proc/sys/kernel/core_pattern",
		"/proc/cmdline",
		"/proc/keys",
		"/proc/key-users",
	}
	for _, f := range files {
		if ctx.CaptureFile(f, "artifacts/kernel"+f, "kernel") {
			r.FilesCollected++
		}
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"lsmod", []string{"lsmod"}},
		{"dmesg", []string{"dmesg", "-T"}},
		{"sysctl_-a", []string{"sysctl", "-a"}},
		{"modinfo_all", []string{"sh", "-c", "lsmod | awk 'NR>1 {print $1}' | xargs -I{} modinfo {} 2>/dev/null"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/kernel_"+c.name+".txt", out, "kernel")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
