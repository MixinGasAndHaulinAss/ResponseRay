package collectors

import (
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type ProcessCollector struct{}

func (ProcessCollector) Name() string { return "Processes" }

func (ProcessCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	if v, err := runCmd(30*time.Second, "ps", "auxwwe"); err == nil {
		out["ps_auxwwe"] = v
	}
	if v, err := runCmd(30*time.Second, "ps", "-eo", "pid,ppid,user,uid,gid,etime,start,stat,pcpu,pmem,rss,vsz,command"); err == nil {
		out["ps_columns"] = v
	}
	if v, err := runCmd(45*time.Second, "lsof", "-n", "-P"); err == nil {
		out["lsof"] = v
	}
	if v, err := runCmd(30*time.Second, "top", "-l", "1", "-n", "0"); err == nil {
		out["top_summary"] = v
	}
	if v, err := runCmd(30*time.Second, "vm_stat"); err == nil {
		out["vm_stat"] = v
	}
	if v, err := runCmd(30*time.Second, "fs_usage", "-w", "-t", "5"); err == nil {
		out["fs_usage_5s"] = v
	}
	if _, err := ctx.WriteJSON("live/processes.json", "processes", out); err != nil {
		return err
	}
	return nil
}

type KernelCollector struct{}

func (KernelCollector) Name() string { return "Kernel" }

func (KernelCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	if v, err := runCmd(15*time.Second, "kextstat", "-l"); err == nil {
		out["kextstat"] = v
	}
	if v, err := runCmd(15*time.Second, "systemextensionsctl", "list"); err == nil {
		out["systemextensionsctl_list"] = v
	}
	if v, err := runCmd(15*time.Second, "sysctl", "-a"); err == nil {
		out["sysctl_all"] = v
	}
	if v, err := runCmd(15*time.Second, "nvram", "-p"); err == nil {
		out["nvram"] = v
	}
	if _, err := ctx.WriteJSON("live/kernel.json", "kernel", out); err != nil {
		return err
	}
	return nil
}

type MountCollector struct{}

func (MountCollector) Name() string { return "Mounts" }

func (MountCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	if v, err := runCmd(15*time.Second, "mount"); err == nil {
		out["mount"] = v
	}
	if v, err := runCmd(15*time.Second, "df", "-h"); err == nil {
		out["df_h"] = v
	}
	if v, err := runCmd(15*time.Second, "df", "-i"); err == nil {
		out["df_i"] = v
	}
	if v, err := runCmd(30*time.Second, "diskutil", "list"); err == nil {
		out["diskutil_list"] = v
	}
	if v, err := runCmd(30*time.Second, "diskutil", "info", "-all"); err == nil {
		out["diskutil_info_all"] = v
	}
	if v, err := runCmd(30*time.Second, "diskutil", "apfs", "list"); err == nil {
		out["diskutil_apfs_list"] = v
	}
	if _, err := ctx.WriteJSON("live/mounts.json", "mounts", out); err != nil {
		return err
	}
	return nil
}
