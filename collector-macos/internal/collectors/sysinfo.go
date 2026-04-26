package collectors

import (
	"runtime"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type SystemInfoCollector struct{}

func (SystemInfoCollector) Name() string { return "SystemInfo" }

func (SystemInfoCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{
		"go_arch":  runtime.GOARCH,
		"go_os":    runtime.GOOS,
		"hostname": ctx.Hostname,
	}
	if v, err := runCmd(10*time.Second, "sw_vers"); err == nil {
		out["sw_vers"] = v
	}
	if v, err := runCmd(10*time.Second, "uname", "-a"); err == nil {
		out["uname"] = v
	}
	if v, err := runCmd(15*time.Second, "system_profiler", "SPHardwareDataType", "SPSoftwareDataType"); err == nil {
		out["system_profiler"] = v
	}
	if v, err := runCmd(10*time.Second, "sysctl", "kern.boottime", "kern.osversion", "kern.osrelease", "kern.uuid", "hw.model"); err == nil {
		out["sysctl_kern"] = v
	}
	if v, err := runCmd(10*time.Second, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		out["ioreg_platform"] = v
	}
	if v, err := runCmd(10*time.Second, "csrutil", "status"); err == nil {
		out["csrutil_status"] = v
	}
	if v, err := runCmd(10*time.Second, "spctl", "--status"); err == nil {
		out["gatekeeper_status"] = v
	}
	if v, err := runCmd(10*time.Second, "fdesetup", "status"); err == nil {
		out["filevault_status"] = v
	}
	if _, err := ctx.WriteJSON("live/system_info.json", "system_info", out); err != nil {
		return err
	}
	return nil
}
