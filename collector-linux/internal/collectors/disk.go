package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type DiskCollector struct{}

func (c *DiskCollector) Name() string        { return "Disk" }
func (c *DiskCollector) Description() string { return "lsblk, df, fdisk, fstab, blkid, partition info" }

func (c *DiskCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	if ctx.CaptureFile("/etc/fstab", "artifacts/disk/fstab", "disk") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/proc/mounts", "artifacts/disk/proc_mounts", "disk") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/proc/partitions", "artifacts/disk/proc_partitions", "disk") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/proc/swaps", "artifacts/disk/proc_swaps", "disk") {
		r.FilesCollected++
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"lsblk", []string{"lsblk", "-o", "NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,UUID,MOUNTPOINT,SIZE,TYPE,RM,RO,MODEL,SERIAL"}},
		{"df_-h", []string{"df", "-h"}},
		{"df_-i", []string{"df", "-i"}},
		{"blkid", []string{"blkid"}},
		{"fdisk_-l", []string{"fdisk", "-l"}},
		{"parted_-l", []string{"parted", "-l"}},
		{"vgs", []string{"vgs"}},
		{"lvs", []string{"lvs"}},
		{"pvs", []string{"pvs"}},
		{"mount", []string{"mount"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/disk_"+c.name+".txt", out, "disk")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

type MountCollector struct{}

func (c *MountCollector) Name() string        { return "Mounts" }
func (c *MountCollector) Description() string { return "Currently mounted filesystems and NFS exports" }

func (c *MountCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	if ctx.CaptureFile("/etc/exports", "artifacts/mounts/exports", "mounts") {
		r.FilesCollected++
	}
	if out, err := runCmd("findmnt", "-J"); err == nil {
		_ = writeText(ctx, "live/findmnt.json", out, "mounts")
		r.FilesCollected++
	}
	if out, err := runCmd("showmount", "-e"); err == nil {
		_ = writeText(ctx, "live/showmount.txt", out, "mounts")
		r.FilesCollected++
	}
	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

type MACCollector struct{}

func (c *MACCollector) Name() string        { return "MAC" }
func (c *MACCollector) Description() string { return "SELinux, AppArmor, chroot, capabilities" }

func (c *MACCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	if ctx.CaptureFile("/etc/selinux/config", "artifacts/mac/selinux_config", "mac") {
		r.FilesCollected++
	}
	if ctx.CaptureFile("/etc/apparmor.d", "artifacts/mac/apparmor.d", "mac") {
		r.FilesCollected++
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"sestatus", []string{"sestatus"}},
		{"getenforce", []string{"getenforce"}},
		{"semodule_-l", []string{"semodule", "-l"}},
		{"aa-status", []string{"aa-status"}},
		{"apparmor_status", []string{"apparmor_status"}},
		{"getcap_recursive", []string{"sh", "-c", "getcap -r / 2>/dev/null"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/mac_"+c.name+".txt", out, "mac")
			r.FilesCollected++
		}
	}
	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
