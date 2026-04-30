package collectors

import (
	"io/fs"
	"path/filepath"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// SecurityCollector captures security-relevant artifacts: SUID binaries,
// shared memory, ulimits, lock files, and mail spool.
type SecurityCollector struct{}

func (c *SecurityCollector) Name() string        { return "Security" }
func (c *SecurityCollector) Description() string { return "SUID binaries, shared memory, ulimits, lock files, capabilities" }

func (c *SecurityCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// SUID binaries - critical for privilege escalation analysis
	if out, err := runCmd("find", "/", "-xdev", "-perm", "-4000", "-type", "f", "-exec", "ls", "-la", "{}", ";"); err == nil {
		_ = writeText(ctx, "live/suid_binaries.txt", out, "security")
		r.FilesCollected++
	}

	// SGID binaries
	if out, err := runCmd("find", "/", "-xdev", "-perm", "-2000", "-type", "f", "-exec", "ls", "-la", "{}", ";"); err == nil {
		_ = writeText(ctx, "live/sgid_binaries.txt", out, "security")
		r.FilesCollected++
	}

	// World-writable files (potential backdoors)
	if out, err := runCmd("find", "/", "-xdev", "-perm", "-0002", "-type", "f", "-exec", "ls", "-la", "{}", ";"); err == nil {
		_ = writeText(ctx, "live/world_writable.txt", out, "security")
		r.FilesCollected++
	}

	// Shared memory segments
	if out, err := runCmd("ipcs", "-m"); err == nil {
		_ = writeText(ctx, "live/shm_segments.txt", out, "security")
		r.FilesCollected++
	}
	if out, err := runCmd("ipcs", "-a"); err == nil {
		_ = writeText(ctx, "live/ipc_all.txt", out, "security")
		r.FilesCollected++
	}

	// /dev/shm listing
	if info, err := stat("/dev/shm"); err == nil && info.IsDir() {
		if out, err := runCmd("ls", "-la", "/dev/shm"); err == nil {
			_ = writeText(ctx, "live/dev_shm.txt", out, "security")
			r.FilesCollected++
		}
	}

	// Ulimit information
	if out, err := runCmd("ulimit", "-a"); err == nil {
		_ = writeText(ctx, "live/ulimit.txt", out, "security")
		r.FilesCollected++
	}

	// Resource limits config
	if ctx.CaptureFile("/etc/security/limits.conf", "artifacts/security/limits.conf", "security") {
		r.FilesCollected++
	}
	if info, err := stat("/etc/security/limits.d"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/security/limits.d", nil,
			func(p string) string {
				return "artifacts/security/limits.d/" + filepath.Base(p)
			}, "security")
		r.FilesCollected += count
	}

	// Lock files
	for _, lockDir := range []string{"/var/lock", "/run/lock"} {
		if info, err := stat(lockDir); err == nil && info.IsDir() {
			if out, err := runCmd("ls", "-laR", lockDir); err == nil {
				_ = writeText(ctx, "live/locks_"+filepath.Base(lockDir)+".txt", out, "security")
				r.FilesCollected++
			}
		}
	}

	// Mail spool (can reveal user activity)
	for _, mailDir := range []string{"/var/mail", "/var/spool/mail"} {
		if info, err := stat(mailDir); err == nil && info.IsDir() {
			if out, err := runCmd("ls", "-la", mailDir); err == nil {
				_ = writeText(ctx, "live/mail_spool_"+filepath.Base(mailDir)+".txt", out, "security")
				r.FilesCollected++
			}
		}
	}

	// Default browser (useful for understanding user activity)
	if out, err := runCmd("xdg-settings", "get", "default-web-browser"); err == nil {
		_ = writeText(ctx, "live/default_browser.txt", out, "security")
		r.FilesCollected++
	}

	// Sysmon for Linux logs (if installed)
	sysmonPaths := []string{
		"/var/log/sysmon",
		"/var/log/sysmonforlinux",
	}
	for _, sp := range sysmonPaths {
		if info, err := stat(sp); err == nil && info.IsDir() {
			count := ctx.CaptureGlob(sp,
				func(p string, info fs.FileInfo) bool {
					return info.Size() < fsutil.MaxSingleFileBytes
				},
				func(p string) string {
					rel, _ := filepath.Rel(sp, p)
					return "artifacts/sysmon/" + rel
				}, "sysmon")
			r.FilesCollected += count
		}
	}

	// Environment variables (can reveal secrets exposure)
	if out, err := runCmd("env"); err == nil {
		_ = writeText(ctx, "live/environment.txt", out, "security")
		r.FilesCollected++
	}

	// Capture security data as JSON for structured parsing
	secData := map[string]any{
		"collection_timestamp": timestamp,
	}
	if out, err := runCmd("ulimit", "-a"); err == nil {
		secData["ulimit"] = out
	}
	if size, err := ctx.WriteJSON("live/security_info.json", "security", secData); err == nil {
		r.FilesCollected++
		r.BytesCollected += size
	}

	r.Elapsed = time.Since(start)
	return r
}

// MailLogCollector captures mail server logs.
type MailLogCollector struct{}

func (c *MailLogCollector) Name() string        { return "MailLogs" }
func (c *MailLogCollector) Description() string { return "Mail server logs (postfix, sendmail, exim)" }

func (c *MailLogCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	mailLogs := []string{
		"/var/log/mail.log",
		"/var/log/mail.err",
		"/var/log/mail.info",
		"/var/log/mail.warn",
		"/var/log/maillog",
	}
	for _, f := range mailLogs {
		if ctx.CaptureFile(f, "artifacts/mail/"+filepath.Base(f), "mail") {
			r.FilesCollected++
		}
	}

	// Postfix config
	if info, err := stat("/etc/postfix"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/postfix",
			func(p string, info fs.FileInfo) bool {
				return !info.IsDir() && info.Size() < fsutil.MaxSingleFileBytes
			},
			func(p string) string {
				return "artifacts/mail/postfix/" + filepath.Base(p)
			}, "mail")
		r.FilesCollected += count
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}

// DHCPCollector captures DHCP server logs.
type DHCPCollector struct{}

func (c *DHCPCollector) Name() string        { return "DHCP" }
func (c *DHCPCollector) Description() string { return "DHCP server logs and configuration" }

func (c *DHCPCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	dhcpFiles := []string{
		"/var/log/dhcpd.log",
		"/var/lib/dhcp/dhcpd.leases",
		"/var/lib/dhcpd/dhcpd.leases",
		"/etc/dhcp/dhcpd.conf",
		"/etc/dhcpd.conf",
	}
	for _, f := range dhcpFiles {
		if ctx.CaptureFile(f, "artifacts/dhcp/"+filepath.Base(f), "dhcp") {
			r.FilesCollected++
		}
	}

	// dnsmasq (common DHCP server)
	if ctx.CaptureFile("/etc/dnsmasq.conf", "artifacts/dhcp/dnsmasq.conf", "dhcp") {
		r.FilesCollected++
	}
	if info, err := stat("/etc/dnsmasq.d"); err == nil && info.IsDir() {
		count := ctx.CaptureGlob("/etc/dnsmasq.d", nil,
			func(p string) string {
				return "artifacts/dhcp/dnsmasq.d/" + filepath.Base(p)
			}, "dhcp")
		r.FilesCollected += count
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
