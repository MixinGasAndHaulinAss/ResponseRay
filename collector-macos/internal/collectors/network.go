package collectors

import (
	"path/filepath"
	"time"

	"github.com/responseray/collector-macos/internal/fsutil"
)

type NetworkCollector struct{}

func (NetworkCollector) Name() string { return "NetworkLive" }

func (NetworkCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	cmds := [][]string{
		{"ifconfig", "-a"},
		{"netstat", "-an"},
		{"netstat", "-rn"},
		{"netstat", "-s"},
		{"arp", "-a"},
		{"ndp", "-an"},
		{"route", "-n", "get", "default"},
		{"scutil", "--dns"},
		{"scutil", "--proxy"},
		{"networksetup", "-listallhardwareports"},
		{"networksetup", "-listallnetworkservices"},
		{"networksetup", "-listpreferrednetworks", "Wi-Fi"},
		{"networksetup", "-getinfo", "Wi-Fi"},
		{"lsof", "-i", "-n", "-P"},
		{"dscacheutil", "-statistics"},
		{"smbutil", "view"},
	}
	for _, c := range cmds {
		key := c[0]
		if len(c) > 1 {
			key = c[0] + "_" + c[1]
		}
		if v, err := runCmd(30*time.Second, c[0], c[1:]...); err == nil {
			out[key] = v
		}
	}

	files := []string{
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/networks",
		"/etc/services",
		"/var/db/dhcpclient/leases",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/network", filepath.Base(f)), "network")
	}

	if _, err := ctx.WriteJSON("live/network.json", "network", out); err != nil {
		return err
	}
	return nil
}

type FirewallCollector struct{}

func (FirewallCollector) Name() string { return "Firewall" }

func (FirewallCollector) Run(ctx *fsutil.Context) error {
	out := map[string]interface{}{}
	if v, err := runCmd(15*time.Second, "pfctl", "-s", "all"); err == nil {
		out["pfctl_all"] = v
	}
	if v, err := runCmd(15*time.Second, "pfctl", "-s", "rules"); err == nil {
		out["pfctl_rules"] = v
	}
	if v, err := runCmd(15*time.Second, "pfctl", "-s", "info"); err == nil {
		out["pfctl_info"] = v
	}
	if v, err := runCmd(15*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); err == nil {
		out["alf_global"] = v
	}
	if v, err := runCmd(15*time.Second, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"); err == nil {
		out["alf_listapps"] = v
	}

	files := []string{
		"/etc/pf.conf",
		"/etc/pf.anchors",
		"/Library/Preferences/com.apple.alf.plist",
	}
	for _, f := range files {
		ctx.CaptureFile(f, filepath.Join("artifacts/firewall", filepath.Base(f)), "firewall")
	}

	if _, err := ctx.WriteJSON("live/firewall.json", "firewall", out); err != nil {
		return err
	}
	return nil
}
