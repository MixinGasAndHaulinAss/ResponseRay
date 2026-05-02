package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type NetworkLiveCollector struct{}

func (c *NetworkLiveCollector) Name() string { return "Network" }
func (c *NetworkLiveCollector) Description() string {
	return "Active connections (ss), routes, interfaces, ARP, DNS resolvers, /etc/hosts"
}

func (c *NetworkLiveCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	files := []string{
		"/etc/hosts",
		"/etc/resolv.conf",
		"/etc/nsswitch.conf",
		"/etc/networks",
		"/etc/services",
		"/etc/host.conf",
		"/etc/protocols",
		"/proc/net/dev",
		"/proc/net/route",
		"/proc/net/route6",
		"/proc/net/arp",
		"/proc/net/tcp",
		"/proc/net/tcp6",
		"/proc/net/udp",
		"/proc/net/udp6",
		"/proc/net/udplite",
		"/proc/net/udplite6",
		"/proc/net/icmp",
		"/proc/net/icmp6",
		"/proc/net/raw",
		"/proc/net/raw6",
		"/proc/net/unix",
		"/proc/net/sockstat",
		"/proc/net/sockstat6",
		"/proc/net/wireless",
		"/proc/net/netstat",
		"/proc/net/snmp",
		"/proc/net/snmp6",
	}
	for _, f := range files {
		if ctx.CaptureFile(f, "artifacts/network"+f, "network") {
			r.FilesCollected++
		}
	}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"ss_-tunap", []string{"ss", "-tunap"}},
		{"ip_-a_addr", []string{"ip", "-a", "addr"}},
		{"ip_-a_link", []string{"ip", "-a", "link"}},
		{"ip_-a_route", []string{"ip", "-a", "route"}},
		{"ip_neigh", []string{"ip", "neigh", "show"}},
		{"netstat_an", []string{"netstat", "-an"}},
		{"netstat_rn", []string{"netstat", "-rn"}},
		{"arp_-an", []string{"arp", "-an"}},
		{"resolvectl_status", []string{"resolvectl", "status"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/network_"+c.name+".txt", out, "network")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
