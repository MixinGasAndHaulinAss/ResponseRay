package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

type FirewallCollector struct{}

func (c *FirewallCollector) Name() string        { return "Firewall" }
func (c *FirewallCollector) Description() string { return "iptables/nftables/firewalld/ufw rule snapshots" }

func (c *FirewallCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}

	for _, c := range []struct {
		name string
		args []string
	}{
		{"iptables-save", []string{"iptables-save"}},
		{"ip6tables-save", []string{"ip6tables-save"}},
		{"nft_list_ruleset", []string{"nft", "list", "ruleset"}},
		{"firewall-cmd_--list-all-zones", []string{"firewall-cmd", "--list-all-zones"}},
		{"firewall-cmd_--get-active-zones", []string{"firewall-cmd", "--get-active-zones"}},
		{"ufw_status_verbose", []string{"ufw", "status", "verbose"}},
	} {
		if out, err := runCmd(c.args...); err == nil {
			_ = writeText(ctx, "live/firewall_"+c.name+".txt", out, "firewall")
			r.FilesCollected++
		}
	}

	r.BytesCollected = ctx.TotalBytes()
	r.Elapsed = time.Since(start)
	return r
}
