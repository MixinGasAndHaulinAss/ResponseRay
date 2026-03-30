package dhcp

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "dhcp" }
func (e *Extractor) Description() string { return "DHCP Server logs (client infrastructure)" }

// DHCP event ID descriptions
var dhcpEventDescriptions = map[string]string{
	"10": "New Lease",
	"11": "Renewed Lease",
	"12": "Released Lease",
	"13": "Duplicate IP",
	"14": "Lease Expired",
	"15": "Lease Denied",
	"17": "Lease Expired/Deleted",
	"18": "Lease Expired/Deactivated",
	"20": "BOOTP Lease",
	"30": "DNS Update Request",
	"31": "DNS Update Failed",
	"32": "DNS Update Success",
	"36": "Lease Deleted (Cleanup)",
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`DhcpSrvLog.*\.log$`, "")
	if err != nil {
		return 0, err
	}
	added := 0
	for _, f := range files {
		decoded, err := extractors.GetFileContent(f)
		if err != nil || len(decoded) == 0 {
			continue
		}

		lines := strings.Split(string(decoded), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "ID,") || strings.HasPrefix(line, "#") {
				continue
			}

			r := csv.NewReader(strings.NewReader(line))
			r.FieldsPerRecord = -1
			record, err := r.Read()
			if err == io.EOF || err != nil || len(record) < 5 {
				continue
			}

			eventID := strings.TrimSpace(record[0])
			date := strings.TrimSpace(record[1])
			timeStr := strings.TrimSpace(record[2])
			ipAddr := ""
			hostname := ""
			macAddr := ""

			if len(record) > 4 {
				ipAddr = strings.TrimSpace(record[4])
			}
			if len(record) > 5 {
				hostname = strings.TrimSpace(record[5])
			}
			if len(record) > 6 {
				macAddr = formatMAC(strings.TrimSpace(record[6]))
			}

			ts := converter.NormalizeTimestamp(date + "T" + timeStr)
			if ts == "" {
				continue
			}

			desc := dhcpEventDescriptions[eventID]
			if desc == "" {
				desc = "DHCP Event " + eventID
			}
			msg := fmt.Sprintf("DHCP: %s - %s", desc, ipAddr)
			if hostname != "" {
				msg += " (" + hostname + ")"
			}

			if conv.AddEvent(ts, "DHCP Server Log Entry", msg,
				"dhcp_event", "CT-DHCP",
				"CyberTriage DHCP Server Log",
				"windows:dhcp:log", map[string]interface{}{
					"event_id":    eventID,
					"description": desc,
					"ip_address":  ipAddr,
					"hostname":    hostname,
					"mac_address": macAddr,
					"log_file":    f.Filename,
				}) {
				added++
			}
		}
	}
	progress.Info(fmt.Sprintf("DHCP: %d log entries", added))
	return added, nil
}

func formatMAC(mac string) string {
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	if len(mac) == 12 {
		return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
			mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12])
	}
	return mac
}
