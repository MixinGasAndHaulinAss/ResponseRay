package entra

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "entra" }
func (e *Extractor) Description() string { return "Entra ID / Azure AD sign-in and audit logs" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	// Entra operates on JSON files directly (standalone mode)
	info, err := os.Stat(cachePath)
	if err != nil {
		return 0, err
	}

	added := 0
	if info.IsDir() {
		entries, err := os.ReadDir(cachePath)
		if err != nil {
			return 0, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			n, err := processEntraFile(filepath.Join(cachePath, entry.Name()), conv)
			if err != nil {
				progress.Warning(fmt.Sprintf("Entra file %s: %v", entry.Name(), err))
				continue
			}
			added += n
		}
	} else if strings.HasSuffix(cachePath, ".json") {
		n, err := processEntraFile(cachePath, conv)
		if err != nil {
			return 0, err
		}
		added = n
	}

	progress.Info(fmt.Sprintf("Entra ID: %d sign-in events", added))
	return added, nil
}

func processEntraFile(path string, conv *converter.Converter) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	// Entra exports can be a JSON array or newline-delimited JSON
	var records []map[string]interface{}

	if err := json.Unmarshal(data, &records); err != nil {
		// Try as NDJSON
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var rec map[string]interface{}
			if err := json.Unmarshal([]byte(line), &rec); err == nil {
				records = append(records, rec)
			}
		}
	}

	added := 0
	for _, rec := range records {
		ts := converter.GetStr(rec, "createdDateTime")
		if ts == "" {
			ts = converter.GetStr(rec, "activityDateTime")
		}
		if ts == "" {
			continue
		}
		ts = converter.NormalizeTimestamp(ts)

		upn := converter.GetStr(rec, "userPrincipalName")
		appName := converter.GetStr(rec, "appDisplayName")
		ipAddr := converter.GetStr(rec, "ipAddress")
		resourceName := converter.GetStr(rec, "resourceDisplayName")

		// Determine event type (sign-in vs audit)
		eventType := "entra_signin"
		dataType := "entra:signin"
		sourceDesc := "Entra ID Sign-In"

		if converter.GetStr(rec, "activityDisplayName") != "" {
			eventType = "entra_audit"
			dataType = "entra:audit"
			sourceDesc = "Entra ID Audit"
		}

		msg := fmt.Sprintf("Entra: %s -> %s", upn, appName)
		if ipAddr != "" {
			msg += fmt.Sprintf(" from %s", ipAddr)
		}
		if resourceName != "" {
			msg += fmt.Sprintf(" (%s)", resourceName)
		}

		// Flatten attributes using camelCase (Microsoft convention)
		attrs := map[string]interface{}{}
		for k, v := range rec {
			switch val := v.(type) {
			case string:
				if val != "" {
					attrs[k] = val
				}
			case float64, bool:
				attrs[k] = val
			case map[string]interface{}:
				// Flatten nested objects with prefix
				for nk, nv := range val {
					if s, ok := nv.(string); ok && s != "" {
						attrs[k+"_"+nk] = s
					}
				}
			}
		}

		if conv.AddEvent(ts, sourceDesc+" Event", msg, eventType,
			"CT-Entra", "CyberTriage "+sourceDesc, dataType, attrs) {
			added++
		}
	}
	return added, nil
}
