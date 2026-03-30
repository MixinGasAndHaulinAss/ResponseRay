package mdo

import (
	"encoding/csv"
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

func (e *Extractor) Name() string        { return "mdo" }
func (e *Extractor) Description() string { return "Microsoft Defender for Office 365 CSV exports" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
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
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".csv") {
				continue
			}
			n, err := processMDOFile(filepath.Join(cachePath, entry.Name()), conv)
			if err != nil {
				progress.Warning(fmt.Sprintf("MDO file %s: %v", entry.Name(), err))
				continue
			}
			added += n
		}
	} else if strings.HasSuffix(cachePath, ".csv") {
		n, err := processMDOFile(cachePath, conv)
		if err != nil {
			return 0, err
		}
		added = n
	}

	progress.Info(fmt.Sprintf("MDO: %d threat events", added))
	return added, nil
}

func processMDOFile(path string, conv *converter.Converter) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	headers, err := r.Read()
	if err != nil {
		return 0, fmt.Errorf("reading CSV header: %w", err)
	}

	// Build column index
	colIdx := map[string]int{}
	for i, h := range headers {
		colIdx[strings.TrimSpace(h)] = i
	}

	// Detect MDO export type from columns
	_, hasClickTime := colIdx["ClickTime"]
	_, hasNetworkMessageId := colIdx["NetworkMessageId"]

	added := 0
	for {
		record, err := r.Read()
		if err != nil {
			break
		}

		get := func(col string) string {
			if i, ok := colIdx[col]; ok && i < len(record) {
				return strings.TrimSpace(record[i])
			}
			return ""
		}

		var ts, msg, eventType, dataType string
		attrs := map[string]interface{}{}

		if hasClickTime {
			// URL Click export
			ts = get("ClickTime")
			url := get("Url")
			user := get("NetworkMessageId")
			action := get("ClickAction")
			eventType = "mdo_url_click"
			dataType = "mdo:url_click"
			msg = fmt.Sprintf("MDO URL Click: %s", url)
			if action != "" {
				msg += fmt.Sprintf(" [%s]", action)
			}
			attrs["url"] = url
			attrs["networkMessageId"] = user
			attrs["clickAction"] = action
			attrs["urlChain"] = get("UrlChain")
			attrs["threats"] = get("Threats")
		} else if hasNetworkMessageId {
			// Email event export
			ts = get("Timestamp")
			if ts == "" {
				ts = get("ReceivedDate")
			}
			sender := get("SenderAddress")
			recipient := get("RecipientAddress")
			subject := get("Subject")
			eventType = "mdo_email_event"
			dataType = "mdo:email_event"
			msg = fmt.Sprintf("MDO Email: %s -> %s: %s", sender, recipient, subject)
			attrs["senderAddress"] = sender
			attrs["recipientAddress"] = recipient
			attrs["subject"] = subject
			attrs["networkMessageId"] = get("NetworkMessageId")
			attrs["deliveryAction"] = get("DeliveryAction")
			attrs["threats"] = get("Threats")
		} else {
			continue
		}

		if ts == "" {
			continue
		}
		ts = converter.NormalizeTimestamp(ts)
		if ts == "" {
			continue
		}

		if conv.AddEvent(ts, "MDO Event Time", msg, eventType,
			"CT-MDO", "Microsoft Defender for Office 365",
			dataType, attrs) {
			added++
		}
	}
	return added, nil
}
