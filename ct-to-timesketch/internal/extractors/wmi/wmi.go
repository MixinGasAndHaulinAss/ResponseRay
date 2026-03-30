package wmi

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "wmi" }
func (e *Extractor) Description() string { return "WMI persistence detection (OBJECTS.DATA)" }

var persistencePatterns = [][]byte{
	[]byte("CommandLineEventConsumer"),
	[]byte("ActiveScriptEventConsumer"),
	[]byte("__EventFilter"),
	[]byte("__FilterToConsumerBinding"),
	[]byte("powershell"),
	[]byte("cmd.exe"),
	[]byte("wscript"),
	[]byte("cscript"),
	[]byte("mshta"),
	[]byte("certutil"),
	[]byte("bitsadmin"),
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`OBJECTS\.DATA`, "")
	if err != nil {
		return 0, err
	}
	added := 0
	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"

	for _, f := range files {
		decoded, err := extractors.GetFileContent(f)
		if err != nil || len(decoded) == 0 {
			continue
		}

		for _, pattern := range persistencePatterns {
			for _, loc := range findAllOccurrences(decoded, pattern) {
				ctxStart := loc - 200
				if ctxStart < 0 {
					ctxStart = 0
				}
				ctxEnd := loc + 200
				if ctxEnd > len(decoded) {
					ctxEnd = len(decoded)
				}
				context := sanitize(decoded[ctxStart:ctxEnd])

				msg := fmt.Sprintf("WMI: %s found in OBJECTS.DATA", string(pattern))
				if conv.AddEvent(ts, "WMI Repository Analysis (Collection Time)", msg,
					"wmi_persistence", "CT-WMI",
					"CyberTriage WMI Repository",
					"windows:wmi:persistence", map[string]interface{}{
						"pattern": string(pattern),
						"context": context,
						"file":    f.Path + "/" + f.Filename,
					}) {
					added++
				}
			}
		}
	}
	progress.Info(fmt.Sprintf("WMI: %d persistence indicators", added))
	return added, nil
}

func findAllOccurrences(data, pattern []byte) []int {
	var locs []int
	start := 0
	for {
		idx := bytes.Index(data[start:], pattern)
		if idx == -1 {
			break
		}
		locs = append(locs, start+idx)
		start += idx + len(pattern)
	}
	return locs
}

func sanitize(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
