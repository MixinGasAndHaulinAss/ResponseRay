package powershell

import (
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

func (e *Extractor) Name() string        { return "powershell" }
func (e *Extractor) Description() string { return "PowerShell command history" }

var suspiciousPatterns = []string{
	"invoke-webrequest", "invoke-expression", "iex(", "iex ",
	"downloadstring", "downloadfile", "net.webclient",
	"start-bitstransfer", "certutil", "-encodedcommand",
	"bypass", "-nop", "-w hidden", "frombase64string",
	"invoke-mimikatz", "invoke-shellcode", "invoke-bloodhound",
	"new-object system.net", "reflection.assembly",
	"add-type", "compilerparameters",
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`ConsoleHost_history\.txt`, "")
	if err != nil {
		return 0, err
	}
	added := 0
	for _, f := range files {
		decoded, err := extractors.GetFileContent(f)
		if err != nil || len(decoded) == 0 {
			continue
		}

		// Use file context to find a user SID from the path
		userSID := extractUserSID(f.Path)
		ts := time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"

		lines := strings.Split(string(decoded), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			suspicious := isSuspicious(line)
			msg := fmt.Sprintf("PS> %s", line)
			attrs := map[string]interface{}{
				"command":       line,
				"line_number":   i + 1,
				"history_file":  f.Path + "/" + f.Filename,
				"user_sid":      userSID,
				"is_suspicious": suspicious,
			}
			if conv.AddEvent(ts, "PowerShell History (Collection Time)", msg,
				"powershell_history", "CT-PowerShell",
				"CyberTriage PowerShell History",
				"windows:powershell:history", attrs) {
				added++
			}
		}
	}
	progress.Info(fmt.Sprintf("PowerShell: %d history commands", added))
	return added, nil
}

func isSuspicious(cmd string) bool {
	lower := strings.ToLower(cmd)
	for _, p := range suspiciousPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func extractUserSID(path string) string {
	// Path often contains something like Users/S-1-5-21-.../AppData
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if strings.HasPrefix(p, "S-1-5-") {
			return p
		}
	}
	parts = strings.Split(path, "\\")
	for _, p := range parts {
		if strings.HasPrefix(p, "S-1-5-") {
			return p
		}
	}
	return ""
}
