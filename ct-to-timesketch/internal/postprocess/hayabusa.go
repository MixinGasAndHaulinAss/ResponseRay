package postprocess

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// Detection holds a single Hayabusa Sigma rule match.
type Detection struct {
	RuleTitle   string
	RuleID      string
	Level       string
	Status      string
	MitreAttack string
	Details     string
	Computer    string
	EventID     string
	Timestamp   string
}

// detectionKey uniquely identifies an event log record for matching.
type detectionKey struct {
	Channel  string
	RecordID string
}

// RunHayabusa finds the Hayabusa binary, runs it against EVTX files in
// artifactDir, parses results, and merges detection tags into the converter's
// accumulated events. Returns the number of events tagged.
func RunHayabusa(artifactDir, binaryPath string, conv *converter.Converter) (int, error) {
	bin, err := findBinary(binaryPath)
	if err != nil {
		return 0, err
	}

	evtxDir := findEVTXDir(artifactDir)
	if evtxDir == "" {
		return 0, fmt.Errorf("no .evtx files found under %s", artifactDir)
	}

	outputPath := filepath.Join(artifactDir, "hayabusa_results.jsonl")
	if err := runBinary(bin, evtxDir, outputPath); err != nil {
		return 0, err
	}

	detections, err := parseResults(outputPath)
	if err != nil {
		return 0, fmt.Errorf("parsing Hayabusa output: %w", err)
	}

	if len(detections) == 0 {
		progress.Info("Hayabusa: no detections found")
		return 0, nil
	}

	tagged := mergeDetections(conv, detections)
	printSummary(detections)
	return tagged, nil
}

// findBinary locates the Hayabusa binary. Checks explicit path, then PATH,
// then common installation directories.
func findBinary(explicit string) (string, error) {
	if explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit, nil
		}
		return "", fmt.Errorf("hayabusa binary not found at: %s", explicit)
	}

	if p, err := exec.LookPath("hayabusa"); err == nil {
		return p, nil
	}

	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "tools", "hayabusa", "hayabusa"),
		filepath.Join(home, "hayabusa", "hayabusa"),
		"/opt/hayabusa/hayabusa",
		"/usr/local/bin/hayabusa",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("hayabusa not found in PATH or common locations; install from https://github.com/Yamato-Security/hayabusa or use --hayabusa-path")
}

// findEVTXDir locates a directory containing .evtx files under artifactDir.
func findEVTXDir(artifactDir string) string {
	var evtxDir string
	filepath.Walk(artifactDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".evtx") && !strings.HasPrefix(info.Name(), "$I") {
			evtxDir = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})
	return evtxDir
}

// runBinary executes Hayabusa json-timeline against a directory of EVTX files.
func runBinary(bin, evtxDir, outputPath string) error {
	cmd := exec.Command(bin,
		"json-timeline",
		"-d", evtxDir,
		"-o", outputPath,
		"-m", "low",
		"-w",
		"-C",
		"-L",
	)
	cmd.Stderr = os.Stderr

	progress.Info(fmt.Sprintf("Running: %s json-timeline -d %s -m low", filepath.Base(bin), evtxDir))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("hayabusa exited with error: %w", err)
	}

	info, err := os.Stat(outputPath)
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("hayabusa produced no output at %s", outputPath)
	}
	return nil
}

// parseResults reads Hayabusa JSONL output and builds a detection lookup
// keyed by (channel, recordID).
func parseResults(jsonlPath string) (map[detectionKey][]Detection, error) {
	f, err := os.Open(jsonlPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	detections := make(map[detectionKey][]Detection)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}

		var rec map[string]interface{}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}

		channel := getStr(rec, "Channel")
		recordID := getStr(rec, "RecordID")
		if recordID == "" {
			recordID = getStr(rec, "EvtxRecordId")
		}
		if recordID == "" {
			continue
		}

		channel = expandChannelName(channel)

		d := Detection{
			RuleTitle:   getStr(rec, "RuleTitle"),
			RuleID:      getStr(rec, "RuleID"),
			Level:       strings.ToLower(getStr(rec, "Level")),
			Status:      getStr(rec, "Status"),
			MitreAttack: extractMitreAttack(rec),
			Details:     getStr(rec, "Details"),
			Computer:    getStr(rec, "Computer"),
			EventID:     getStr(rec, "EventID"),
			Timestamp:   getStr(rec, "Timestamp"),
		}

		key := detectionKey{Channel: channel, RecordID: recordID}
		detections[key] = append(detections[key], d)
	}
	return detections, sc.Err()
}

// mergeDetections iterates the converter's events and tags those that match
// a Hayabusa detection by channel + record_number.
func mergeDetections(conv *converter.Converter, detections map[detectionKey][]Detection) int {
	tagged := 0
	for i := range conv.Events {
		event := conv.Events[i]

		channel, _ := event["channel"].(string)
		recordNum := fmt.Sprint(event["record_number"])
		if recordNum == "" || recordNum == "<nil>" {
			continue
		}

		key := detectionKey{Channel: channel, RecordID: recordNum}
		matches := detections[key]
		if len(matches) == 0 {
			continue
		}

		// Build tags
		tags := getExistingTags(event)
		tags = appendUnique(tags, "hayabusa")
		tags = appendUnique(tags, "sigma")

		var ruleNames, ruleIDs []string
		levels := map[string]bool{}
		mitreSet := map[string]bool{}

		for _, d := range matches {
			ruleNames = append(ruleNames, d.RuleTitle)
			if d.RuleID != "" {
				ruleIDs = append(ruleIDs, d.RuleID)
			}
			levels[d.Level] = true
			tags = appendUnique(tags, "hayabusa:"+d.Level)
			if d.MitreAttack != "" {
				for _, t := range strings.Split(d.MitreAttack, ", ") {
					mitreSet[t] = true
				}
			}
		}

		event["tag"] = tags

		if len(ruleNames) <= 5 {
			event["hayabusa_rule"] = strings.Join(ruleNames, "; ")
		} else {
			event["hayabusa_rule"] = strings.Join(ruleNames[:5], "; ") +
				fmt.Sprintf(" (+%d more)", len(ruleNames)-5)
		}
		if len(ruleIDs) > 0 {
			event["hayabusa_rule_id"] = strings.Join(ruleIDs, "; ")
		}

		event["hayabusa_level"] = highestLevel(levels)
		event["hayabusa_detection_count"] = len(matches)

		if len(mitreSet) > 0 {
			techniques := make([]string, 0, len(mitreSet))
			for t := range mitreSet {
				techniques = append(techniques, t)
			}
			sort.Strings(techniques)
			event["mitre_attack"] = strings.Join(techniques, ", ")
		}

		conv.Events[i] = event
		tagged++
	}
	return tagged
}

// printSummary outputs a formatted detection summary.
func printSummary(detections map[detectionKey][]Detection) {
	byLevel := map[string]int{}
	byRule := map[string]int{}
	total := 0

	for _, dList := range detections {
		for _, d := range dList {
			byLevel[d.Level]++
			byRule[d.RuleTitle]++
			total++
		}
	}

	progress.Info(fmt.Sprintf("Hayabusa: %d detections across %d events", total, len(detections)))

	levelOrder := []string{"critical", "high", "medium", "low", "informational"}
	for _, level := range levelOrder {
		if count, ok := byLevel[level]; ok {
			progress.Info(fmt.Sprintf("  %-15s %d", strings.ToUpper(level), count))
		}
	}

	type ruleCount struct {
		name  string
		count int
	}
	var topRules []ruleCount
	for name, count := range byRule {
		topRules = append(topRules, ruleCount{name, count})
	}
	sort.Slice(topRules, func(i, j int) bool { return topRules[i].count > topRules[j].count })

	if len(topRules) > 0 {
		progress.Info("  Top detections:")
		limit := 5
		if len(topRules) < limit {
			limit = len(topRules)
		}
		for _, rc := range topRules[:limit] {
			name := rc.name
			if len(name) > 60 {
				name = name[:60] + "..."
			}
			progress.Info(fmt.Sprintf("    %s (%d)", name, rc.count))
		}
	}
}

// --- helpers ---

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func getExistingTags(event converter.Event) []string {
	v, ok := event["tag"]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return append([]string{}, t...)
	case []interface{}:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t != "" {
			return []string{t}
		}
	}
	return nil
}

func appendUnique(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

var channelExpansion = map[string]string{
	"Sec":         "Security",
	"Sys":         "System",
	"App":         "Application",
	"Sysmon":      "Microsoft-Windows-Sysmon/Operational",
	"PwSh":        "Microsoft-Windows-PowerShell/Operational",
	"PwShClassic": "Windows PowerShell",
	"TaskSch":     "Microsoft-Windows-TaskScheduler/Operational",
	"WinRM":       "Microsoft-Windows-WinRM/Operational",
	"Defender":    "Microsoft-Windows-Windows Defender/Operational",
	"TermServ":    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"RDP-Client":  "Microsoft-Windows-TerminalServices-RDPClient/Operational",
	"Bits":        "Microsoft-Windows-Bits-Client/Operational",
	"DNS":         "Microsoft-Windows-DNS-Client/Operational",
	"Firewall":    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	"WMI":         "Microsoft-Windows-WMI-Activity/Operational",
	"NTLM":        "Microsoft-Windows-NTLM/Operational",
}

func expandChannelName(abbrev string) string {
	if full, ok := channelExpansion[abbrev]; ok {
		return full
	}
	return abbrev
}

func extractMitreAttack(rec map[string]interface{}) string {
	if v, ok := rec["MitreAttack"]; ok {
		switch t := v.(type) {
		case string:
			return t
		case []interface{}:
			var parts []string
			for _, item := range t {
				if s, ok := item.(string); ok && s != "" {
					parts = append(parts, s)
				}
			}
			return strings.Join(parts, ", ")
		}
	}
	if tags, ok := rec["Tags"].([]interface{}); ok {
		var mitre []string
		for _, t := range tags {
			if s, ok := t.(string); ok && strings.HasPrefix(s, "attack.") {
				mitre = append(mitre, s)
			}
		}
		return strings.Join(mitre, ", ")
	}
	return ""
}

func highestLevel(levels map[string]bool) string {
	priority := []string{"critical", "high", "medium", "low", "informational"}
	for _, p := range priority {
		if levels[p] {
			return p
		}
	}
	for l := range levels {
		return l
	}
	return "unknown"
}
