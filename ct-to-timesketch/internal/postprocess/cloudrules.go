package postprocess

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// RunCloudRules loads a CloudRules json.gz file, evaluates all enabled rules
// against the converter's accumulated events, and tags matching events with
// enrichment metadata. Returns the number of events tagged.
func RunCloudRules(rulesPath string, conv *converter.Converter) (int, error) {
	path := findRulesFile(rulesPath)
	if path == "" {
		return 0, fmt.Errorf("CloudRules file not found; use --cloudrules-path or place in cloudrules/ directory")
	}

	progress.Info(fmt.Sprintf("Loading rules from: %s", filepath.Base(path)))
	rs, err := loadAndCompile(path)
	if err != nil {
		return 0, fmt.Errorf("loading CloudRules: %w", err)
	}

	progress.Info(fmt.Sprintf("Compiled %d rules across %d plugin types", rs.totalRules, rs.pluginCount))

	results := rs.evaluate(conv.Events)
	if len(results) == 0 {
		progress.Info("CloudRules: no detections")
		return 0, nil
	}

	tagged := mergeCloudRulesResults(conv, results, rs.impactMapping)
	printCloudRulesSummary(results)
	return tagged, nil
}

// ---------------------------------------------------------------------------
// JSON schema types
// ---------------------------------------------------------------------------

type cloudRulesFile struct {
	Rules []cloudRule `json:"rules"`
}

type cloudRule struct {
	RuleID       string        `json:"ruleId"`
	RuleVersion  int           `json:"ruleVersion"`
	Plugin       string        `json:"plugin"`
	Enabled      bool          `json:"enabled"`
	RuleMetadata *ruleMetadata `json:"ruleMetadata,omitempty"`
}

type ruleMetadata struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type resultData struct {
	AnalysisResultType string     `json:"analysisResultType"`
	Score              string     `json:"score"`
	Justification      string     `json:"justification"`
	DuplicatePolicy    string     `json:"duplicatePolicy"`
	MitreAttackTypes   []mitreRef `json:"mitreAttackTypes"`
}

type mitreRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Per-plugin JSON payload types

type fileCorrelatedPayload struct {
	Rules []struct {
		Matches struct {
			FileName         string   `json:"fileName"`
			FileNameNoExt    string   `json:"fileNameNoExt"`
			Path             string   `json:"path"`
			Extensions       []string `json:"extensions"`
			Arguments        []string `json:"arguments"`
			DataTypes        []string `json:"dataTypes"`
			ParentProcess    string   `json:"parentProcess"`
			Sources          string   `json:"sources"`
			FileSignedStatus string   `json:"fileSignedStatus"`
			TaskName         string   `json:"taskName"`
		} `json:"matches"`
		Result resultData `json:"result"`
	} `json:"rules"`
}

type powershellArgsPayload struct {
	Rules []struct {
		ArgToken string     `json:"argToken"`
		Result   resultData `json:"result"`
	} `json:"rules"`
}

type domainPayload struct {
	Domains []struct {
		ServiceProvider   string     `json:"serviceProvider"`
		DomainIdentifier  string     `json:"domainIdentifier"`
		DomainStarPattern string     `json:"domainStarPattern"`
		NewResultARData   resultData `json:"newResultARData"`
		OldResultOverride struct {
			Score         string `json:"score"`
			Justification string `json:"justification"`
		} `json:"oldResultAROverrideData"`
		NewOSOverride struct {
			Score         string `json:"score"`
			Justification string `json:"justification"`
		} `json:"newOSAROverrideData"`
	} `json:"domains"`
}

type remoteManagementPayload struct {
	Rules []struct {
		RMMRecord struct {
			ID string `json:"id"`
		} `json:"rmmRecord"`
		MatchesPath []struct {
			FileName      string   `json:"fileName"`
			FileNameNoExt string   `json:"fileNameNoExt"`
			Path          string   `json:"path"`
			Extensions    []string `json:"extensions"`
		} `json:"matchesPath"`
	} `json:"rules"`
}

type eventsMatchingPayload struct {
	Rules []struct {
		Matches struct {
			EventIDs    []int             `json:"eventIds"`
			LogFileName string            `json:"logFileName"`
			LogNames    string            `json:"logNames"`
			Payload     map[string]string `json:"payload"`
		} `json:"matches"`
		Result resultData `json:"result"`
	} `json:"rules"`
}

type executableTypePayload struct {
	Rules []struct {
		Record struct {
			ID        string     `json:"id"`
			NewResult resultData `json:"newResult"`
			OldResult struct {
				Score         string `json:"score"`
				Justification string `json:"justification"`
			} `json:"oldResultOverride"`
			NewOsOverride struct {
				Score         string `json:"score"`
				Justification string `json:"justification"`
			} `json:"newOsOverride"`
		} `json:"record"`
		Matches []struct {
			FileName  string   `json:"fileName"`
			DataTypes []string `json:"dataTypes"`
		} `json:"matches"`
	} `json:"rules"`
}

type libNotOnDiskPayload struct {
	Rules []struct {
		LibToMatch struct {
			Path          string   `json:"path"`
			FileNameNoExt string   `json:"fileNameNoExt"`
			Extensions    []string `json:"extensions"`
		} `json:"libToMatch"`
		AnalysisResultData struct {
			Score         string `json:"score"`
			Justification string `json:"justification"`
		} `json:"analysisResultData"`
	} `json:"rules"`
}

type malwareDowngradePayload struct {
	Types []string `json:"downgradeAnalysisResultTypes"`
}

type impactMappingPayload struct {
	Entries []struct {
		AnalysisResultType string `json:"analysisResultType"`
		Impact             string `json:"impact"`
	} `json:"entries"`
}

type hayabusaExcludePayload struct {
	Lines []struct {
		GUID string `json:"guid"`
	} `json:"excludeRulesLines"`
}

type commonBitsPayload struct {
	Domains []struct {
		Host string `json:"host"`
	} `json:"commonBitsJobDomains"`
}

type hostPortExclusionPayload struct {
	Ports []struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"excludedHostPorts"`
}

// ---------------------------------------------------------------------------
// Compiled rule types
// ---------------------------------------------------------------------------

type compiledRuleSet struct {
	fileCorrelated   []compiledFCRule
	powershellArgs   []compiledPSRule
	domain           []compiledDomainRule
	remoteManagement []compiledRMMRule
	eventsMatching   []compiledEMRule
	executableType   []compiledETRule
	libNotOnDisk     []compiledLNDRule
	malwareDowngrade map[string]bool
	impactMapping    map[string]string
	hayabusaExclude  map[string]bool
	hostPortExclude  []compiledHPExclusion
	commonBitsDomain []*regexp.Regexp

	emByEventID map[int][]*compiledEMRule
	totalRules  int
	pluginCount int
}

type compiledFCRule struct {
	ruleID        string
	fileName      *regexp.Regexp
	fileNameNoExt *regexp.Regexp
	pathRe        *regexp.Regexp
	extensions    []*regexp.Regexp
	arguments     []*regexp.Regexp
	dataTypes     map[string]bool
	eventTypes    map[string]bool // mapped from CT dataTypes
	parentProcess *regexp.Regexp
	sources       *regexp.Regexp
	signedStatus  *regexp.Regexp
	taskName      *regexp.Regexp
	result        compiledResult
	hasNameCheck  bool // true if at least one name/path/args criterion was compiled
}

type compiledPSRule struct {
	ruleID   string
	argToken string
	result   compiledResult
}

type compiledDomainRule struct {
	ruleID          string
	serviceProvider string
	domainPattern   *regexp.Regexp
	newResult       compiledResult
}

type compiledRMMRule struct {
	ruleID  string
	toolID  string
	matches []compiledRMMPath
}

type compiledRMMPath struct {
	fileName      string
	fileNameNoExt string
	pathGlob      *regexp.Regexp
	extensions    []string
}

type compiledEMRule struct {
	ruleID      string
	eventIDs    map[int]bool
	logFileName *regexp.Regexp
	logNames    *regexp.Regexp
	payload     map[string]*regexp.Regexp
	result      compiledResult
}

type compiledETRule struct {
	ruleID    string
	toolID    string
	matches   []compiledETMatch
	newResult compiledResult
}

type compiledETMatch struct {
	fileName   string
	eventTypes map[string]bool
}

type compiledLNDRule struct {
	ruleID        string
	pathGlob      *regexp.Regexp
	fileNameNoExt *regexp.Regexp
	extensions    []string
	score         string
	justification string
}

type compiledHPExclusion struct {
	host *regexp.Regexp
	port int
}

type compiledResult struct {
	analysisType string
	score        string
	justification string
	mitreAttack  []string
}

// CRDetection is a single CloudRules match against an event.
type CRDetection struct {
	RuleID        string
	Plugin        string
	AnalysisType  string
	Score         string
	Justification string
	MitreAttack   []string
	ToolName      string
}

// ---------------------------------------------------------------------------
// CT DataType to Timesketch event_type mapping
// ---------------------------------------------------------------------------

var ctDataTypeEventTypes = map[string][]string{
	"PROCESS_INSTANCE":   {"process_execution", "running_process"},
	"FILE":               {"file_timeline", "file_timeline_fn", "file_access"},
	"WEB_ARTIFACT":       {"web_visit", "web_download"},
	"USER_ACCESSED_DATA": {"file_access"},
	"TRIGGERED_TASK":     {"scheduled_task", "triggered_task", "windows_task"},
	"SERVICE":            {"windows_service"},
	"STARTUP_PROGRAM":    {"startup_item"},
	"CONFIG_ITEM":        {"os_config"},
	"SCHEDULED_TASK":     {"scheduled_task", "triggered_task", "windows_task"},
}

func buildEventTypeSet(ctTypes []string) map[string]bool {
	set := make(map[string]bool)
	for _, ct := range ctTypes {
		if ts, ok := ctDataTypeEventTypes[ct]; ok {
			for _, t := range ts {
				set[t] = true
			}
		}
	}
	return set
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

func findRulesFile(explicit string) string {
	if explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit
		}
		return ""
	}

	searchDirs := []string{}
	if exe, err := os.Executable(); err == nil {
		searchDirs = append(searchDirs, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		searchDirs = append(searchDirs, cwd)
	}
	if home, err := os.UserHomeDir(); err == nil {
		searchDirs = append(searchDirs, filepath.Join(home, ".ct-to-timesketch"))
	}

	for _, dir := range searchDirs {
		crDir := filepath.Join(dir, "cloudrules")
		matches, _ := filepath.Glob(filepath.Join(crDir, "CloudRules_rv*.json.gz"))
		if gzMatch := pickHighestRevision(matches); gzMatch != "" {
			return gzMatch
		}
		matches, _ = filepath.Glob(filepath.Join(crDir, "CloudRules_rv*.json"))
		if jsonMatch := pickHighestRevision(matches); jsonMatch != "" {
			return jsonMatch
		}
	}
	return ""
}

func pickHighestRevision(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	sort.Strings(paths)
	return paths[len(paths)-1]
}

// ---------------------------------------------------------------------------
// Load, parse, compile
// ---------------------------------------------------------------------------

func loadAndCompile(path string) (*compiledRuleSet, error) {
	var reader io.Reader
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("decompressing: %w", err)
		}
		defer gz.Close()
		reader = gz
	} else {
		reader = f
	}

	var file cloudRulesFile
	if err := json.NewDecoder(reader).Decode(&file); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	rs := &compiledRuleSet{
		malwareDowngrade: make(map[string]bool),
		impactMapping:    make(map[string]string),
		hayabusaExclude:  make(map[string]bool),
		emByEventID:      make(map[int][]*compiledEMRule),
	}

	// Deduplicate rules by ruleId, keeping the highest version
	bestVersion := map[string]int{}
	for _, rule := range file.Rules {
		if !rule.Enabled || rule.RuleMetadata == nil {
			continue
		}
		if existing, ok := bestVersion[rule.RuleID]; !ok || rule.RuleVersion > existing {
			bestVersion[rule.RuleID] = rule.RuleVersion
		}
	}

	pluginsSeen := map[string]bool{}

	for _, rule := range file.Rules {
		if !rule.Enabled || rule.RuleMetadata == nil {
			continue
		}
		if bestVersion[rule.RuleID] != rule.RuleVersion {
			continue
		}
		pluginsSeen[rule.Plugin] = true

		switch rule.Plugin {
		case "FileCorrelatedCloudRulePlugin_v1":
			rs.compileFileCorrelated(rule)
		case "PowershellArgsCloudRulePlugin_v1":
			rs.compilePowershellArgs(rule)
		case "DomainCloudRulePlugin_v1":
			rs.compileDomain(rule)
		case "RemoteManagementCloudRulePlugin_v1":
			rs.compileRemoteManagement(rule)
		case "EventsMatchingCloudRulePlugin_v1":
			rs.compileEventsMatching(rule)
		case "ExecutableTypeCloudRulePlugin_v1":
			rs.compileExecutableType(rule)
		case "LibNotOnDiskCloudRulePlugin_v1":
			rs.compileLibNotOnDisk(rule)
		case "MalwareDowngradeCloudRulePlugin_v1":
			rs.compileMalwareDowngrade(rule)
		case "AnalysisResultImpactMappingCloudRulePlugin_v1":
			rs.compileImpactMapping(rule)
		case "HayabusaCloudRulePlugin_v1":
			rs.compileHayabusaExclude(rule)
		case "CommonBitsJobDomainCloudRulePlugin_v1":
			rs.compileCommonBits(rule)
		case "HostPortExclusionCloudRulePlugin_v1":
			rs.compileHostPortExclusion(rule)
		}
	}

	rs.totalRules = len(rs.fileCorrelated) + len(rs.powershellArgs) +
		len(rs.domain) + len(rs.remoteManagement) + len(rs.eventsMatching) +
		len(rs.executableType) + len(rs.libNotOnDisk) + len(rs.malwareDowngrade) +
		len(rs.impactMapping) + len(rs.commonBitsDomain) + len(rs.hostPortExclude)
	if len(rs.hayabusaExclude) > 0 {
		rs.totalRules += len(rs.hayabusaExclude)
	}
	rs.pluginCount = len(pluginsSeen)

	return rs, nil
}

func (rs *compiledRuleSet) compileFileCorrelated(rule cloudRule) {
	var p fileCorrelatedPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		c := compiledFCRule{
			ruleID:     rule.RuleID,
			dataTypes:  strSetFromSlice(r.Matches.DataTypes),
			eventTypes: buildEventTypeSet(r.Matches.DataTypes),
			result:     compileResultData(r.Result),
		}
		c.fileName = compileJavaRegex(r.Matches.FileName)
		c.fileNameNoExt = compileJavaRegex(r.Matches.FileNameNoExt)
		c.pathRe = compileJavaRegex(r.Matches.Path)
		c.parentProcess = compileJavaRegex(r.Matches.ParentProcess)
		c.sources = compileJavaRegex(r.Matches.Sources)
		c.signedStatus = compileJavaRegex(r.Matches.FileSignedStatus)
		c.taskName = compileJavaRegex(r.Matches.TaskName)
		for _, ext := range r.Matches.Extensions {
			if re := compileJavaRegex(ext); re != nil {
				c.extensions = append(c.extensions, re)
			}
		}
		for _, arg := range r.Matches.Arguments {
			if re := compileJavaRegex(arg); re != nil {
				c.arguments = append(c.arguments, re)
			}
		}
		// A rule must have at least one content criterion to avoid matching everything
		c.hasNameCheck = c.fileName != nil || c.fileNameNoExt != nil ||
			c.pathRe != nil || len(c.extensions) > 0 || len(c.arguments) > 0 ||
			c.parentProcess != nil || c.taskName != nil
		rs.fileCorrelated = append(rs.fileCorrelated, c)
	}
}

func (rs *compiledRuleSet) compilePowershellArgs(rule cloudRule) {
	var p powershellArgsPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		rs.powershellArgs = append(rs.powershellArgs, compiledPSRule{
			ruleID:   rule.RuleID,
			argToken: strings.ToLower(r.ArgToken),
			result:   compileResultData(r.Result),
		})
	}
}

func (rs *compiledRuleSet) compileDomain(rule cloudRule) {
	var p domainPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, d := range p.Domains {
		pattern := globToRegex(d.DomainStarPattern)
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}
		rs.domain = append(rs.domain, compiledDomainRule{
			ruleID:          rule.RuleID,
			serviceProvider: d.ServiceProvider,
			domainPattern:   re,
			newResult:       compileResultData(d.NewResultARData),
		})
	}
}

func (rs *compiledRuleSet) compileRemoteManagement(rule cloudRule) {
	var p remoteManagementPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		c := compiledRMMRule{
			ruleID: rule.RuleID,
			toolID: r.RMMRecord.ID,
		}
		for _, mp := range r.MatchesPath {
			cm := compiledRMMPath{
				fileName:      strings.ToLower(mp.FileName),
				fileNameNoExt: strings.ToLower(mp.FileNameNoExt),
				extensions:    toLowerSlice(mp.Extensions),
			}
			if mp.Path != "" {
				cm.pathGlob = compileGlob(mp.Path)
			}
			c.matches = append(c.matches, cm)
		}
		rs.remoteManagement = append(rs.remoteManagement, c)
	}
}

func (rs *compiledRuleSet) compileEventsMatching(rule cloudRule) {
	var p eventsMatchingPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		c := compiledEMRule{
			ruleID:      rule.RuleID,
			eventIDs:    intSetFromSlice(r.Matches.EventIDs),
			logFileName: compileJavaRegex(r.Matches.LogFileName),
			logNames:    compileJavaRegex(r.Matches.LogNames),
			payload:     make(map[string]*regexp.Regexp),
			result:      compileResultData(r.Result),
		}
		for k, v := range r.Matches.Payload {
			if re := compileJavaRegex(v); re != nil {
				c.payload[k] = re
			}
		}
		rs.eventsMatching = append(rs.eventsMatching, c)

		ref := &rs.eventsMatching[len(rs.eventsMatching)-1]
		for eid := range c.eventIDs {
			rs.emByEventID[eid] = append(rs.emByEventID[eid], ref)
		}
	}
}

func (rs *compiledRuleSet) compileExecutableType(rule cloudRule) {
	var p executableTypePayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		c := compiledETRule{
			ruleID:    rule.RuleID,
			toolID:    r.Record.ID,
			newResult: compileResultData(r.Record.NewResult),
		}
		for _, m := range r.Matches {
			c.matches = append(c.matches, compiledETMatch{
				fileName:   strings.ToLower(m.FileName),
				eventTypes: buildEventTypeSet(m.DataTypes),
			})
		}
		rs.executableType = append(rs.executableType, c)
	}
}

func (rs *compiledRuleSet) compileLibNotOnDisk(rule cloudRule) {
	var p libNotOnDiskPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, r := range p.Rules {
		c := compiledLNDRule{
			ruleID:        rule.RuleID,
			extensions:    toLowerSlice(r.LibToMatch.Extensions),
			score:         r.AnalysisResultData.Score,
			justification: r.AnalysisResultData.Justification,
		}
		if r.LibToMatch.Path != "" {
			c.pathGlob = compileGlob(r.LibToMatch.Path)
		}
		if r.LibToMatch.FileNameNoExt != "" {
			c.fileNameNoExt = compileGlob(r.LibToMatch.FileNameNoExt)
		}
		rs.libNotOnDisk = append(rs.libNotOnDisk, c)
	}
}

func (rs *compiledRuleSet) compileMalwareDowngrade(rule cloudRule) {
	var p malwareDowngradePayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, t := range p.Types {
		rs.malwareDowngrade[t] = true
	}
}

func (rs *compiledRuleSet) compileImpactMapping(rule cloudRule) {
	var p impactMappingPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, e := range p.Entries {
		rs.impactMapping[e.AnalysisResultType] = e.Impact
	}
}

func (rs *compiledRuleSet) compileHayabusaExclude(rule cloudRule) {
	var p hayabusaExcludePayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, l := range p.Lines {
		rs.hayabusaExclude[l.GUID] = true
	}
}

func (rs *compiledRuleSet) compileCommonBits(rule cloudRule) {
	var p commonBitsPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, d := range p.Domains {
		if re, err := regexp.Compile("(?i)" + d.Host); err == nil {
			rs.commonBitsDomain = append(rs.commonBitsDomain, re)
		}
	}
}

func (rs *compiledRuleSet) compileHostPortExclusion(rule cloudRule) {
	var p hostPortExclusionPayload
	if err := json.Unmarshal(rule.RuleMetadata.Payload, &p); err != nil {
		return
	}
	for _, hp := range p.Ports {
		if re, err := regexp.Compile("(?i)" + hp.Host); err == nil {
			rs.hostPortExclude = append(rs.hostPortExclude, compiledHPExclusion{
				host: re,
				port: hp.Port,
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Evaluation loop
// ---------------------------------------------------------------------------

func (rs *compiledRuleSet) evaluate(events []converter.Event) map[int][]CRDetection {
	results := make(map[int][]CRDetection)

	// Phase 1: Apply Hayabusa exclusions (remove FP Hayabusa detections)
	if len(rs.hayabusaExclude) > 0 {
		rs.applyHayabusaExclusions(events)
	}

	// Phase 2: Evaluate detection plugins per event
	for i, event := range events {
		detections := rs.evaluateEvent(event)
		if len(detections) > 0 {
			results[i] = detections
		}
	}
	return results
}

func (rs *compiledRuleSet) evaluateEvent(event converter.Event) []CRDetection {
	var detections []CRDetection
	eventType, _ := event["event_type"].(string)

	// FileCorrelated: match by fileName/path/args on process/file events
	if len(rs.fileCorrelated) > 0 {
		for j := range rs.fileCorrelated {
			rule := &rs.fileCorrelated[j]
			if len(rule.eventTypes) > 0 && !rule.eventTypes[eventType] {
				continue
			}
			if d := evalFileCorrelated(rule, event); d != nil {
				detections = append(detections, *d)
			}
		}
	}

	// PowershellArgs: substring in command_line for PowerShell processes
	processName, _ := event["process_name"].(string)
	if len(rs.powershellArgs) > 0 && strings.Contains(strings.ToLower(processName), "powershell") {
		cmdLine, _ := event["command_line"].(string)
		if cmdLine != "" {
			cmdLower := strings.ToLower(cmdLine)
			for j := range rs.powershellArgs {
				if d := evalPowershellArgs(&rs.powershellArgs[j], cmdLower); d != nil {
					detections = append(detections, *d)
				}
			}
		}
	}

	// EventsMatching: indexed by event_id for fast lookup
	if len(rs.emByEventID) > 0 {
		eidStr, _ := event["event_id"].(string)
		if eidStr != "" {
			eid, _ := strconv.Atoi(eidStr)
			if rules, ok := rs.emByEventID[eid]; ok {
				for _, rule := range rules {
					if d := evalEventsMatching(rule, event); d != nil {
						detections = append(detections, *d)
					}
				}
			}
		}
	}

	// Domain: check url/domain/remote_host against exfiltration domains
	domain, _ := event["domain"].(string)
	url, _ := event["url"].(string)
	remoteHost, _ := event["remote_host"].(string)
	if len(rs.domain) > 0 && (domain != "" || url != "" || remoteHost != "") {
		if !rs.isExcludedNetwork(event, domain, remoteHost) {
			for j := range rs.domain {
				if d := evalDomain(&rs.domain[j], domain, url, remoteHost); d != nil {
					detections = append(detections, *d)
				}
			}
		}
	}

	// RemoteManagement: literal/glob match on file paths
	fileName, _ := event["file_name"].(string)
	filePath, _ := event["file_path"].(string)
	processPath, _ := event["process_path"].(string)
	if fileName == "" {
		fileName = processName
	}
	if filePath == "" {
		filePath = processPath
	}
	if len(rs.remoteManagement) > 0 && (fileName != "" || filePath != "") {
		for j := range rs.remoteManagement {
			if d := evalRemoteManagement(&rs.remoteManagement[j], fileName, filePath, processName, processPath); d != nil {
				detections = append(detections, *d)
			}
		}
	}

	// ExecutableType: literal fileName match for data transfer tools
	if len(rs.executableType) > 0 && fileName != "" {
		for j := range rs.executableType {
			if d := evalExecutableType(&rs.executableType[j], fileName, eventType); d != nil {
				detections = append(detections, *d)
			}
		}
	}

	// LibNotOnDisk: DLL paths from memory analysis
	if len(rs.libNotOnDisk) > 0 && filePath != "" {
		for j := range rs.libNotOnDisk {
			if d := evalLibNotOnDisk(&rs.libNotOnDisk[j], fileName, filePath); d != nil {
				detections = append(detections, *d)
			}
		}
	}

	return detections
}

func (rs *compiledRuleSet) isExcludedNetwork(event converter.Event, domain, remoteHost string) bool {
	target := domain
	if target == "" {
		target = remoteHost
	}
	if target == "" {
		return false
	}

	for _, re := range rs.commonBitsDomain {
		if re.MatchString(target) {
			return true
		}
	}

	portStr, _ := event["remote_port"].(string)
	portNum, _ := strconv.Atoi(portStr)
	if portNum == 0 {
		if pf, ok := event["remote_port"].(float64); ok {
			portNum = int(pf)
		}
	}
	for _, hp := range rs.hostPortExclude {
		if hp.port == portNum && hp.host.MatchString(target) {
			return true
		}
	}
	return false
}

func (rs *compiledRuleSet) applyHayabusaExclusions(events []converter.Event) {
	excluded := 0
	for i := range events {
		ruleIDs, _ := events[i]["hayabusa_rule_id"].(string)
		if ruleIDs == "" {
			continue
		}
		for _, id := range strings.Split(ruleIDs, "; ") {
			if rs.hayabusaExclude[strings.TrimSpace(id)] {
				delete(events[i], "hayabusa_rule")
				delete(events[i], "hayabusa_rule_id")
				delete(events[i], "hayabusa_level")
				delete(events[i], "hayabusa_detection_count")
				tags := getExistingTags(events[i])
				var filtered []string
				for _, t := range tags {
					if !strings.HasPrefix(t, "hayabusa") && t != "sigma" {
						filtered = append(filtered, t)
					}
				}
				if len(filtered) > 0 {
					events[i]["tag"] = filtered
				} else {
					delete(events[i], "tag")
				}
				excluded++
				break
			}
		}
	}
	if excluded > 0 {
		progress.Info(fmt.Sprintf("  Removed %d Hayabusa false-positive detections via CloudRules exclusions", excluded))
	}
}

// ---------------------------------------------------------------------------
// Merge results into events
// ---------------------------------------------------------------------------

func mergeCloudRulesResults(conv *converter.Converter, results map[int][]CRDetection, impactMap map[string]string) int {
	tagged := 0
	for i, detections := range results {
		event := conv.Events[i]

		tags := getExistingTags(event)
		tags = appendUnique(tags, "cloudrules")

		var ruleNames, ruleIDs, analysisTypes, justifications []string
		scores := map[string]bool{}
		mitreSet := map[string]bool{}

		for _, d := range detections {
			name := d.ToolName
			if name == "" {
				name = d.AnalysisType
			}
			if d.Plugin != "" {
				name = d.Plugin + ": " + name
			}
			ruleNames = appendUniqueStr(ruleNames, name)
			ruleIDs = appendUniqueStr(ruleIDs, d.RuleID)
			analysisTypes = appendUniqueStr(analysisTypes, d.AnalysisType)

			resolved := resolveTemplate(d.Justification, event)
			justifications = appendUniqueStr(justifications, resolved)

			scores[d.Score] = true
			tags = appendUnique(tags, "cloudrules:"+strings.ToLower(d.Score))

			for _, m := range d.MitreAttack {
				mitreSet[m] = true
			}
		}

		event["tag"] = tags

		if len(ruleNames) <= 5 {
			event["cloudrules_rule"] = strings.Join(ruleNames, "; ")
		} else {
			event["cloudrules_rule"] = strings.Join(ruleNames[:5], "; ") +
				fmt.Sprintf(" (+%d more)", len(ruleNames)-5)
		}
		event["cloudrules_rule_id"] = strings.Join(ruleIDs, "; ")
		event["cloudrules_score"] = highestCRScore(scores)
		event["cloudrules_detection_count"] = len(detections)
		event["cloudrules_analysis_type"] = strings.Join(analysisTypes, "; ")

		if len(justifications) > 0 {
			event["cloudrules_justification"] = strings.Join(justifications, " | ")
		}

		// Impact from lookup table
		for _, at := range analysisTypes {
			if impact, ok := impactMap[at]; ok {
				event["cloudrules_impact"] = impact
				break
			}
		}

		// Merge MITRE ATT&CK with existing
		if existing, ok := event["mitre_attack"].(string); ok && existing != "" {
			for _, t := range strings.Split(existing, ", ") {
				mitreSet[strings.TrimSpace(t)] = true
			}
		}
		if len(mitreSet) > 0 {
			techniques := make([]string, 0, len(mitreSet))
			for t := range mitreSet {
				if t != "" {
					techniques = append(techniques, t)
				}
			}
			sort.Strings(techniques)
			event["mitre_attack"] = strings.Join(techniques, ", ")
		}

		conv.Events[i] = event
		tagged++
	}
	return tagged
}

// ---------------------------------------------------------------------------
// Template resolution
// ---------------------------------------------------------------------------

func resolveTemplate(template string, event converter.Event) string {
	if !strings.Contains(template, "${") && !strings.Contains(template, "{0}") {
		return template
	}

	result := template

	// ${payload.Field} and ${field} substitution
	for {
		start := strings.Index(result, "${")
		if start < 0 {
			break
		}
		end := strings.Index(result[start:], "}")
		if end < 0 {
			break
		}
		end += start

		expr := result[start+2 : end]
		// Strip pipe transforms for now (regex_replace etc.)
		if pipe := strings.Index(expr, "|"); pipe >= 0 {
			expr = expr[:pipe]
		}

		var value string
		if strings.HasPrefix(expr, "payload.") {
			fieldName := expr[8:]
			value = eventStr(event, fieldName)
			if value == "" {
				value = eventStr(event, toSnakeCase(fieldName))
			}
		} else {
			value = eventStr(event, expr)
			if value == "" {
				value = eventStr(event, toSnakeCase(expr))
			}
		}

		if value == "" {
			value = result[start : end+1]
		}
		result = result[:start] + value + result[end+1:]
	}

	return result
}

// ---------------------------------------------------------------------------
// Regex and pattern helpers
// ---------------------------------------------------------------------------

func convertJavaRegex(pattern string) string {
	if pattern == "" {
		return ""
	}
	var b strings.Builder
	i := 0
	for i < len(pattern) {
		if i+1 < len(pattern) && pattern[i] == '\\' && pattern[i+1] == 'Q' {
			end := strings.Index(pattern[i+2:], "\\E")
			if end >= 0 {
				b.WriteString(regexp.QuoteMeta(pattern[i+2 : i+2+end]))
				i = i + 2 + end + 2
				continue
			}
		}
		b.WriteByte(pattern[i])
		i++
	}
	return b.String()
}

func compileJavaRegex(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	goPattern := convertJavaRegex(pattern)
	goPattern = stripLookaheads(goPattern)
	re, err := regexp.Compile("(?i)" + goPattern)
	if err != nil {
		return nil
	}
	return re
}

// stripLookaheads removes Java/Perl-style lookahead assertions (?!...) and
// (?=...) that Go's regexp engine doesn't support. This makes the pattern
// slightly more permissive, which is acceptable for threat detection.
func stripLookaheads(pattern string) string {
	for {
		idx := strings.Index(pattern, "(?!")
		if idx < 0 {
			idx = strings.Index(pattern, "(?=")
		}
		if idx < 0 {
			break
		}
		depth := 0
		end := idx
		for i := idx; i < len(pattern); i++ {
			if pattern[i] == '(' {
				depth++
			} else if pattern[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		pattern = pattern[:idx] + pattern[end+1:]
	}
	return pattern
}

// globToRegex converts a CT domain glob pattern like "**.mega.nz" to a regex.
func globToRegex(glob string) string {
	glob = strings.ReplaceAll(glob, ".", "\\.")
	glob = strings.ReplaceAll(glob, "**\\.", "(.*\\.)?")
	glob = strings.ReplaceAll(glob, "*", "[^.]*")
	return "^" + glob + "$"
}

// compileGlob converts a file-path glob to a case-insensitive regex.
func compileGlob(pattern string) *regexp.Regexp {
	if pattern == "" {
		return nil
	}
	// Normalize forward slashes
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, "\\*\\*", ".*")
	escaped = strings.ReplaceAll(escaped, "\\*", "[^/]*")
	escaped = strings.ReplaceAll(escaped, "\\?", ".")
	re, err := regexp.Compile("(?i)" + escaped)
	if err != nil {
		return nil
	}
	return re
}

// ---------------------------------------------------------------------------
// Score helpers
// ---------------------------------------------------------------------------

var crScoreRank = map[string]int{
	"NOTABLE":        3,
	"LIKELY_NOTABLE": 2,
	"UNKNOWN":        1,
}

func highestCRScore(scores map[string]bool) string {
	best := ""
	bestRank := 0
	for s := range scores {
		if r, ok := crScoreRank[s]; ok && r > bestRank {
			best = s
			bestRank = r
		}
	}
	if best == "" {
		for s := range scores {
			return s
		}
	}
	return best
}

// ---------------------------------------------------------------------------
// Summary output
// ---------------------------------------------------------------------------

func printCloudRulesSummary(results map[int][]CRDetection) {
	byScore := map[string]int{}
	byPlugin := map[string]int{}
	byType := map[string]int{}
	total := 0

	for _, detections := range results {
		for _, d := range detections {
			byScore[d.Score]++
			byPlugin[d.Plugin]++
			byType[d.AnalysisType]++
			total++
		}
	}

	progress.Info(fmt.Sprintf("CloudRules: %d detections across %d events", total, len(results)))

	scoreOrder := []string{"NOTABLE", "LIKELY_NOTABLE", "UNKNOWN"}
	for _, score := range scoreOrder {
		if count, ok := byScore[score]; ok {
			progress.Info(fmt.Sprintf("  %-20s %d", score, count))
		}
	}

	type kv struct {
		k string
		v int
	}
	var topTypes []kv
	for k, v := range byType {
		topTypes = append(topTypes, kv{k, v})
	}
	sort.Slice(topTypes, func(i, j int) bool { return topTypes[i].v > topTypes[j].v })
	if len(topTypes) > 0 {
		progress.Info("  Top detection types:")
		limit := 5
		if len(topTypes) < limit {
			limit = len(topTypes)
		}
		for _, kv := range topTypes[:limit] {
			progress.Info(fmt.Sprintf("    %-45s %d", kv.k, kv.v))
		}
	}
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func compileResultData(r resultData) compiledResult {
	var mitre []string
	for _, m := range r.MitreAttackTypes {
		if m.ID != "" {
			mitre = append(mitre, m.ID)
		}
	}
	return compiledResult{
		analysisType:  r.AnalysisResultType,
		score:         r.Score,
		justification: r.Justification,
		mitreAttack:   mitre,
	}
}

func strSetFromSlice(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func intSetFromSlice(s []int) map[int]bool {
	m := make(map[int]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func toLowerSlice(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = strings.ToLower(v)
	}
	return out
}

func appendUniqueStr(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func eventStr(event converter.Event, key string) string {
	if v, ok := event[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func toSnakeCase(s string) string {
	var b strings.Builder
	for i, c := range s {
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(c + 32)
		} else if c == ' ' {
			b.WriteByte('_')
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func stripExtension(name string) string {
	if idx := strings.LastIndex(name, "."); idx > 0 {
		return name[:idx]
	}
	return name
}

func getExtension(name string) string {
	if idx := strings.LastIndex(name, "."); idx >= 0 && idx < len(name)-1 {
		return strings.ToLower(name[idx+1:])
	}
	return ""
}
