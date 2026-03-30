package postprocess

import (
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
)

// evalFileCorrelated checks a single FileCorrelated rule against an event.
// Returns a detection if all non-nil match fields are satisfied.
func evalFileCorrelated(rule *compiledFCRule, event converter.Event) *CRDetection {
	if !rule.hasNameCheck {
		return nil
	}

	processName, _ := event["process_name"].(string)
	fileName, _ := event["file_name"].(string)
	processPath, _ := event["process_path"].(string)
	filePath, _ := event["file_path"].(string)
	cmdLine, _ := event["command_line"].(string)
	parentPath, _ := event["parent_path"].(string)
	taskName, _ := event["task_name"].(string)
	if taskName == "" {
		taskName, _ = event["service_name"].(string)
	}

	// fileName match: test against both process_name and file_name
	if rule.fileName != nil {
		matched := false
		if processName != "" && rule.fileName.MatchString(processName) {
			matched = true
		}
		if !matched && fileName != "" && rule.fileName.MatchString(fileName) {
			matched = true
		}
		if !matched {
			return nil
		}
	}

	// fileNameNoExt
	if rule.fileNameNoExt != nil {
		matched := false
		if processName != "" && rule.fileNameNoExt.MatchString(stripExtension(processName)) {
			matched = true
		}
		if !matched && fileName != "" && rule.fileNameNoExt.MatchString(stripExtension(fileName)) {
			matched = true
		}
		if !matched {
			return nil
		}
	}

	// path match: test against process_path and file_path
	if rule.pathRe != nil {
		matched := false
		// Normalize to forward slashes for matching
		if processPath != "" && rule.pathRe.MatchString(toForwardSlash(processPath)) {
			matched = true
		}
		if !matched && filePath != "" && rule.pathRe.MatchString(toForwardSlash(filePath)) {
			matched = true
		}
		if !matched {
			return nil
		}
	}

	// extensions
	if len(rule.extensions) > 0 {
		ext := getExtension(fileName)
		if ext == "" {
			ext = getExtension(processName)
		}
		if ext == "" {
			return nil
		}
		matched := false
		for _, re := range rule.extensions {
			if re.MatchString(ext) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}

	// arguments: ALL must match command_line
	if len(rule.arguments) > 0 {
		if cmdLine == "" {
			return nil
		}
		for _, re := range rule.arguments {
			if !re.MatchString(cmdLine) {
				return nil
			}
		}
	}

	// parentProcess
	if rule.parentProcess != nil {
		if parentPath == "" || !rule.parentProcess.MatchString(toForwardSlash(parentPath)) {
			return nil
		}
	}

	// taskName
	if rule.taskName != nil {
		if taskName == "" || !rule.taskName.MatchString(taskName) {
			return nil
		}
	}

	// signedStatus (may not be available in current events)
	if rule.signedStatus != nil {
		status, _ := event["file_signed_status"].(string)
		if status == "" || !rule.signedStatus.MatchString(status) {
			return nil
		}
	}

	// sources
	if rule.sources != nil {
		source, _ := event["source_short"].(string)
		if source == "" {
			source, _ = event["source_long"].(string)
		}
		if source == "" || !rule.sources.MatchString(source) {
			return nil
		}
	}

	toolName := ""
	if processName != "" {
		toolName = processName
	} else if fileName != "" {
		toolName = fileName
	}

	return &CRDetection{
		RuleID:        rule.ruleID,
		Plugin:        "FileCorrelated",
		AnalysisType:  rule.result.analysisType,
		Score:         rule.result.score,
		Justification: rule.result.justification,
		MitreAttack:   rule.result.mitreAttack,
		ToolName:      toolName,
	}
}

// evalPowershellArgs checks if a case-insensitive command line contains the
// rule's argToken substring.
func evalPowershellArgs(rule *compiledPSRule, cmdLineLower string) *CRDetection {
	if !strings.Contains(cmdLineLower, rule.argToken) {
		return nil
	}
	return &CRDetection{
		RuleID:        rule.ruleID,
		Plugin:        "PowershellArgs",
		AnalysisType:  rule.result.analysisType,
		Score:         rule.result.score,
		Justification: rule.result.justification,
		MitreAttack:   rule.result.mitreAttack,
		ToolName:      rule.argToken,
	}
}

// evalDomain checks a domain glob pattern against url, domain, and remote_host.
func evalDomain(rule *compiledDomainRule, domain, url, remoteHost string) *CRDetection {
	matched := false
	if domain != "" && rule.domainPattern.MatchString(domain) {
		matched = true
	}
	if !matched && remoteHost != "" && rule.domainPattern.MatchString(remoteHost) {
		matched = true
	}
	if !matched && url != "" {
		// Extract domain from URL
		d := extractDomainFromURL(url)
		if d != "" && rule.domainPattern.MatchString(d) {
			matched = true
		}
	}
	if !matched {
		return nil
	}

	// Use newResult (most conservative) since we don't have OS age info
	return &CRDetection{
		RuleID:        rule.ruleID,
		Plugin:        "Domain",
		AnalysisType:  rule.newResult.analysisType,
		Score:         rule.newResult.score,
		Justification: rule.newResult.justification,
		MitreAttack:   rule.newResult.mitreAttack,
		ToolName:      rule.serviceProvider,
	}
}

// evalEventsMatching checks a compiled EventsMatching rule against a Windows
// event log entry. The event_id is already pre-filtered via the emByEventID
// index, so we only check logFileName and payload here.
func evalEventsMatching(rule *compiledEMRule, event converter.Event) *CRDetection {
	// logFileName or logNames must match
	channel, _ := event["channel"].(string)
	logName, _ := event["log_name"].(string)

	if rule.logFileName != nil {
		matched := false
		if channel != "" && rule.logFileName.MatchString(channel) {
			matched = true
		}
		if !matched && logName != "" && rule.logFileName.MatchString(logName) {
			matched = true
		}
		// Also try with .evtx suffix appended (CloudRules patterns often match "Name.evtx")
		if !matched && channel != "" {
			evtxName := strings.ReplaceAll(channel, "/", "%4") + ".evtx"
			if rule.logFileName.MatchString(evtxName) {
				matched = true
			}
		}
		if !matched {
			return nil
		}
	}

	if rule.logNames != nil {
		matched := false
		if channel != "" && rule.logNames.MatchString(channel) {
			matched = true
		}
		if !matched && logName != "" && rule.logNames.MatchString(logName) {
			matched = true
		}
		if !matched {
			return nil
		}
	}

	// payload field regex matching
	for field, re := range rule.payload {
		val := eventStr(event, field)
		if val == "" {
			val = eventStr(event, toSnakeCase(field))
		}
		if val == "" {
			// Check flattened event data attributes
			val = eventStr(event, strings.ToLower(strings.ReplaceAll(field, " ", "_")))
		}
		if val == "" || !re.MatchString(val) {
			return nil
		}
	}

	return &CRDetection{
		RuleID:        rule.ruleID,
		Plugin:        "EventsMatching",
		AnalysisType:  rule.result.analysisType,
		Score:         rule.result.score,
		Justification: rule.result.justification,
		MitreAttack:   rule.result.mitreAttack,
	}
}

// evalRemoteManagement checks if file/process paths match any RMM tool patterns.
// matchesPath entries are OR'd -- any single match triggers the rule.
// Within each entry, ALL non-empty fields must match (AND logic).
func evalRemoteManagement(rule *compiledRMMRule, fileName, filePath, processName, processPath string) *CRDetection {
	fileNameLower := strings.ToLower(fileName)
	processNameLower := strings.ToLower(processName)

	for _, mp := range rule.matches {
		allMatch := true
		hasCondition := false

		if mp.fileName != "" {
			hasCondition = true
			if fileNameLower != mp.fileName && processNameLower != mp.fileName {
				allMatch = false
			}
		}

		if allMatch && mp.fileNameNoExt != "" {
			hasCondition = true
			fnNoExt := strings.ToLower(stripExtension(fileName))
			pnNoExt := strings.ToLower(stripExtension(processName))
			if fnNoExt != mp.fileNameNoExt && pnNoExt != mp.fileNameNoExt {
				allMatch = false
			}
		}

		if allMatch && mp.pathGlob != nil {
			hasCondition = true
			fpNorm := strings.ToLower(toForwardSlash(filePath))
			ppNorm := strings.ToLower(toForwardSlash(processPath))
			pathOK := false
			if fpNorm != "" && mp.pathGlob.MatchString(fpNorm) {
				pathOK = true
			}
			if !pathOK && ppNorm != "" && mp.pathGlob.MatchString(ppNorm) {
				pathOK = true
			}
			if !pathOK {
				allMatch = false
			}
		}

		if allMatch && len(mp.extensions) > 0 {
			hasCondition = true
			ext := getExtension(fileName)
			if ext == "" {
				ext = getExtension(processName)
			}
			extOK := false
			for _, e := range mp.extensions {
				if ext == e {
					extOK = true
					break
				}
			}
			if !extOK {
				allMatch = false
			}
		}

		if hasCondition && allMatch {
			return &CRDetection{
				RuleID:       rule.ruleID,
				Plugin:       "RemoteManagement",
				AnalysisType: "REMOTE_ACCESS_SOFTWARE",
				Score:        "NOTABLE",
				MitreAttack:  nil,
				ToolName:     rule.toolID,
			}
		}
	}
	return nil
}

// evalExecutableType checks literal fileName matches for data transfer tools.
// Uses newResult (most conservative) since OS age isn't available.
func evalExecutableType(rule *compiledETRule, fileName, eventType string) *CRDetection {
	fileNameLower := strings.ToLower(fileName)

	for _, m := range rule.matches {
		if fileNameLower != m.fileName {
			continue
		}
		// Optional eventType filter
		if len(m.eventTypes) > 0 && !m.eventTypes[eventType] {
			continue
		}
		return &CRDetection{
			RuleID:        rule.ruleID,
			Plugin:        "ExecutableType",
			AnalysisType:  rule.newResult.analysisType,
			Score:         rule.newResult.score,
			Justification: rule.newResult.justification,
			MitreAttack:   rule.newResult.mitreAttack,
			ToolName:      rule.toolID,
		}
	}
	return nil
}

// evalLibNotOnDisk checks if a DLL path matches a known library pattern.
// This plugin targets DLLs loaded in memory that aren't on disk -- requires
// at least one match criterion and the file must have a DLL extension.
func evalLibNotOnDisk(rule *compiledLNDRule, fileName, filePath string) *CRDetection {
	hasCondition := false
	pathNorm := strings.ToLower(toForwardSlash(filePath))

	// Only evaluate against DLL/library files
	ext := getExtension(fileName)
	if ext == "" {
		ext = getExtension(filePath)
	}
	isDLL := ext == "dll" || ext == "sys" || ext == "drv"
	if len(rule.extensions) > 0 {
		isDLL = false
		for _, e := range rule.extensions {
			if ext == e {
				isDLL = true
				break
			}
		}
	}
	if !isDLL {
		return nil
	}

	if rule.pathGlob != nil {
		hasCondition = true
		if !rule.pathGlob.MatchString(pathNorm) {
			return nil
		}
	}

	if rule.fileNameNoExt != nil {
		hasCondition = true
		nameNoExt := strings.ToLower(stripExtension(fileName))
		if !rule.fileNameNoExt.MatchString(nameNoExt) {
			return nil
		}
	}

	if !hasCondition {
		return nil
	}

	justification := rule.justification
	if strings.Contains(justification, "{0}") {
		justification = strings.ReplaceAll(justification, "{0}", fileName)
	}

	return &CRDetection{
		RuleID:        rule.ruleID,
		Plugin:        "LibNotOnDisk",
		AnalysisType:  "DLL_INJECTION",
		Score:         rule.score,
		Justification: justification,
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func toForwardSlash(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}

func extractDomainFromURL(url string) string {
	u := url
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	if idx := strings.Index(u, "/"); idx >= 0 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx >= 0 {
		u = u[:idx]
	}
	if idx := strings.Index(u, "?"); idx >= 0 {
		u = u[:idx]
	}
	return u
}
