package help

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
)

const version = "2026.03.13.1"

type topic struct {
	name     string
	summary  string
	sections []section
	related  []string
}

type section struct {
	title   string
	content string
}

var topicOrder = []string{
	"pipeline",
	"extractors",
	"cloudrules",
	"hayabusa",
	"output",
	"cloud",
	"examples",
}

var (
	topics    map[string]*topic
	topicOnce sync.Once
)

func ensureTopics() {
	topicOnce.Do(func() {
		topics = map[string]*topic{
			"pipeline":   topicPipeline(),
			"extractors": topicExtractors(),
			"cloudrules": topicCloudRules(),
			"hayabusa":   topicHayabusa(),
			"output":     topicOutput(),
			"cloud":      topicCloud(),
			"examples":   topicExamples(),
		}
	})
}

// Show displays help for the given topic. If topic is empty, shows the index.
func Show(topicName string) {
	ensureTopics()

	if topicName == "" {
		showIndex()
		return
	}

	t, ok := topics[strings.ToLower(topicName)]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown help topic: %q\n\n", topicName)
		fmt.Fprintf(os.Stderr, "Available topics:\n")
		for _, name := range topicOrder {
			fmt.Fprintf(os.Stderr, "  %-14s %s\n", name, topics[name].summary)
		}
		fmt.Fprintf(os.Stderr, "\nUse \"ct-to-timesketch help <topic>\" for details.\n")
		os.Exit(1)
	}

	showTopic(t)
}

func showIndex() {
	fmt.Printf("ct-to-timesketch %s\n", version)
	fmt.Println()
	fmt.Println("  A pure Go forensic timeline converter for CyberTriage captures.")
	fmt.Println("  Converts .json.gz capture files to Timesketch JSONL format with optional")
	fmt.Println("  Hayabusa Sigma and CyberTriage CloudRules threat detection.")
	fmt.Println()
	fmt.Println("Topics:")
	for _, name := range topicOrder {
		t := topics[name]
		fmt.Printf("  %-14s %s\n", name, t.summary)
	}
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  ct-to-timesketch help <topic>        Show detailed help for a topic")
	fmt.Println("  ct-to-timesketch --help               Show flag reference")
	fmt.Println("  ct-to-timesketch --version            Show version")
	fmt.Println("  ct-to-timesketch --list-extractors    Show all extractors")
	fmt.Println()
	fmt.Println("Quick start:")
	fmt.Println("  ct-to-timesketch capture.json.gz")
	fmt.Println("  ct-to-timesketch capture.json.gz --hayabusa --cloudrules")
}

func showTopic(t *topic) {
	fmt.Printf("ct-to-timesketch help %s\n", t.name)
	fmt.Println()

	for _, s := range t.sections {
		fmt.Printf("%s\n", s.title)
		for _, line := range strings.Split(s.content, "\n") {
			fmt.Printf("  %s\n", line)
		}
		fmt.Println()
	}

	if len(t.related) > 0 {
		fmt.Printf("Related topics: %s\n", strings.Join(t.related, ", "))
		fmt.Println("Use \"ct-to-timesketch help <topic>\" for details.")
	}
}

// ---------------------------------------------------------------------------
// Topic: pipeline
// ---------------------------------------------------------------------------

func topicPipeline() *topic {
	return &topic{
		name:    "pipeline",
		summary: "How the processing pipeline works end-to-end",
		sections: []section{
			{title: "Overview", content: `The pipeline processes a CyberTriage .json.gz capture in sequential stages.
Each stage feeds into the next. All stages except threat detection are mandatory.`},
			{title: "Stages", content: `Stage 1: DECOMPRESS
  Input:   capture.json.gz (compressed CyberTriage export)
  Output:  capture.json.cache (decompressed JSON, stored beside the original)
  Details: gzip decompression. Skipped if .cache already exists.
  Typical: 5-10 seconds for 1GB compressed

Stage 2: STREAMING SCAN
  Input:   .json.cache file
  Output:  Timeline events (processes, logons, DNS, network, services, tasks, MFT)
           Native artifacts exported to artifacts/<hostname>/
  Details: Single-pass byte-level JSON streaming parser. Creates timeline events
           AND extracts collected files (EVTX, registry hives, prefetch, etc.)
           as native files on disk for subsequent extractors.
  Typical: 15-30 seconds per GB of decompressed data

Stage 3: EXTRACTORS (all run automatically)
  Input:   Native artifact files in artifacts/<hostname>/
  Output:  Additional timeline events from binary parsing
  Details: Pure Go parsers for EVTX, registry, SRUM, browser history, LNK,
           prefetch, PowerShell history, scheduled tasks, and more.
           Every registered extractor runs unconditionally.
  Typical: 1-10 seconds total for all extractors

Stage 4: HAYABUSA THREAT DETECTION (optional, --hayabusa)
  Input:   Native EVTX files in artifacts/<hostname>/
  Output:  Hayabusa detection tags merged into matching timeline events
  Details: Shells out to the Hayabusa binary which applies Sigma rules
           against EVTX files. Results matched by (channel, record_number).
  Typical: 10-60 seconds depending on EVTX volume

Stage 5: CLOUDRULES THREAT DETECTION (optional, --cloudrules)
  Input:   All accumulated timeline events + CloudRules json.gz file
  Output:  CloudRules detection tags merged into matching timeline events
  Details: Go-native rule evaluation engine. 386 rules across 12 plugin types.
           Evaluates every event against compiled regex patterns. Must run
           AFTER Hayabusa (HayabusaExclusion plugin removes FP detections).
  Typical: 20-150 seconds depending on event count

Stage 6: WRITE JSONL
  Input:   All accumulated timeline events
  Output:  reports/<hostname>_timeline.jsonl
  Details: Buffered JSON encoding with 4MB write buffer.
  Typical: 1-5 seconds`},
			{title: "Data flow", content: `capture.json.gz
  -> [Decompress] -> .json.cache
  -> [Streaming Scan] -> timeline events + artifacts/<hostname>/
  -> [Extractors] -> additional timeline events
  -> [Hayabusa] -> Sigma detection tags on EVTX events
  -> [CloudRules] -> CloudRules detection tags on all events
  -> [Write JSONL] -> reports/<hostname>_timeline.jsonl`},
			{title: "Flags that affect pipeline behavior", content: `--skip-base         Skip stages 1-2, re-run extractors against existing artifacts
--hayabusa          Enable stage 4 (Hayabusa Sigma detection)
--hayabusa-path     Explicit path to Hayabusa binary
--cloudrules        Enable stage 5 (CloudRules threat detection)
--cloudrules-path   Explicit path to CloudRules json.gz file
--artifacts-dir     Override default artifacts/<hostname>/ directory
--output / -o       Override default reports/<hostname>_timeline.jsonl path`},
			{title: "Performance expectations", content: `Capture Size    Events         Total Time    Throughput
500 MB          ~500K-1M       30-60s        ~15-30 MB/s
1 GB            ~2-4M          1-3 min       ~15-25 MB/s
2 GB            ~3-8M          3-8 min       ~10-20 MB/s
2.5 GB          ~4-8M          5-12 min      ~10-15 MB/s

CloudRules adds ~20-150s depending on event count.
Hayabusa adds ~10-60s depending on EVTX volume.`},
		},
		related: []string{"extractors", "cloudrules", "hayabusa", "output"},
	}
}

// ---------------------------------------------------------------------------
// Topic: extractors
// ---------------------------------------------------------------------------

func topicExtractors() *topic {
	names := extractors.ListNames()
	sort.Strings(names)

	var listBuilder strings.Builder
	for _, name := range names {
		ext := extractors.Get(name)
		if ext == nil {
			continue
		}
		listBuilder.WriteString(fmt.Sprintf("%-20s %s\n", name, ext.Description()))
	}

	return &topic{
		name:    "extractors",
		summary: "All forensic extractors and what they parse",
		sections: []section{
			{title: "Overview", content: `Every registered extractor runs automatically on every capture.
There are no --parse flags. The streaming scan (stage 2) exports collected
files as native artifacts to disk, then each extractor parses its file types.

Cloud-only extractors (entra, mdo) require explicit mode flags.`},
			{title: "Registered extractors", content: strings.TrimSpace(listBuilder.String())},
			{title: "Extractor details", content: `browser
  Files:       History, Cookies (SQLite databases)
  Patterns:    Chrome, Edge, Firefox profile directories
  Events:      web_visit, web_download
  Key fields:  url, domain, title, visit_count, browser_name

dhcp
  Files:       DHCP Server audit logs
  Events:      dhcp_lease
  Key fields:  client_ip, client_mac, hostname, event_id

evtx
  Files:       *.evtx (Windows Event Log)
  Parser:      Pure Go EVTX parser with full EventData/UserData extraction
  Events:      windows_logon, windows_process, windows_account,
               windows_authentication, windows_firewall, windows_task,
               windows_rdp, windows_powershell, windows_dns, windows_smb,
               windows_defender, windows_dhcp, windows_service, windows_event
  Key fields:  event_id, channel, record_number, provider_name, plus all
               EventData fields flattened into the event

lnk
  Files:       *.lnk (Windows shortcut files)
  Events:      lnk_target
  Key fields:  target_path, working_dir, arguments, drive_type, volume_label

powershell
  Files:       ConsoleHost_history.txt
  Events:      powershell_history
  Key fields:  command, is_suspicious, suspicious_indicators

prefetch
  Files:       *.pf (Windows Prefetch)
  Events:      prefetch_execution
  Key fields:  executable_name, run_count, prefetch_hash

recyclebin
  Files:       $I* (Recycle Bin metadata)
  Events:      recyclebin_delete
  Key fields:  original_path, file_size, deleted_by

registry
  Files:       NTUSER.DAT, UsrClass.dat, SAM, SYSTEM, SOFTWARE, SECURITY,
               Amcache.hve
  Parser:      Pure Go registry hive parser
  Events:      startup_item, registry_shellbag, registry_userassist,
               registry_bam, registry_usb, registry_service, registry_amcache,
               registry_shimcache, registry_networklist, registry_typedurls,
               registry_recentdocs, registry_winlogon, registry_software
  Key fields:  key_path, value_name, value_data (varies by artifact type)

scheduled_tasks
  Files:       *.xml (Task Scheduler XML exports)
  Events:      scheduled_task
  Key fields:  task_name, task_path, command, arguments, author, triggers

srum
  Files:       SRUDB.dat (System Resource Usage Monitor)
  Parser:      Pure Go ESE database parser
  Events:      srum_app_usage, srum_network_connectivity, srum_network_data
  Key fields:  app_id, user_sid, bytes_sent, bytes_received, foreground_time

timeline
  Files:       ActivitiesCache.db (Windows Timeline)
  Events:      timeline_activity, timeline_engaged
  Key fields:  app_id, activity_type, display_text, device_id

wmi
  Files:       OBJECTS.DATA (WMI repository)
  Events:      wmi_persistence
  Key fields:  consumer_name, consumer_type, event_filter, command

entra (requires --entra flag)
  Files:       Entra ID / Azure AD sign-in JSON exports
  Events:      entra_signin, entra_audit
  Key fields:  user_principal_name, app_display_name, ip_address,
               location, status, conditional_access_status

mdo (requires --mdo flag)
  Files:       Microsoft Defender for Office 365 CSV exports
  Events:      mdo_url_click, mdo_email_event
  Key fields:  url, sender, recipient, action, threat_type`},
		},
		related: []string{"pipeline", "output"},
	}
}

// ---------------------------------------------------------------------------
// Topic: cloudrules
// ---------------------------------------------------------------------------

func topicCloudRules() *topic {
	return &topic{
		name:    "cloudrules",
		summary: "CyberTriage CloudRules threat detection engine (12 plugin types)",
		sections: []section{
			{title: "Overview", content: `CloudRules is a Go-native rule evaluation engine that applies CyberTriage
threat detection rules against all timeline events. Unlike Hayabusa (which
shells out to an external binary for EVTX files only), CloudRules evaluates
compiled regex patterns directly against every event in memory.

Enable with: --cloudrules
Specify rules: --cloudrules-path <path-to-CloudRules.json.gz>`},
			{title: "Rule file discovery", content: `When --cloudrules-path is not specified, the tool searches:
  1. cloudrules/ directory beside the binary
  2. cloudrules/ in the current working directory
  3. ~/.ct-to-timesketch/cloudrules/

It looks for files matching CloudRules_rv*.json.gz or CloudRules_rv*.json
and picks the highest revision number.

A bundled rule file is included in the repository at:
  cloudrules/CloudRules_rv3160001.json.gz`},
			{title: "Plugin types (12)", content: `Plugin                         Rules  Description
FileCorrelatedCloudRule        122    Regex match on fileName, path, arguments, dataTypes
PowershellArgsCloudRule         78    Substring match on PowerShell command lines
DomainCloudRule                 64    Glob match on URLs, domains, remote hosts
RemoteManagementCloudRule       45    Literal/glob match on RMM tool file paths
EventsMatchingCloudRule         38    Event ID + log name + payload field regex
ExecutableTypeCloudRule         18    Literal fileName match for data transfer tools
LibNotOnDiskCloudRule           16    DLL path match for injection indicators
MalwareDowngradeCloudRule       11    Post-process: reduce severity for known FPs
ImpactMappingCloudRule           2    Lookup table: analysis type -> impact text
CommonBitsJobDomainCloudRule     2    Suppress BITS job domain false positives
HayabusaCloudRule                1    Remove specific Hayabusa false positives
HostPortExclusionCloudRule       1    Suppress host:port network false positives`},
			{title: "Scoring model", content: `Each detection receives a score indicating severity:

  NOTABLE          Highest severity. Strongly indicates compromise or misuse.
  LIKELY_NOTABLE   Moderate severity. Warrants investigation.
  UNKNOWN          Low severity. Informational; context-dependent.

When multiple rules match a single event, the highest score wins.
Domain and ExecutableType plugins support age-tier scoring (new vs old
artifacts). Without OS install date, the tool defaults to newResult
(most conservative/highest severity).`},
			{title: "Detection types (common)", content: `Type                              Meaning
REMOTE_ACCESS_SOFTWARE            RMM/remote access tool detected
DATA_TRANSFER_TOOL                Exfiltration-capable tool (rclone, restic, etc.)
POWERSHELL_DOWNLOAD               PowerShell download cradle pattern
POWERSHELL_SCRIPT_BAD_NAME        Known malicious PowerShell script name
WINDOWS_DEFENDER_EXCLUSION_RULE   Defender exclusion added (persistence technique)
WINDOWS_DEFENDER_FEATURE_DISABLED Defender feature disabled (defense evasion)
DOUBLE_FILE_EXTENSION             Masquerading: file.doc.exe pattern
BADLIST_HIT                       Known suspicious executable name
EXTERNAL_STORAGE_DOMAIN           Cloud storage / exfiltration domain
DLL_INJECTION                     Memory-resident DLL not on disk
ACCOUNT_COMPROMISE_DETECTED       Compromised account indicators`},
			{title: "Event enrichment fields", content: `When a rule matches, these fields are added to the event:

Field                        Description
tag                          ["cloudrules", "cloudrules:<score>"] appended to existing tags
cloudrules_rule              Plugin type + tool/detection name
cloudrules_rule_id           Rule UUID(s), semicolon-separated
cloudrules_score             Highest score: NOTABLE > LIKELY_NOTABLE > UNKNOWN
cloudrules_detection_count   Number of rules that matched this event
cloudrules_analysis_type     Analysis result type(s), semicolon-separated
cloudrules_justification     Human-readable justification text(s)
cloudrules_impact            Impact description from lookup table
mitre_attack                 MITRE ATT&CK technique IDs, merged with existing`},
			{title: "Parameters", content: `--cloudrules           Enable CloudRules threat detection (bool, default false)
--cloudrules-path      Path to CloudRules json.gz file (string, auto-detected)`},
		},
		related: []string{"hayabusa", "output", "pipeline"},
	}
}

// ---------------------------------------------------------------------------
// Topic: hayabusa
// ---------------------------------------------------------------------------

func topicHayabusa() *topic {
	return &topic{
		name:    "hayabusa",
		summary: "Hayabusa Sigma-based EVTX threat detection",
		sections: []section{
			{title: "Overview", content: `Hayabusa is an external Sigma-based threat detection tool for Windows Event
Logs. When --hayabusa is specified, the tool runs the Hayabusa binary against
exported EVTX files and merges detection results back into matching timeline
events by (channel, record_number).

Hayabusa must be installed separately. The tool auto-detects its location.
Install from: https://github.com/Yamato-Security/hayabusa`},
			{title: "Binary discovery", content: `When --hayabusa-path is not specified, the tool searches:
  1. System PATH (via exec.LookPath)
  2. ~/tools/hayabusa/hayabusa
  3. ~/hayabusa/hayabusa
  4. /opt/hayabusa/hayabusa
  5. /usr/local/bin/hayabusa`},
			{title: "How it works", content: `1. Locates the Hayabusa binary
2. Finds exported EVTX files under artifacts/<hostname>/
3. Runs: hayabusa json-timeline -d <evtx-dir> -o <output> -m low -w -C -L
4. Parses the JSONL output (Channel, RecordID, RuleTitle, Level, MitreAttack)
5. Matches detections to existing timeline events by (channel, record_number)
6. Merges detection metadata into matched events`},
			{title: "Severity levels (low to high)", content: `Level            Description
informational    Normal system activity; context only
low              Minor anomaly; usually benign
medium           Suspicious activity; warrants review
high             Likely malicious; investigate promptly
critical         Active compromise indicators; immediate response`},
			{title: "Event enrichment fields", content: `Field                        Description
tag                          ["hayabusa", "sigma", "hayabusa:<level>"] appended
hayabusa_rule                Sigma rule title(s), semicolon-separated
hayabusa_rule_id             Sigma rule UUID(s), semicolon-separated
hayabusa_level               Highest severity: critical > high > medium > low
hayabusa_detection_count     Number of Sigma rules that matched this event
mitre_attack                 MITRE ATT&CK technique IDs from Sigma tags`},
			{title: "Parameters", content: `--hayabusa          Enable Hayabusa threat detection (bool, default false)
--hayabusa-path     Path to Hayabusa binary (string, auto-detected)`},
			{title: "Interaction with CloudRules", content: `CloudRules MUST run after Hayabusa. The HayabusaCloudRule plugin removes
specific Hayabusa false-positive detections identified by CyberTriage.
If both --hayabusa and --cloudrules are used, the pipeline automatically
runs them in the correct order.`},
		},
		related: []string{"cloudrules", "output", "pipeline"},
	}
}

// ---------------------------------------------------------------------------
// Topic: output
// ---------------------------------------------------------------------------

func topicOutput() *topic {
	return &topic{
		name:    "output",
		summary: "JSONL output format, Timesketch fields, and enrichment attributes",
		sections: []section{
			{title: "Overview", content: `Output is a JSONL (JSON Lines) file where each line is a self-contained JSON
object representing one timeline event. This format is directly importable
into Timesketch.

Default path: reports/<hostname>_timeline.jsonl
Override with: --output <path> or -o <path>`},
			{title: "Core fields (present on every event)", content: `Field              Type     Description
datetime           string   ISO 8601 timestamp with milliseconds (2024-01-15T14:30:00.000Z)
timestamp_desc     string   What this timestamp represents (e.g. "Windows Event Log Entry")
message            string   Human-readable event summary
data_type          string   Timesketch data type classification (e.g. "windows:evtx:record")
event_type         string   Event category (e.g. "windows_logon", "file_timeline")
source_short       string   Short source identifier (e.g. "CT-EventLog")
source_long        string   Detailed source description
host_name          string   Hostname of the analyzed system`},
			{title: "Common artifact fields (vary by event_type)", content: `Field              Found on                  Description
process_name       process_execution         Executable file name
process_path       process_execution         Full path to executable
command_line       process_execution         Full command line with arguments
parent_path        process_execution         Parent process path
pid                process_execution         Process ID
user               process_execution         User who ran the process
file_name          file_timeline             File name from MFT
file_path          file_timeline             Full file path
file_size          file_timeline             File size in bytes
event_id           windows_* events          Windows Event ID number
channel            windows_* events          Event log channel name
record_number      windows_* events          Event log record number
url                web_visit                 Full URL
domain             web_visit, network_*      Domain name
remote_host        network_connection        Remote hostname/IP
remote_port        network_connection        Remote port number`},
			{title: "CyberTriage analysis fields", content: `These fields come from CyberTriage's own analysis results embedded in
the capture file. They are extracted automatically.

Field                  Description
ct_significance        CyberTriage significance rating
ct_analysis_type       Analysis type (e.g. MALWARE, SUSPICIOUS)
ct_justification       CyberTriage's explanation of the finding
mitre_attack_ids       MITRE ATT&CK IDs from CyberTriage analysis`},
			{title: "Hayabusa enrichment fields (--hayabusa)", content: `Field                        Description
tag                          ["hayabusa", "sigma", "hayabusa:<level>"]
hayabusa_rule                Sigma rule title(s)
hayabusa_rule_id             Sigma rule UUID(s)
hayabusa_level               Highest: critical > high > medium > low > informational
hayabusa_detection_count     Number of matching Sigma rules`},
			{title: "CloudRules enrichment fields (--cloudrules)", content: `Field                        Description
tag                          ["cloudrules", "cloudrules:<score>"]
cloudrules_rule              Plugin type + tool/detection name
cloudrules_rule_id           Rule UUID(s)
cloudrules_score             Highest: NOTABLE > LIKELY_NOTABLE > UNKNOWN
cloudrules_detection_count   Number of matching CloudRules
cloudrules_analysis_type     Detection category (e.g. REMOTE_ACCESS_SOFTWARE)
cloudrules_justification     Human-readable explanation
cloudrules_impact            Impact description from lookup table`},
			{title: "Shared enrichment fields", content: `Field              Description
mitre_attack       MITRE ATT&CK technique IDs, merged from all sources
                   (CyberTriage, Hayabusa, CloudRules). Comma-separated.
tag                String array of all tags. Multiple sources append to
                   the same array. Example: ["hayabusa", "sigma",
                   "hayabusa:high", "cloudrules", "cloudrules:notable"]`},
			{title: "Tag structure", content: `Tags follow a namespace:value pattern for filtering in Timesketch:

Source tags:       hayabusa, sigma, cloudrules
Level tags:        hayabusa:critical, hayabusa:high, hayabusa:medium,
                   hayabusa:low, hayabusa:informational
Score tags:        cloudrules:notable, cloudrules:likely_notable,
                   cloudrules:unknown

Timesketch filter examples:
  tag:"hayabusa"                    All Hayabusa detections
  tag:"cloudrules:notable"          High-severity CloudRules hits
  tag:"hayabusa:critical"           Critical Sigma detections
  tag:"cloudrules" AND tag:"hayabusa"  Events flagged by both engines`},
		},
		related: []string{"cloudrules", "hayabusa", "extractors"},
	}
}

// ---------------------------------------------------------------------------
// Topic: cloud
// ---------------------------------------------------------------------------

func topicCloud() *topic {
	return &topic{
		name:    "cloud",
		summary: "Cloud log modes: Entra ID and Microsoft Defender for Office 365",
		sections: []section{
			{title: "Overview", content: `Cloud log modes process Azure/M365 log exports directly, bypassing the
CyberTriage streaming scan pipeline. Each mode requires an explicit flag.`},
			{title: "Entra ID mode (--entra)", content: `Processes Microsoft Entra ID (Azure AD) sign-in and audit log exports.

Usage:
  ct-to-timesketch sign_in_logs.json --entra
  ct-to-timesketch /path/to/entra-exports/ --entra

Input formats:
  - Single JSON file with sign-in or audit records
  - Directory containing multiple JSON export files

Event types produced:
  entra_signin     Sign-in events (interactive, non-interactive, service principal)
  entra_audit      Directory changes, app registrations, role assignments

Key fields:
  user_principal_name, app_display_name, ip_address, location,
  status, conditional_access_status, risk_level, risk_state,
  client_app, resource_display_name

How to export from Azure:
  1. Azure Portal -> Microsoft Entra ID -> Sign-in logs
  2. Click "Download" -> JSON format
  3. For audit logs: Monitoring -> Audit logs -> Download -> JSON`},
			{title: "MDO mode (--mdo)", content: `Processes Microsoft Defender for Office 365 threat event exports.

Usage:
  ct-to-timesketch url_clicks.csv --mdo
  ct-to-timesketch /path/to/mdo-exports/ --mdo

Input formats:
  - CSV export from Microsoft 365 Defender portal
  - Directory containing multiple CSV files

Event types produced:
  mdo_url_click      URL click events (Safe Links)
  mdo_email_event    Email delivery/block events

Key fields:
  url, sender, recipient, subject, action, threat_type,
  delivery_action, detection_method, click_time

How to export from M365:
  1. Microsoft 365 Defender -> Email & collaboration -> Explorer
  2. Select time range and filters
  3. Export to CSV`},
			{title: "Parameters", content: `--entra    Input is Entra ID / Azure AD sign-in JSON (bool, default false)
--mdo      Input is Microsoft Defender for Office 365 CSV (bool, default false)

Note: --entra and --mdo bypass the CyberTriage streaming scan entirely.
The input file does not need to be a .json.gz capture.`},
			{title: "Combining with threat detection", content: `Cloud log modes can be combined with --cloudrules for domain-based
threat detection on Entra sign-in sources and MDO URL click events.
Hayabusa is not applicable (no EVTX files).

Example:
  ct-to-timesketch sign_in_logs.json --entra --cloudrules`},
		},
		related: []string{"pipeline", "output", "examples"},
	}
}

// ---------------------------------------------------------------------------
// Topic: examples
// ---------------------------------------------------------------------------

func topicExamples() *topic {
	return &topic{
		name:    "examples",
		summary: "Common usage patterns and automation recipes",
		sections: []section{
			{title: "Basic conversion", content: `# Convert a single CyberTriage capture (all extractors run automatically)
ct-to-timesketch capture.json.gz

# Specify output path
ct-to-timesketch capture.json.gz -o /path/to/output.jsonl

# Specify artifacts directory
ct-to-timesketch capture.json.gz --artifacts-dir /mnt/fast-ssd/artifacts/`},
			{title: "With threat detection", content: `# Hayabusa Sigma rules only
ct-to-timesketch capture.json.gz --hayabusa

# CloudRules only
ct-to-timesketch capture.json.gz --cloudrules

# Both engines (recommended for comprehensive detection)
ct-to-timesketch capture.json.gz --hayabusa --cloudrules

# With explicit paths to detection tools
ct-to-timesketch capture.json.gz \
  --hayabusa --hayabusa-path /opt/hayabusa/hayabusa \
  --cloudrules --cloudrules-path /opt/cloudrules/CloudRules_rv3160001.json.gz`},
			{title: "Cloud log analysis", content: `# Entra ID sign-in logs
ct-to-timesketch sign_in_logs.json --entra

# Entra ID with CloudRules domain detection
ct-to-timesketch sign_in_logs.json --entra --cloudrules

# MDO (Defender for Office) events
ct-to-timesketch url_clicks.csv --mdo

# Directory of Entra exports
ct-to-timesketch /path/to/entra-exports/ --entra`},
			{title: "Re-running extractors", content: `# Skip streaming scan, re-run extractors against existing artifacts
# Useful when adding new extractors or debugging
ct-to-timesketch capture.json.gz --skip-base

# Re-run with threat detection on existing artifacts
ct-to-timesketch capture.json.gz --skip-base --hayabusa --cloudrules`},
			{title: "Automation and scripting", content: `# Process all captures in a directory
for f in captures/**/*.json.gz; do
  ct-to-timesketch "$f" --cloudrules
done

# Process with cleanup between runs (preserves disk space)
for f in captures/**/*.json.gz; do
  ct-to-timesketch "$f" --cloudrules
  HOSTNAME=$(ct-to-timesketch "$f" 2>&1 | grep "Host:" | awk '{print $2}')
  rm -rf "artifacts/$HOSTNAME"
  rm -f "${f%.gz}.cache"
done

# Get version for scripting
ct-to-timesketch --version

# List extractors programmatically
ct-to-timesketch --list-extractors

# Check available help topics
ct-to-timesketch help

# Get structured info on a specific capability
ct-to-timesketch help cloudrules`},
			{title: "Agentic AI integration", content: `# Discover tool capabilities
ct-to-timesketch help

# Get detailed field reference for output parsing
ct-to-timesketch help output

# Understand detection enrichment for post-processing
ct-to-timesketch help cloudrules
ct-to-timesketch help hayabusa

# Verify tool is available and check version
ct-to-timesketch --version

# Process a capture and parse results
ct-to-timesketch capture.json.gz --cloudrules --hayabusa -o timeline.jsonl
# Then parse timeline.jsonl (each line is a JSON object)
# Filter by: tag contains "cloudrules:notable" for high-severity findings
# Filter by: tag contains "hayabusa:critical" for critical Sigma hits`},
		},
		related: []string{"pipeline", "output", "cloudrules", "hayabusa", "cloud"},
	}
}
