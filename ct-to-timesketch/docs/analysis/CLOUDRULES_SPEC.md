# CyberTriage CloudRules json.gz Specification

> **Version**: 1.0 -- Derived from `CloudRules_rv3160001.json.gz` and `JsonGzCloudRuleParser.java`  
> **Date**: 2026-03-10  
> **Source of Truth**: Decompiled Java parser + data-driven analysis of 398 rules across 12 plugin types  
> **Companions**: [CYBERTRIAGE_JSON_GZ_SPEC.md](CYBERTRIAGE_JSON_GZ_SPEC.md) | [CLOUDRULES_ANALYSIS.md](CLOUDRULES_ANALYSIS.md) | [CT_PROCESSING_PIPELINE.md](CT_PROCESSING_PIPELINE.md)

---

## 1. File-Level Envelope

CloudRules are distributed as a single file per revision, either gzip-compressed or plain JSON.

### File naming

```
CloudRules_rv<revision>.json.gz
CloudRules_rv<revision>.json
```

The revision number encodes the minimum CT version (e.g., `rv3160001` = CT 3.16.0, patch 001).

### Location on CyberTriage Server

```
C:\Program Files\Cyber Triage\cybertriage\cloudrules\CloudRules_rv<revision>.json.gz
```

### Envelope schema

```json
{
  "rules": [
    { ...CloudRule object... },
    { ...CloudRule object... }
  ]
}
```

The root is a JSON object with a single key `"rules"` whose value is an array of CloudRule objects.

### Parser configuration (Java reference)

`JsonGzCloudRuleParser` (singleton) uses Jackson `ObjectMapper` with:

- `FAIL_ON_UNKNOWN_PROPERTIES = false` -- forward-compatible; new fields are silently ignored
- `FAIL_ON_MISSING_CREATOR_PROPERTIES = false`
- `FAIL_ON_NULL_CREATOR_PROPERTIES = false`
- Custom deserializers for `CloudRuleMetadata` and `CloudRuleListDTO`

Accepts both `.json.gz` (auto-decompresses via `GZIPInputStream`) and `.json` (plain read).

### Quick-start parsing walkthrough

This section provides a step-by-step recipe for reading and deserializing a CloudRules file. Detailed schemas for each element follow in Sections 2-6.

**Step 1: Open and decompress**

If the file ends in `.json.gz`, wrap the file reader in a gzip decompressor. If it ends in `.json`, read directly. The result is a UTF-8 JSON stream.

```go
var reader io.Reader
if strings.HasSuffix(path, ".json.gz") {
    f, _ := os.Open(path)
    reader, _ = gzip.NewReader(f)
} else {
    reader, _ = os.Open(path)
}
```

**Step 2: Unmarshal the root envelope**

The root JSON object has a single key `"rules"` containing an array. Each element is a CloudRule.

```go
type CloudRulesFile struct {
    Rules []CloudRule `json:"rules"`
}

var file CloudRulesFile
json.NewDecoder(reader).Decode(&file)
// file.Rules has 398 elements in rv3160001
```

**Step 3: Iterate rules, skip disabled**

Each CloudRule has a fixed set of top-level fields. Disabled rules (`enabled: false`) have no `ruleMetadata` and must be skipped.

```go
type CloudRule struct {
    RuleID                 string           `json:"ruleId"`
    RuleVersion            int              `json:"ruleVersion"`
    EffectiveMinCtVersion  string           `json:"effectiveMinCtVersion"`
    Plugin                 string           `json:"plugin"`
    Enabled                bool             `json:"enabled"`
    RuleMetadata           *RuleMetadata    `json:"ruleMetadata,omitempty"`
}

for _, rule := range file.Rules {
    if !rule.Enabled || rule.RuleMetadata == nil {
        continue
    }
    // process rule...
}
```

**Step 4: Unwrap ruleMetadata**

`ruleMetadata` is always `{"type": "JSON", "payload": {...}}`. The `type` field is always `"JSON"` in the current revision. The `payload` is a `json.RawMessage` whose shape depends on the `plugin` type.

```go
type RuleMetadata struct {
    Type    string          `json:"type"`
    Payload json.RawMessage `json:"payload"`
}
```

**Step 5: Dispatch on plugin type, unmarshal payload**

Switch on the `plugin` string to select the correct payload struct. There are 12 plugin types, each with a distinct payload schema (documented in Section 4). Most plugins wrap their rules in a `payload.rules` array, but some use different top-level keys.

```go
switch rule.Plugin {
case "FileCorrelatedCloudRulePlugin_v1":
    // payload.rules[] -> {matches, result}
    var p FileCorrelatedPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "PowershellArgsCloudRulePlugin_v1":
    // payload.rules[] -> {argToken, result}
    var p PowershellArgsPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "DomainCloudRulePlugin_v1":
    // payload.domains[] -> {serviceProvider, domainIdentifier, ...}
    var p DomainPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "EventsMatchingCloudRulePlugin_v1":
    // payload.rules[] -> {context, matches, result}
    var p EventsMatchingPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "ExecutableTypeCloudRulePlugin_v1":
    // payload.rules[] -> {record, context, matches}
    var p ExecutableTypePayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "RemoteManagementCloudRulePlugin_v1":
    // payload.rules[] -> {rmmRecord, context, matchesPath}
    var p RemoteManagementPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "LibNotOnDiskCloudRulePlugin_v1":
    // payload.rules[] -> {libToMatch, context, analysisResultData}
    var p LibNotOnDiskPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "MalwareDowngradeCloudRulePlugin_v1":
    // payload.downgradeAnalysisResultTypes[] -> string enum values
    var p MalwareDowngradePayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "AnalysisResultImpactMappingCloudRulePlugin_v1":
    // payload.entries[] -> {analysisResultType, impact}
    var p ImpactMappingPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "CommonBitsJobDomainCloudRulePlugin_v1":
    // payload.commonBitsJobDomains[] -> {host}
    var p CommonBitsPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "HayabusaCloudRulePlugin_v1":
    // payload.excludeRulesLines[] -> {guid, comment}
    var p HayabusaPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

case "HostPortExclusionCloudRulePlugin_v1":
    // payload.excludedHostPorts[] -> {host, port}
    var p HostPortExclusionPayload
    json.Unmarshal(rule.RuleMetadata.Payload, &p)

default:
    // unknown plugin -- skip for forward compatibility
    continue
}
```

**Payload top-level key reference:**

| Plugin | Payload top-level key | Element shape |
|---|---|---|
| FileCorrelatedCloudRulePlugin_v1 | `rules` | `{matches, result}` |
| PowershellArgsCloudRulePlugin_v1 | `rules` | `{argToken, result}` |
| DomainCloudRulePlugin_v1 | `domains` | `{serviceProvider, domainIdentifier, domainStarPattern, newResultARData, oldResultAROverrideData, newOSAROverrideData}` |
| RemoteManagementCloudRulePlugin_v1 | `rules` | `{rmmRecord, context, matchesPath}` |
| EventsMatchingCloudRulePlugin_v1 | `rules` | `{context, matches, result}` |
| ExecutableTypeCloudRulePlugin_v1 | `rules` | `{record, context, matches}` |
| LibNotOnDiskCloudRulePlugin_v1 | `rules` | `{libToMatch, context, analysisResultData}` |
| MalwareDowngradeCloudRulePlugin_v1 | `downgradeAnalysisResultTypes` | `string` |
| AnalysisResultImpactMappingCloudRulePlugin_v1 | `entries` | `{analysisResultType, impact}` |
| CommonBitsJobDomainCloudRulePlugin_v1 | `commonBitsJobDomains` | `{host}` |
| HayabusaCloudRulePlugin_v1 | `excludeRulesLines` | `{guid, comment}` |
| HostPortExclusionCloudRulePlugin_v1 | `excludedHostPorts` | `{host, port}` |

**Step 6: Compile regex patterns**

Most match fields contain Java-syntax regular expressions. Key patterns:

- `\Q...\E` -- Java literal quoting. In Go, strip `\Q` and `\E` and use `regexp.QuoteMeta()` on the content, or convert to Go-compatible literal syntax.
- Standard regex otherwise -- Java and Go regex are largely compatible (both RE2-safe in most CloudRules patterns observed).

Pre-compile patterns at load time, not per-event evaluation.

**Step 7: Evaluate against events**

For each event from the CyberTriage agent output, iterate the compiled rules for applicable plugins and check for matches. See Section 7 for the full integration specification, including event field mapping tables and evaluation order.

**Validation**: Parse the bundled `analysis/CloudRules_rv3160001.json.gz` and verify you get 398 rules (386 enabled, 12 disabled) across 12 plugin types.

---

## 2. CloudRule Object Schema

Every element in the `"rules"` array has this structure:

| Field | Type | Required | Description |
|---|---|---|---|
| `ruleId` | string (UUID) | Yes | Unique identifier for the rule |
| `ruleVersion` | integer | Yes | Monotonically increasing version number |
| `effectiveMinCtVersion` | string (semver) | Yes | Minimum CT version required to evaluate this rule (e.g., `"3.12.0"`) |
| `plugin` | string (enum) | Yes | Plugin type that evaluates this rule -- see Section 4 |
| `enabled` | boolean | Yes | Whether the rule is active |
| `ruleMetadata` | object | Conditional | Present when the rule carries evaluation logic. **May be absent** when `enabled=false` |

### Version distribution (rv3160001)

| effectiveMinCtVersion | Count |
|---|---|
| 3.10.0 | 48 |
| 3.11.0 | 14 |
| 3.12.0 | 309 |
| 3.13.0 | 16 |
| 3.14.0 | 6 |
| 3.15.0 | 5 |

Enabled: 386. Disabled: 12 (7 DomainCloudRule, 5 FileCorrelated -- all lack `ruleMetadata`).

---

## 3. ruleMetadata Wrapper

When present, `ruleMetadata` always has this shape:

```json
{
  "type": "JSON",
  "payload": { ...plugin-specific content... }
}
```

- `type` is always `"JSON"` in the current revision.
- `payload` contains the plugin-specific rule definition. Its structure varies by `plugin` type.

Parsers MUST:
- Tolerate `ruleMetadata` being absent (skip the rule)
- Ignore `type` values they don't recognize
- Ignore unknown fields within `payload` (forward compatibility)

---

## 4. Plugin Type Specifications

### 4.1 FileCorrelatedCloudRulePlugin_v1

**Count**: 122 rules (117 enabled with metadata, 5 disabled without)  
**Purpose**: Match artifacts by file name, path, arguments, and other file/process attributes. The highest-volume plugin, covering Impacket tools, LOLBins, double extensions, printer exploits, and more.

#### Payload schema

```json
{
  "rules": [
    {
      "matches": {
        "fileName": "<regex>",
        "fileNameNoExt": "<regex>",
        "path": "<regex>",
        "extensions": ["<regex>", ...],
        "arguments": ["<regex>", ...],
        "dataTypes": ["FILE", "PROCESS_INSTANCE", ...],
        "parentProcess": "<regex>",
        "sources": "<regex>",
        "fileSignedStatus": "<regex>",
        "taskName": "<regex>",
        "comment": "<string>"
      },
      "result": {
        "analysisResultType": "<enum>",
        "score": "<NOTABLE|LIKELY_NOTABLE|UNKNOWN>",
        "justification": "<string>",
        "duplicatePolicy": "<EACH_TYPE_HIGHEST_SCORE|MERGE_SAME_TYPE>",
        "mitreAttackTypes": [
          { "id": "<ATT&CK ID>", "title": "<optional>" }
        ]
      }
    }
  ]
}
```

#### Match field semantics

| Field | Type | Occurrence | Description |
|---|---|---|---|
| `fileName` | regex | 97 rules | Match against the artifact's file name (e.g., `^\Qrar.exe\E$`) |
| `fileNameNoExt` | regex | 10 rules | Match against file name without extension |
| `path` | regex | 3 rules | Match against the full file path |
| `extensions` | regex[] | 2 rules | Match file extension(s) |
| `arguments` | regex[] | 89 rules | ALL regexes must match the process command line arguments |
| `dataTypes` | string[] | 117 rules | Artifact must be one of these data types |
| `parentProcess` | regex | 3 rules | Match against parent process path |
| `sources` | regex | 8 rules | Match against source information |
| `fileSignedStatus` | regex | 6 rules | Match against code signing status |
| `taskName` | regex | 2 rules | Match against scheduled task/service name |
| `comment` | string | 1 rule | Informational, not used for matching |

All regex fields use Java regex syntax. `\Q...\E` is used extensively for literal matching.

#### dataTypes enum values (for match filtering)

`FILE`, `WEB_ARTIFACT`, `PROCESS_INSTANCE`, `USER_ACCESSED_DATA`, `TRIGGERED_TASK`, `SERVICE`, `STARTUP_PROGRAM`

#### Result types produced (12 unique)

`IMPACKET_TOOL` (78), `BADLIST_HIT` (11), `PRINT_PROCESSOR_SIGN_STATUS` (6), `DOUBLE_FILE_EXTENSION` (6), `REMOTE_EXECUTION_SCREENCONNECT` (5), `REMOTE_EXECUTION_SMBEXEC_PY` (3), `LOL_BIN_DOWNLOAD` (2), `PRINT_PROCESSOR_BAD_NAME` (2), `PATH_TRAVERSAL` (1), `WINDOWS_DEFENDER_REGISTRY_KEY_MODIFICATION` (1), `WINDOWS_DEFENDER_FEATURE_DISABLED` (1), `WINDOWS_DEFENDER_EXCLUSION_RULE` (1)

#### Example: Impacket tool detection

```json
{
  "matches": {
    "fileName": "^\\Qpowershell.exe\\E$",
    "dataTypes": ["PROCESS_INSTANCE"],
    "arguments": [
      "[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}run\\.ps1"
    ]
  },
  "result": {
    "analysisResultType": "REMOTE_EXECUTION_SCREENCONNECT",
    "score": "LIKELY_NOTABLE",
    "justification": "Arguments contain matching pattern for ScreenConnect command script name",
    "mitreAttackTypes": [{ "id": "S0591", "title": "ConnectWise" }],
    "duplicatePolicy": "MERGE_SAME_TYPE"
  }
}
```

#### Example: LOLBin download detection

```json
{
  "matches": {
    "fileName": "^\\Qcertutil.exe\\E$",
    "dataTypes": ["PROCESS_INSTANCE"],
    "arguments": [
      "^(.*\\s)?-urlcache(\\s.*)?$",
      "^(.*\\s)?-f(\\s.*)?$"
    ]
  },
  "result": {
    "analysisResultType": "LOL_BIN_DOWNLOAD",
    "score": "LIKELY_NOTABLE",
    "justification": "Tool to download files",
    "mitreAttackTypes": [
      { "id": "T1105", "title": "Ingress Tool Transfer" },
      { "id": "S0160", "title": "certutil" }
    ]
  }
}
```

---

### 4.2 PowershellArgsCloudRulePlugin_v1

**Count**: 78 rules  
**Purpose**: Detect known-malicious PowerShell script names and download patterns in process command lines.

#### Payload schema

```json
{
  "rules": [
    {
      "argToken": "<substring>",
      "result": {
        "analysisResultType": "<enum>",
        "score": "<score>",
        "justification": "<string>",
        "mitreAttackTypes": [{ "id": "<ATT&CK ID>" }]
      }
    }
  ]
}
```

#### Match semantics

- `argToken` is a **substring match** (not regex) against the process command line arguments
- Only applicable to PowerShell process instances

#### Score distribution

NOTABLE: 71 rules. LIKELY_NOTABLE: 7 rules.

#### Result types produced (4 unique)

`POWERSHELL_SCRIPT_BAD_NAME` (67), `POWERSHELL_DOWNLOAD` (7), `WINDOWS_DEFENDER_EXCLUSION_RULE` (2), `WINDOWS_DEFENDER_FEATURE_DISABLED` (2)

#### Example: Empire script detection

```json
{
  "argToken": "Get-Keystrokes.ps1",
  "result": {
    "analysisResultType": "POWERSHELL_SCRIPT_BAD_NAME",
    "score": "NOTABLE",
    "justification": "PowerShell script name matches Empire script used for collecting sensitive data",
    "mitreAttackTypes": [{ "id": "TA0009" }]
  }
}
```

---

### 4.3 DomainCloudRulePlugin_v1

**Count**: 64 rules (57 enabled with metadata, 7 disabled without)  
**Purpose**: Flag connections to known exfiltration, file-sharing, and cloud storage domains. Uses three-tier age-based scoring.

#### Payload schema

```json
{
  "domains": [
    {
      "serviceProvider": "<string>",
      "domainIdentifier": "<domain>",
      "domainStarPattern": "<glob>",
      "newResultARData": {
        "analysisResultType": "<enum>",
        "score": "<score>",
        "justification": "<string>",
        "mitreAttackTypes": [{ "id": "<ATT&CK ID>" }]
      },
      "oldResultAROverrideData": {
        "score": "<score>",
        "justification": "<string>"
      },
      "newOSAROverrideData": {
        "score": "<score>",
        "justification": "<string>"
      }
    }
  ]
}
```

#### Three-tier scoring model

| Tier | Field | Meaning |
|---|---|---|
| New to system | `newResultARData` | Domain appeared in last 30 days on an existing system |
| Old on system | `oldResultAROverrideData` | Domain has been seen for more than 30 days |
| New OS | `newOSAROverrideData` | Domain on a system less than 30 days old |

All 57 enabled rules produce `EXTERNAL_STORAGE_DOMAIN` as the `analysisResultType`. `newResultARData` always has `score: NOTABLE`; both overrides always have `score: LIKELY_NOTABLE`.

#### Domain object fields

| Field | Type | Present | Description |
|---|---|---|---|
| `serviceProvider` | string | All | Human-readable provider name (e.g., "Dropbox", "Mega Limited") |
| `domainIdentifier` | string | All | Base domain (e.g., `"mega.nz"`) |
| `domainStarPattern` | glob | All | Glob pattern for subdomain matching (e.g., `"**.mega.nz"`) |
| `newResultARData` | object | All | Primary analysis result |
| `oldResultAROverrideData` | object | All | Override for aged domains |
| `newOSAROverrideData` | object | All | Override for new OS installs |

#### Service providers (57 unique)

Anonfiles, Apple, Atlassian, BackBlaze, Bluehost, Box, Clbin, Cloudflare, Cloudways, DigitalOcean, Discord, Dropbox, Evernote, Filebin, Filetransfer.io, Gofile, Google, Heroku, Hostinger, IBM, Ideone.com, InMotion Hosting, Ix.io, Linode, Mediafire, Mega Limited, Microsoft, Ngrok, Notion.so, Oracle, Paste.ee, Pastebin, Pastebin.pl, Pastie.org, Plesk, Rentry.co, Replit, Sendspace, Siasky, Sprunge, Telegram, Termbin, TextBin, Transfer.sh, Trello, Ufile, Uplooder, Wasabi Technologies, WeTransfer B.V, ZeroBin, pCloud

#### Example: Termbin exfiltration domain

```json
{
  "serviceProvider": "Termbin",
  "domainIdentifier": "termbin.com",
  "domainStarPattern": "**.termbin.com",
  "newResultARData": {
    "analysisResultType": "EXTERNAL_STORAGE_DOMAIN",
    "score": "NOTABLE",
    "justification": "Domain 'termbin.com' is new to the system in the last 30 days",
    "mitreAttackTypes": [{ "id": "T1567" }]
  },
  "oldResultAROverrideData": {
    "score": "LIKELY_NOTABLE",
    "justification": "Domain 'termbin.com' referenced on the system more than 30 days ago"
  },
  "newOSAROverrideData": {
    "score": "LIKELY_NOTABLE",
    "justification": "Domain 'termbin.com' is new to a new system created in the last 30 days"
  }
}
```

---

### 4.4 RemoteManagementCloudRulePlugin_v1

**Count**: 45 rules  
**Purpose**: Detect Remote Monitoring and Management (RMM) tools by file paths and names. RMM tools are commonly abused by attackers for persistence and remote access.

#### Payload schema

```json
{
  "rules": [
    {
      "rmmRecord": {
        "id": "<tool name>"
      },
      "context": {
        "operatingSystemFamilies": ["WINDOWS"]
      },
      "matchesPath": [
        {
          "fileNameNoExt": "<string>",
          "extensions": ["<string>"],
          "path": "<glob>",
          "fileName": "<string>"
        }
      ]
    }
  ]
}
```

#### matchesPath field semantics

| Field | Count | Description |
|---|---|---|
| `fileNameNoExt` | 44 | File name without extension (literal, not regex) |
| `extensions` | 44 | File extensions to match (literal) |
| `path` | 103 | Installation path patterns (glob, e.g., `/Program Files/XEOX/`) |
| `fileName` | 55 | Full file name (literal) |

Multiple `matchesPath` entries are OR'd -- any match triggers the rule.

#### RMM tools covered (45 unique)

Action1, AeroAdmin, Ammyy Admin, Any Desk, Anydesk, Atera, Chrome Remote Desktop, DWAgent, FixMeIT, GoToMyPC, ISL Online, Kaseya, Level, LiteManager, LogMeIn Client, LogMeIn Pro, LogMeIn Rescue, MobaCterm Portable Version, MobaXTerm, MSP 360, N-Able, Net Monitor for Employees, NetSupport Manager, Parallels Access, PulseWay, Pulseway, RAdmin, RealVNC, Remote Desktop Plus, Remote PC, Remote Utilities, Rust Desk, SimpleHelp, SplashTopSOS, SupRemo, Team Viewer, TeamViewer, TightVNC, Ultra Viewer, UltraVNC, Xeox, Zoho Assist

#### Example: Xeox RMM detection

```json
{
  "rmmRecord": { "id": "Xeox" },
  "context": { "operatingSystemFamilies": ["WINDOWS"] },
  "matchesPath": [
    { "fileNameNoExt": "xeox-agent_x64", "extensions": ["exe"] },
    { "path": "/Program Files/XEOX/" }
  ]
}
```

---

### 4.5 EventsMatchingCloudRulePlugin_v1

**Count**: 38 rules  
**Purpose**: Detect suspicious Windows event log entries by event ID, log source, and payload field values. Primarily targets Windows Defender tampering and malware detections.

#### Payload schema

```json
{
  "rules": [
    {
      "context": {
        "operatingSystemFamilies": ["WINDOWS"]
      },
      "matches": {
        "eventIds": [<int>, ...],
        "logFileName": "<regex>",
        "logNames": "<regex>",
        "payload": {
          "<field name>": "<regex>",
          ...
        }
      },
      "result": {
        "analysisResultType": "<enum>",
        "score": "<score>",
        "justification": "<string with optional templates>",
        "duplicatePolicy": "<policy>",
        "mitreAttackTypes": [{ "id": "<ATT&CK ID>", "title": "<optional>" }]
      }
    }
  ]
}
```

#### Match field semantics

| Field | Count | Description |
|---|---|---|
| `eventIds` | 38 | Integer array -- event MUST have one of these IDs |
| `logFileName` | 37 | Regex against the `.evtx` file name |
| `logNames` | 1 | Regex against the log channel name (alternative to `logFileName`) |
| `payload` | 28 | Key-value map where each value is a regex matched against the event's named data fields |

#### Template syntax in justifications

Some justifications contain template variables that should be resolved at evaluation time:

| Syntax | Example | Description |
|---|---|---|
| `${payload.Field}` | `${payload.Threat Name}` | Insert the value of the named event payload field |
| `${payload.Field\|regex_replace("pat","repl")}` | `${payload.New Value\|regex_replace("^HKLM\\\\...","$1")}` | Insert field value after regex transformation |
| `${timestamp}` | `${timestamp}` | Insert the event timestamp |
| `${fileName}` | `${fileName}` | Insert the matched file name |

#### Result types produced (8 unique)

`TSK_MALWARE` (9), `MALWARE_PREVIOUSLY_DETECTED` (9), `WINDOWS_DEFENDER_FEATURE_DISABLED` (6), `WIN_DEFENDER_ACTION_FAILED` (6), `WINDOWS_DEFENDER_EXCLUSION_RULE` (3), `WIN_DEFENDER_QUARANTINE_FILE_RESTORED` (3), `WIN_DEFENDER_PROTECTED_FOLDER_REMOVED` (1), `WDFILTER_SERVICE_NOT_RUNNING` (1)

#### Example: Defender exclusion rule added

```json
{
  "context": { "operatingSystemFamilies": ["WINDOWS"] },
  "matches": {
    "eventIds": [5007],
    "logFileName": "^\\QMicrosoft-Windows-Windows Defender%4Operational.evtx\\E$",
    "payload": {
      "New Value": "^HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows Defender\\\\Exclusion\\\\.*$"
    }
  },
  "result": {
    "analysisResultType": "WINDOWS_DEFENDER_EXCLUSION_RULE",
    "duplicatePolicy": "EACH_TYPE_HIGHEST_SCORE",
    "score": "NOTABLE",
    "justification": "Defender exclusion added: ${payload.New Value|regex_replace(\"^HKLM\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows Defender\\\\\\\\Exclusion\\\\\\\\([^\\\\\\\\]*).*$\", \"$1\")} ${payload.New Value|regex_replace(\"^HKLM\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows Defender\\\\\\\\Exclusion\\\\\\\\[^\\\\\\\\]*\\\\\\\\(.*?)\\\\s*=.*$\", \"$1\")}",
    "mitreAttackTypes": [{ "id": "T1562_001", "title": "Impair Defenses: Disable or Modify Tools" }]
  }
}
```

---

### 4.6 ExecutableTypeCloudRulePlugin_v1

**Count**: 18 rules  
**Purpose**: Detect data transfer and exfiltration tools with three-tier age-based scoring (new file on existing system, old file, file on new system).

#### Payload schema

```json
{
  "rules": [
    {
      "record": {
        "id": "<tool name>",
        "newResult": {
          "analysisResultType": "<enum>",
          "score": "<score>",
          "justification": "<string>",
          "mitreAttackTypes": [{ "id": "<ATT&CK ID>", "title": "<optional>" }]
        },
        "oldResultOverride": {
          "score": "<score>",
          "justification": "<string>"
        },
        "newOsOverride": {
          "score": "<score>",
          "justification": "<string>"
        }
      },
      "context": {
        "operatingSystemFamilies": ["WINDOWS"]
      },
      "matches": [
        {
          "fileName": "<string>",
          "dataTypes": ["FILE", "PROCESS_INSTANCE", ...]
        }
      ]
    }
  ]
}
```

#### Three-tier scoring model

| Tier | Field | Meaning |
|---|---|---|
| New file (<30 days) | `record.newResult` | Tool added to system in last 30 days |
| Old file (>30 days) | `record.oldResultOverride` | Tool has been on system longer than 30 days |
| New OS (<30 days) | `record.newOsOverride` | Tool on a newly provisioned system |

All 18 rules produce `DATA_TRANSFER_TOOL` with `newResult.score: NOTABLE` and both overrides at `LIKELY_NOTABLE`.

#### Tools covered (18 unique)

Box Drive, Drop Box, FileZilla, FreeFileSync, GoodSync, Google Drive, IBM Aspera Connect, IDrive, MegaSync, Pandora RC, PCloud Database, Putty SCP, Rclone, Restic, Robo-FTP, Sugar Sync, TeraCopy, WinSCP

#### Example: Rclone exfiltration tool

```json
{
  "record": {
    "id": "Rclone",
    "newResult": {
      "analysisResultType": "DATA_TRANSFER_TOOL",
      "score": "NOTABLE",
      "justification": "Added to system in last 30 days",
      "mitreAttackTypes": [{ "id": "TA0010", "title": "Exfiltration" }]
    },
    "oldResultOverride": {
      "score": "LIKELY_NOTABLE",
      "justification": "Has been on the system longer than 30 days"
    },
    "newOsOverride": {
      "score": "LIKELY_NOTABLE",
      "justification": "Added to a new system created in the last 30 days"
    }
  },
  "context": { "operatingSystemFamilies": ["WINDOWS"] },
  "matches": [
    {
      "fileName": "rclone.exe",
      "dataTypes": ["FILE", "PROCESS_INSTANCE", "USER_ACCESSED_DATA", "WEB_ARTIFACT", "CONFIG_ITEM", "SCHEDULED_TASK", "STARTUP_PROGRAM"]
    }
  ]
}
```

---

### 4.7 LibNotOnDiskCloudRulePlugin_v1

**Count**: 16 rules  
**Purpose**: Detect DLLs referenced in memory that are not present on disk -- a common indicator of DLL injection or EDR/AV presence.

#### Payload schema

```json
{
  "rules": [
    {
      "libToMatch": {
        "path": "<glob>",
        "fileNameNoExt": "<glob>",
        "extensions": ["<string>"]
      },
      "context": {
        "operatingSystemFamilies": ["WINDOWS"]
      },
      "analysisResultData": {
        "score": "<score>",
        "justification": "<string with {0} placeholder>"
      }
    }
  ]
}
```

#### Match semantics

- `libToMatch` fields use **glob patterns** (not regex): `*` matches any sequence, unlike regex `.*`
- `path` is matched against the DLL's full path (e.g., `/windows/system32/msc0ree.dll`)
- `fileNameNoExt` can contain wildcards (e.g., `sophos*`)
- `extensions` is a literal list (e.g., `["dll"]`)

#### Justification placeholder

The `{0}` in justification strings uses Java `MessageFormat` syntax. It is replaced with the matched library name at evaluation time.

#### Example: SentinelOne DLL detection

```json
{
  "libToMatch": {
    "path": "/windows/system32/msc0ree.dll"
  },
  "context": { "operatingSystemFamilies": ["WINDOWS"] },
  "analysisResultData": {
    "score": "UNKNOWN",
    "justification": "SentinelOne dll: {0}"
  }
}
```

---

### 4.8 MalwareDowngradeCloudRulePlugin_v1

**Count**: 11 rules  
**Purpose**: Downgrade the severity of certain analysis result types. When an artifact already has an `analysisResultType` listed here, its score may be reduced.

#### Payload schema

```json
{
  "downgradeAnalysisResultTypes": [
    "<analysisResultType>",
    ...
  ]
}
```

Each rule contains a simple list of `analysisResultType` strings whose severity should be downgraded.

#### Example

```json
{
  "ruleId": "175891d9-2718-49d3-9714-7924b501b26e",
  "ruleVersion": 1,
  "effectiveMinCtVersion": "3.10.0",
  "plugin": "MalwareDowngradeCloudRulePlugin_v1",
  "enabled": true,
  "ruleMetadata": {
    "type": "JSON",
    "payload": {
      "downgradeAnalysisResultTypes": ["PROCESS_PATH_SC"]
    }
  }
}
```

---

### 4.9 AnalysisResultImpactMappingCloudRulePlugin_v1

**Count**: 2 rules  
**Purpose**: Provide human-readable impact descriptions for analysis result types. This is a lookup table, not a detection rule.

#### Payload schema

```json
{
  "entries": [
    {
      "analysisResultType": "<enum>",
      "impact": "<human-readable description>"
    }
  ]
}
```

#### Current coverage

95 unique `analysisResultType` values mapped to impact descriptions. Selected examples:

| analysisResultType | impact |
|---|---|
| `ACCOUNT_COMPROMISE_DETECTED` | Attacker could be using this account. |
| `LSASS_MEM_DUMP` | Attacker may have access to password hashes for accounts on this system. |
| `RANSOM_NOTE_DETECTED` | Ransomware may have been used. Details could be in note. |
| `REMOTE_ACCESS_SOFTWARE` | Could have been used by attacker to remotely access the system |
| `DATA_TRANSFER_TOOL` | Data could have been exfiltrated using this tool. |
| `WIN_EVENT_LOG_CLEARED` | Logging could be minimized or disabled. |
| `VOLUME_SHADOW_DELETED` | Local backups of system data will not exist. |
| `POWERSHELL_SCRIPT_BAD_NAME` | Powershell could have been used to download malware |
| `IMPACKET_TOOL` | Impacket allows attackers to move laterally in a network and exploit other systems |
| `SLIVER_BINARY` | Sliver allows attackers to remotely control a host |

Full catalog in Appendix A.

---

### 4.10 CommonBitsJobDomainCloudRulePlugin_v1

**Count**: 2 rules  
**Purpose**: Maintain a list of known-benign BITS (Background Intelligent Transfer Service) job domains. Connections to these domains via BITS are expected and should not be flagged.

#### Payload schema

```json
{
  "commonBitsJobDomains": [
    { "host": "<regex>" }
  ]
}
```

#### Current entries

```
(\\w+\\.)*adobe\\.com$
(\\w+\\.)*live\\.com$
(\\w+\\.)*gvt1\\.com$
(\\w+\\.)*microsoft\\.com$
```

---

### 4.11 HayabusaCloudRulePlugin_v1

**Count**: 1 rule  
**Purpose**: Exclude specific Hayabusa/Sigma correlation rules that produce excessive false positives.

#### Payload schema

```json
{
  "excludeRulesLines": [
    {
      "guid": "<UUID>",
      "comment": "<description>"
    }
  ]
}
```

#### Current exclusions (3)

| GUID | Suppressed Rule |
|---|---|
| `49d15187-4203-4e11-8acd-8736f25b6608` | `Sec_4648_Med_ExplicitLogon_PW-Spray_Correlation.yml` |
| `0ae09af3-f30f-47c2-a31c-83e0b918eeee` | `Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml` |
| `23179f25-6fce-4827-bae1-b219deaf563e` | `Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml` |

---

### 4.12 HostPortExclusionCloudRulePlugin_v1

**Count**: 1 rule  
**Purpose**: Exclude specific host:port combinations from network anomaly detection.

#### Payload schema

```json
{
  "excludedHostPorts": [
    {
      "host": "<regex>",
      "port": <integer>
    }
  ]
}
```

#### Current exclusions

| Host pattern | Port | Purpose |
|---|---|---|
| `.*\\.eset\\.com$` | 8883 | ESET MQTT telemetry |
| `.*\\.1e100\\.net$` | 5228 | Google Cloud Messaging |

---

## 5. Shared Types and Enumerations

### 5.1 Score

Three severity levels used across all plugins:

| Value | Meaning |
|---|---|
| `NOTABLE` | High confidence indicator of suspicious/malicious activity |
| `LIKELY_NOTABLE` | Lower confidence or benign-context variant of a notable finding |
| `UNKNOWN` | Indeterminate; requires analyst review |

### 5.2 duplicatePolicy

Controls how multiple matches on the same artifact are consolidated:

| Value | Behavior |
|---|---|
| `EACH_TYPE_HIGHEST_SCORE` | Keep one result per `analysisResultType`, using the highest score |
| `MERGE_SAME_TYPE` | Merge all results of the same type into one |

### 5.3 analysisResultType

150 unique values in the current revision. See Appendix B for full catalog.

### 5.4 MITRE ATT&CK References

CloudRules reference ATT&CK IDs using this structure:

```json
{ "id": "T1562_001", "title": "Impair Defenses: Disable or Modify Tools" }
```

- `id` uses underscore separators (e.g., `T1562_001` not `T1562.001`)
- `title` is optional
- Both technique IDs (`Txxxx`), tactic IDs (`TAxxxx`), and software IDs (`Sxxxx`) are used

24 unique IDs in current revision: `S0029`, `S0160`, `S0357`, `S0591`, `T1036_007`, `T1047`, `T1053_002`, `T1070_001`, `T1105`, `T1112`, `T1547_012`, `T1560_001`, `T1562_001`, `T1562_002`, `T1567`, `T1569_002`, `TA0001`, `TA0002`, `TA0003`, `TA0004`, `TA0006`, `TA0008`, `TA0009`, `TA0010`

### 5.5 operatingSystemFamilies

Context filter for rule applicability. Only `WINDOWS` is observed in the current revision.

### 5.6 Template / Variable Syntax

Justification strings may contain interpolation variables:

| Syntax | Engine | Description |
|---|---|---|
| `{0}` | Java `MessageFormat` | Positional placeholder (LibNotOnDisk plugin) |
| `${field}` | CT template engine | Simple field substitution |
| `${payload.Key}` | CT template engine | Event payload field lookup |
| `${payload.Key\|regex_replace("pat","repl")}` | CT template engine | Field value with regex transformation |
| `${timestamp}` | CT template engine | Event timestamp |
| `${fileName}` | CT template engine | Matched file name |

---

## 6. Disabled Rules

12 rules are disabled in the current revision:

- 7 `DomainCloudRulePlugin_v1` rules (all version 22, no `ruleMetadata`)
- 5 `FileCorrelatedCloudRulePlugin_v1` rules (all version 3130006, no `ruleMetadata`)

Parsers MUST tolerate absent `ruleMetadata` on disabled rules. Disabled rules should be skipped during evaluation.

---

## 7. ct-to-timesketch Integration Specification

This section defines how to implement a CloudRules post-processing engine in the ct-to-timesketch Go pipeline, modeled on the existing Hayabusa enrichment pattern.

### 7.1 Architecture Overview

**Hayabusa pattern (existing):**

```
EVTX artifacts on disk
    --> hayabusa binary (external)
    --> hayabusa_results.jsonl
    --> mergeDetections(conv.Events)
    --> tagged Events with hayabusa_rule, hayabusa_level, mitre_attack, etc.
```

**CloudRules pattern (proposed):**

```
CloudRules_rv*.json.gz (shipped alongside binary or user-provided)
    --> loadRules() (Go-native JSON parsing)
    --> evaluateRules(conv.Events)
    --> tagged Events with cloudrules_score, cloudrules_analysis_type, mitre_attack, etc.
```

Key difference: No external binary. The CloudRules json.gz file IS the rule set. The Go code implements a native rule evaluation engine.

### 7.2 Proposed File Layout

```
internal/postprocess/
    hayabusa.go           (existing)
    cloudrules.go          (new -- rule loader + evaluator + merger)
    cloudrules_plugins.go  (new -- per-plugin evaluation functions)
```

### 7.3 Top-Level API

Following the Hayabusa pattern in `hayabusa.go`:

```go
// RunCloudRules loads the CloudRules file, evaluates all enabled rules against
// the converter's accumulated events, and tags matching events with enrichment
// metadata. Returns the number of events tagged.
func RunCloudRules(rulesPath string, conv *converter.Converter) (int, error)
```

### 7.4 CLI Integration

New flags in `cmd/ct-to-timesketch/main.go`, parallel to `--hayabusa` / `--hayabusa-path`:

```go
flag.BoolVar(&cloudrules, "cloudrules", false, "Run CyberTriage CloudRules threat detection on timeline events")
flag.StringVar(&cloudrulesPath, "cloudrules-path", "", "Path to CloudRules json.gz (auto-detected if omitted)")
```

Inserted in `main.go` after the Hayabusa block (after line ~210):

```go
if cloudrules {
    progress.Header("CLOUDRULES THREAT DETECTION")
    timer := progress.NewStepTimer("CloudRules")
    tagged, err := postprocess.RunCloudRules(cloudrulesPath, conv)
    if err != nil {
        progress.Warning(fmt.Sprintf("CloudRules: %v", err))
    } else if tagged > 0 {
        progress.Info(fmt.Sprintf("  Tagged %d events with CloudRules detections", tagged))
    }
    timer.Done()
}
```

### 7.5 CloudRules File Discovery

When `--cloudrules-path` is not specified, auto-detect in order:

1. `cloudrules/CloudRules_rv*.json.gz` relative to binary location
2. `cloudrules/CloudRules_rv*.json.gz` relative to working directory
3. `~/.ct-to-timesketch/cloudrules/CloudRules_rv*.json.gz`

If multiple revisions exist, use the highest revision number.

### 7.6 Event Field Mapping

This is the critical mapping from CloudRules match criteria to the fields already present on `converter.Event` objects (as produced by the converter methods in `internal/converter/methods.go` and `internal/converter/windows.go`).

#### FileCorrelatedCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `fileName` (regex) | `process_name`, `file_name` | Match against both |
| `fileNameNoExt` (regex) | Strip extension from `process_name` / `file_name` | |
| `path` (regex) | `process_path`, `file_path` | Match against both |
| `extensions` (regex[]) | Extract extension from `file_name` / `process_name` | |
| `arguments` (regex[]) | `command_line` | ALL regexes must match |
| `dataTypes` | `event_type` | Map: `PROCESS_INSTANCE` -> `process_execution`, `FILE` -> `file_activity`, `WEB_ARTIFACT` -> `web_artifact`, `USER_ACCESSED_DATA` -> `user_accessed_data`, `TRIGGERED_TASK` -> `scheduled_task`, `SERVICE` -> `service_activity`, `STARTUP_PROGRAM` -> `startup_item` |
| `parentProcess` (regex) | `parent_path` | |
| `fileSignedStatus` (regex) | Not currently extracted | **Gap**: needs `file_signed_status` attribute |
| `taskName` (regex) | `task_name`, `service_name` | From configItem/service converters |

#### PowershellArgsCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `argToken` (substring) | `command_line` | Only evaluate where `process_name` contains `powershell` |

#### DomainCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `domainStarPattern` (glob) | `url`, `domain`, `remote_host` | Convert glob to regex: `**.` -> `(.*\.)?` |
| Age tier selection | Compare `datetime` against system install date | Requires `imageInfo` collection time or OS install date from cache |

#### EventsMatchingCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `eventIds` (int[]) | `event_id` | Parse event's `event_id` string to int |
| `logFileName` (regex) | `channel`, `log_name` | Hayabusa channel expansion may be needed |
| `logNames` (regex) | `channel`, `log_name` | Alternative to `logFileName` |
| `payload` (map of regex) | Flattened event attributes | `ConvertWindowsEvent` and `ConvertLogLine` flatten payload fields into event attributes |

#### RemoteManagementCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `matchesPath[].fileName` | `process_name`, `file_name` | Literal match |
| `matchesPath[].fileNameNoExt` | Strip extension from above | Literal match |
| `matchesPath[].path` | `process_path`, `file_path` | Glob match |
| `matchesPath[].extensions` | Extension from file/process name | Literal match |

#### ExecutableTypeCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `matches[].fileName` | `process_name`, `file_name` | Literal match |
| `matches[].dataTypes` | `event_type` | Same mapping as FileCorrelated |
| Age tier selection | Compare artifact age | Same as DomainCloudRule |

#### LibNotOnDiskCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `libToMatch.path` (glob) | DLL paths in process/file events | Limited applicability -- mainly relevant for memory forensics |

#### MalwareDowngradeCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `downgradeAnalysisResultTypes[]` | `ct_analysis_type` | Modify existing analysis type scores |

#### AnalysisResultImpactMappingCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `entries[].analysisResultType` | `ct_analysis_type` | Add `ct_impact` field from lookup |

#### CommonBitsJobDomainCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `commonBitsJobDomains[].host` (regex) | `domain`, `remote_host` | Suppress false positives on BITS events |

#### HayabusaCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `excludeRulesLines[].guid` | `hayabusa_rule_id` | Remove Hayabusa detections. MUST run after Hayabusa. |

#### HostPortExclusionCloudRulePlugin_v1

| CloudRule match field | converter Event field(s) | Notes |
|---|---|---|
| `excludedHostPorts[].host` (regex) | `remote_host`, `domain` | Suppress network false positives |
| `excludedHostPorts[].port` (int) | `remote_port`, `port` | Combined host+port match |

### 7.7 Event Enrichment Fields

Parallel to Hayabusa's enrichment fields:

| Hayabusa field | CloudRules equivalent | Description |
|---|---|---|
| `tag` += `["hayabusa", "sigma"]` | `tag` += `["cloudrules", "cloudrules:<score>"]` | Standard tag array |
| `hayabusa_rule` | `cloudrules_rule` | Plugin name + tool/domain name |
| `hayabusa_rule_id` | `cloudrules_rule_id` | `ruleId` UUID |
| `hayabusa_level` | `cloudrules_score` | Highest score: NOTABLE > LIKELY_NOTABLE > UNKNOWN |
| `hayabusa_detection_count` | `cloudrules_detection_count` | Number of rules matched |
| `mitre_attack` | `mitre_attack` | **Merged** with existing MITRE IDs |
| -- | `cloudrules_analysis_type` | `analysisResultType` value(s) |
| -- | `cloudrules_justification` | Justification string(s) with templates resolved |
| -- | `cloudrules_impact` | Human-readable impact from AnalysisResultImpactMapping |

### 7.8 Plugin Evaluation Order

Recommended order for correctness (some plugins depend on others):

| Order | Plugin | Reason |
|---|---|---|
| 1 | AnalysisResultImpactMapping | Pre-load as lookup table for impact strings |
| 2 | MalwareDowngrade | Modifies existing analysis results before other rules run |
| 3 | HayabusaExclusion | Remove false-positive Hayabusa results before further tagging |
| 4 | HostPortExclusion | Build exclusion set for network events |
| 5 | CommonBitsJobDomain | Build exclusion set for BITS events |
| 6 | FileCorrelated | Highest volume (122 rules), broadest matching |
| 7 | PowershellArgs | 78 rules, process events only |
| 8 | Domain | 64 rules, network/web events |
| 9 | RemoteManagement | 45 rules, file/process events |
| 10 | EventsMatching | 38 rules, log/event entries |
| 11 | ExecutableType | 18 rules, file/process events |
| 12 | LibNotOnDisk | 16 rules, memory forensics DLLs |

### 7.9 CloudRules File Distribution

#### Bundled reference copy

A validated copy of `CloudRules_rv3160001.json.gz` (27,548 bytes) is included alongside this specification at:

```
analysis/CloudRules_rv3160001.json.gz
```

This is a byte-for-byte copy of the file from CyberTriageSrv, verified via gzip integrity check. It can be used directly as the `--cloudrules-path` argument for development and testing.

#### How to obtain the file

| Method | Path / Command | Notes |
|---|---|---|
| CT Server disk | `C:\Program Files\Cyber Triage\cybertriage\cloudrules\CloudRules_rv*.json.gz` | Always present; updated on CT version upgrade |
| Bundled with ct-to-timesketch | `cloudrules/CloudRules_rv*.json.gz` relative to binary | Ship latest revision with each release |
| User-provided | `--cloudrules-path <path>` | For custom/newer revisions |

#### CT Cloud Update API (reference only)

CyberTriage servers automatically check for updates via the Basis Technology cloud API. This is documented here for reference but is **not recommended** for ct-to-timesketch integration due to license dependency.

**Authentication** (two-step):

1. `POST https://rep1.cybertriage.com/_ah/api/auth/v2/generate_token`
   - Body: `{"l4j_license_id": "<id>", "ct_license_id": "<uuid>", "host_id": "<generated>", "ct_version": "<version>"}`
   - Returns: `{"token": "...", "api_key": "...", "expiration": "<epoch>"}`
   - Tokens are cached for 5 minutes

2. `GET https://rep1.cybertriage.com/_ah/api/config/v1/cloudrules/latest?ruleVersion={currentVersion}&token={token}&api_key={api_key}`
   - Returns: JSON body of updated rules (not gzipped), or empty/no-op if no updates available
   - Downloaded files are saved as `CloudRuleDownload_after{version}.json`

**Internal update flow** (decompiled from `CloudRulePluginManager`):

1. `CloudRuleUpdateService` fires periodically (every 960th invocation of its task loop)
2. Checks current DB version via `CloudRulesTable.getLatestDownloadedRuleVersion()`
3. Copies any newer installation rules to a "CloudRulesDropbox" staging directory
4. Calls the cloud API to check for rules newer than `max(dbVersion, installationVersion)`
5. Parses downloaded rules from the dropbox, inserts into PostgreSQL, validates/compiles per plugin
6. Air-gapped systems (`GlobalState.isAirGapped()`) skip the API call entirely

**Plugin registration**: 13 plugins registered via Java SPI (`META-INF/services/com.basistech.df.cybertriage.cloudrules.CloudRulePlugin`), including `AnalysisResultFilteringCloudRulePlugin` which has no rules in rv3160001 but is registered for future use.

#### Update cadence observations

- rv3160001 was shipped with CT 3.16.0 (file date: Jan 14, 2026)
- As of Mar 10, 2026, the CT Cloud API returns no newer revision
- The server has been checking approximately daily since Feb 17, 2026 -- all checks return "no updates"
- Update frequency appears to be **per major CT release** (roughly quarterly), not continuous
- A 1-2 month delay in updating the bundled CloudRules file is insignificant

#### Recommended distribution strategy for ct-to-timesketch

1. **Bundle the latest `CloudRules_rv*.json.gz`** with each ct-to-timesketch release
2. **Update the bundled file** when a new CT version ships (check the server path above)
3. **Accept `--cloudrules-path`** for operators who want to use a custom or newer file
4. **Do not implement API-based auto-update** -- the license requirement and sparse update cadence don't justify the complexity

### 7.10 Identified Gaps

Fields required by CloudRules that are not currently extracted by ct-to-timesketch converters:

| Missing Field | Required By | Priority |
|---|---|---|
| `file_signed_status` | FileCorrelated (6 rules) | Medium -- requires extracting `fileSignedStatus` from artifact |
| OS install date / system age | Domain, ExecutableType (82 rules) | High -- needed for three-tier scoring. Can derive from `imageInfo` section |
| DLL paths from memory analysis | LibNotOnDisk (16 rules) | Low -- only applicable when memory forensics data is present |
| BITS job domain | CommonBitsJobDomain (2 rules) | Low -- only applicable to BITS-specific events |

---

## Appendix A: AnalysisResultImpactMapping (Full Catalog)

95 entries mapping `analysisResultType` to human-readable `impact`:

| analysisResultType | impact |
|---|---|
| `ACCOUNT_COMPROMISE_DETECTED` | Attacker could be using this account. |
| `ACCOUNT_COMPROMISE_SUSPECTED` | Attacker may have access to this account. |
| `ACCOUNT_ENUMERATION_SUSPECTED` | Attacker tried to guess account names and passwords. Unknown if they were successful. |
| `ACCOUNT_FAKING_ATTEMPT` | Account could have been created by an attacker to blend in. |
| `ADMIN_SHARE_ARGS_REFERENCE` | User may have copied data to or from the remote host. |
| `AS_REP_ROASTING` | Attacker may have access to this account. |
| `AUDIT_POLICY_CHANGED` | Logging could be minimized or disabled. |
| `BACKUP_CATALOG_DELETED` | Local backups of system data will not exist. |
| `BITS_DEST_PATH_CONTAINS_IP` | Data could have been exfiltrated using this tool. |
| `BITS_SOURCE_PATH_CONTAINS_IP` | BITS could have been used to download malware. |
| `BRUTE_FORCE_PASSWORD` | Attacker tried to guess the password for this account. Unknown if they were successful. |
| `CONFIG_SHELL_MULTIPLE_ENTRIES` | Could have been installed by the attacker for persistence. |
| `CONFIG_USERINIT_MULTIPLE_ENTRIES` | Could have been installed by the attacker for persistence. |
| `CREDENTIAL_SPRAY` | Attacker tried to guess account names and passwords. Unknown if they were successful. |
| `DATA_TRANSFER_TOOL` | Data could have been exfiltrated using this tool. |
| `DLL_INJECTION` | Attacker could have control of this process. |
| `DOUBLE_FILE_EXTENSION` | File maybe associated with malware. |
| `ENCRYPTED_ARCHIVE` | Could contain exfiltrated data |
| `EVENT_LOG_CHANGED` | Logging could be minimized or disabled. |
| `EXE_LOCATION_ADS` | Could have been hidden by the attacker |
| `EXE_LOCATION_RECYCLE_BIN` | Could be a recently deleted executable |
| `EXE_PACKED` | Could be malware that is obfuscated to make reverse engineering harder |
| `EXE_SIGNATURE` | Could be malware if unsigned |
| `EXFIL_DOMAIN` | Data could have been exfiltrated from this host. |
| `EXTERNAL_STORAGE_DOMAIN` | Data could have been exfiltrated to this domain. |
| `FAKE_TERMSERVICE_FOUND` | Could have been installed by the attacker for persistence. |
| `FILE_MEM_DUMP` | Attacker may have access to password hashes for accounts on this system. |
| `FILE_PATH_NONSTD` | Could be a malicious version of a Windows program. |
| `FIREWALL_DISABLED` | Attacker may have installed software that needs network access. |
| `FLAWEDGRACE_BAD_ARGS` | FlawedGrace allows attackers to remotely access the system |
| `HIDDEN_SCHEDULED_TASK` | Could have been created by attacker for persistence. |
| `ICED_ID_IOCS` | IcedID is malware that provides persistence, remote control, and other capabilities. |
| `IMPACKET_TOOL` | Impacket allows attackers to move laterally in a network and exploit other systems |
| `INTERACTIVE_LOGON_ACCOUNT_FAKE` | Attacker could have used suspicious user account to log in |
| `LNK_LONG_TARGET_PATH` | File maybe associated with malware. |
| `LNK_NOT_CREATED_LOCALLY` | Could have been downloaded by the attacker. |
| `LOL_BIN_DOWNLOAD` | Could have been used to download malware |
| `LSASS_MEM_DUMP` | Attacker may have access to password hashes for accounts on this system. |
| `MALWARE_EXECUTABLE` | Scripts may have been used in the attack. |
| `OFFICE_MALWARE_SUSPECTED` | File may have been used to deliver malware. |
| `PDF_MALWARE_SUSPECTED` | File may have been used to deliver malware. |
| `POWERSHELL_SCRIPT_BAD_NAME` | Powershell could have been used to download malware |
| `PRINT_PROCESSOR_BAD_NAME` | Could have been installed by the attacker for persistence. |
| `PRINT_PROCESSOR_SIGN_STATUS` | Could have been installed by the attacker for persistence. |
| `PRIVILEGE_ESCALATION` | Attacker may have obtained admin access. |
| `PROCESS_MEM_DUMP` | Attacker may have access to password hashes for accounts on this system. |
| `PROCESS_NETWORK_DRIVE` | Could be malware that was remotely launched |
| `PROCESS_PARENT_UNEXPECT` | Could have been manually started by the attacker |
| `PROCESS_RUN_AS_SYSTEM` | Attacker may have obtained admin access. |
| `RANSOM_NOTE_DETECTED` | Ransomware may have been used. Details could be in note. |
| `RANSOM_NOTE_SUSPECTED` | Ransomware may have been used. Details could be in note. |
| `RANSOMWARE_ENCRYPTED_FILE_SUSPECTED` | Ransomware may have occurred |
| `RCLONE_ARGS_EXFIL` | Data could have been exfiltrated using this tool. |
| `RCLONE_EXFIL` | Data could have been exfiltrated using this tool. |
| `RECENTLY_DOWNLOADED` | File could have been used by the attacker. |
| `REMOTE_ACCESS_SOFTWARE` | Could have been used by attacker to remotely access the system |
| `SLIVER_BINARY` | Sliver allows attackers to remotely control a host |
| `SLIVER_PSEXEC` | Sliver allows attackers to remotely control a host |
| `SMALL_MAX_LOG_SIZE` | Logging could be minimized or disabled. |
| `STARTUP_FOLDER_PATH_NONSTD` | Could have been changed by the attacker for persistence. |
| `STARTUP_REG_ARGS_LONG` | Could be file-less malware |
| `STARTUP_REG_KEY_NAME_LONG` | Could be file-less malware |
| `STARTUP_REG_VAL_NAME_LONG` | Could be file-less malware |
| `SUSPECTED_KERBEROASTING` | Attacker may have access to this account. |
| `SUSPICIOUS_NETWORK_PROVIDER` | Could have been installed by the attacker for persistence. |
| `TGT_SERVICE_NONSTD` | Attacker may have access to this account. |
| `TRIGGERED_BITS_NOTIFY_CMD_FAILED` | BITS could be used for persistence by constantly loading a process. |
| `TRIGGERED_BITS_PATH_SOURCE_LOCAL` | BITS could have been used to download malware or obtain persistence. |
| `TSK_MALWARE` | Attacker may have used malware. Unknown if it ran. |
| `UNCOMMON_LNK_FOUND` | Could have been created by attacker to install malware or persistence. |
| `UNEXPECTED_SERVICE_EXE` | Could be malware added by the attacker. |
| `UNUSUAL_PORT` | Could be a connection to attacker's system using a non-standard protocol |
| `USED_REMOTE_ADMIN_SHARE` | User may have copied data to or from the remote host. |
| `USER_ACCOUNT_ACTIVITY_STARTED` | New user to this system that could have been used by attacker. |
| `USER_RECENTLY_CREATED` | New user account that could have been used by attacker. |
| `VOLUME_SHADOW_DELETED` | Local backups of system data will not exist. |
| `VOLUME_SHADOW_DISABLED` | Local backups of system data will not exist. |
| `VOLUME_SHADOW_STORAGE_SIZE_CHANGED` | Local backups of system data will not exist. |
| `WDFILTER_SERVICE_NOT_RUNNING` | Windows Defender could not detect attacker activity |
| `WDFILTER_SERVICE_STARTUP_NOT_AUTO` | Windows Defender could not detect attacker activity |
| `WIN_DEFENDER_ACTION_FAILED` | Unknown. Windows Defender was not able to do what it wanted. |
| `WIN_DEFENDER_FILTER_TAMPERING` | Windows Defender is not able to protect the entire system. |
| `WIN_DEFENDER_PROTECTED_FOLDER_REMOVED` | Attacker may have made changes to a folder that is normally protected. |
| `WIN_DEFENDER_QUARANTINE_FILE_RESTORED` | File was detected as malware and then restored. Unknown if it ran. |
| `WIN_DEFENDER_SERVICE_NOT_RUNNING` | Windows Defender is not able to protect the entire system. |
| `WIN_DEFENDER_SERVICE_STARTUP_NOT_AUTO` | Windows Defender is not able to protect the entire system. |
| `WIN_EVENT_LOG_CLEARED` | Logging could be minimized or disabled. |
| `WIN_EVENT_LOG_SERVICE_NOT_RUNNING` | Logging could be minimized or disabled. |
| `WIN_EVENT_LOG_SERVICE_STARTUP_NOT_AUTO` | Logging could be minimized or disabled. |
| `WIN_EVENT_LOG_SERVICE_STOPPED` | Logging could be minimized or disabled. |
| `WIN_PE_ENABLED` | Logging could be minimized or disabled. |
| `WIN_PREFETCH_SETTING_DISABLED` | Process history will be minimized. |
| `WINDOWS_DEFENDER_EXCLUSION_RULE` | Windows Defender is not monitoring this folder. |
| `WINDOWS_DEFENDER_FEATURE_DISABLED` | Windows Defender is not able to protect the entire system. |
| `WINDOWS_DEFENDER_REGISTRY_KEY_MODIFICATION` | Windows Defender is not able to protect the entire system. |

---

## Appendix B: analysisResultType Full Catalog

150 unique values observed across all CloudRules plugins (detection + impact mapping + downgrade):

```
ABUSED_WIN_BIN
ACCOUNT_COMPROMISE_DETECTED
ACCOUNT_COMPROMISE_SUSPECTED
ACCOUNT_ENUMERATION_SUSPECTED
ACCOUNT_FAKING_ATTEMPT
ADMIN_SHARE_ARGS_REFERENCE
AS_REP_ROASTING
AUDIT_POLICY_CHANGED
BACKUP_CATALOG_DELETED
BADLIST_HIT
BADLIST_PARTIAL_HIT
BITS_DEST_PATH_CONTAINS_IP
BITS_SOURCE_PATH_CONTAINS_IP
BRUTE_FORCE_PASSWORD
CONFIG_HOSTS_NONSTD
CONFIG_IMG_FILE_EXE
CONFIG_REMOTE_ACCESSIBILITY_BACKDOOR
CONFIG_SHELL_MULTIPLE_ENTRIES
CONFIG_USERINIT_MULTIPLE_ENTRIES
CONNECTION_PORT_LOC_NONSTD
CONNECTION_PORT_REM_NONSTD
CREDENTIAL_SPRAY
DATA_TRANSFER_TOOL
DLL_INJECTION
DOUBLE_FILE_EXTENSION
ENCRYPTED_ARCHIVE
EVENT_LOG_CHANGED
EXE_LOCATION_ADS
EXE_LOCATION_RECYCLE_BIN
EXE_PACKED
EXE_SIGNATURE
EXFIL_DOMAIN
EXTERNAL_STORAGE_DOMAIN
FAKE_TERMSERVICE_FOUND
FILE_MEM_DUMP
FILE_PATH_NONSTD
FILE_RULE_MATCH
FIREWALL_DISABLED
FLAWEDGRACE_BAD_ARGS
GOODLIST_HIT
HIDDEN_SCHEDULED_TASK
HOST_HIGHFLUX
ICED_ID_IOCS
IMPACKET_TOOL
INTERACTIVE_LOGON_ACCOUNT_FAKE
LNK_LONG_TARGET_PATH
LNK_NOT_CREATED_LOCALLY
LOL_BIN_DOWNLOAD
LSASS_MEM_DUMP
MALWARE_EXECUTABLE
MALWARE_PREVIOUSLY_DETECTED
MEMPROCFS_FINDEVIL
NONE
OFFICE_MALWARE_SUSPECTED
PATH_TRAVERSAL
PDF_MALWARE_SUSPECTED
PORT_NONSTD
PORT_PROCESS_PATH_NONSTD
PORT_PROCESS_UNEXPECT
POWERSHELL_DOWNLOAD
POWERSHELL_SCRIPT_BAD_NAME
PRINT_PROCESSOR_BAD_NAME
PRINT_PROCESSOR_SIGN_STATUS
PRIVILEGE_ESCALATION
PROCESS_MEM_DUMP
PROCESS_MISSING_FILE
PROCESS_MULTIPLE_INSTANCE
PROCESS_NAME_SIMILAR
PROCESS_NETWORK_DRIVE
PROCESS_PARENT_UNEXPECT
PROCESS_PATH_NONSTD
PROCESS_PATH_SC
PROCESS_PATH_UNEXPECT
PROCESS_PORT_NONSTD
PROCESS_RUN_AS_SYSTEM
PROCESS_USER_UNEXPECT
RANSOMWARE_ENCRYPTED_FILE_SUSPECTED
RANSOM_NOTE_DETECTED
RANSOM_NOTE_SUSPECTED
RCLONE_ARGS_EXFIL
RCLONE_EXFIL
RECENTLY_DOWNLOADED
REMEXEC_USERID_MISMATCH
REMOTE_ACCESS_SOFTWARE
REMOTE_EXECUTION_SCREENCONNECT
REMOTE_EXECUTION_SMBEXEC_PY
SLIVER_BINARY
SLIVER_PSEXEC
SMALL_MAX_LOG_SIZE
STARTUP_ARG_REGKEY
STARTUP_ARG_SCRIPT
STARTUP_CORE_NONMS_SIGNED
STARTUP_CORE_UNSIGNED
STARTUP_FOLDER_PATH_NONSTD
STARTUP_PATH_REGKEY
STARTUP_REG_ARGS_LONG
STARTUP_REG_KEY_NAME_LONG
STARTUP_REG_KEY_NULL
STARTUP_REG_VALUE_NULL
STARTUP_REG_VAL_NAME_LONG
SUSPECTED_KERBEROASTING
SUSPICIOUS_FILE_NAME
SUSPICIOUS_NETWORK_PROVIDER
TEMP_FOLDER_ARCHIVE
TEMP_FOLDER_SHELL_SCRIPT
TGT_SERVICE_NONSTD
TRIGGERED_BITS_NOTIFY_CMD_FAILED
TRIGGERED_BITS_PATH_SOURCE_LOCAL
TRIGGERED_CREATION_30DAYS
TRIGGERED_PATH_NONSTD
TRIGGERED_PATH_SC_UNEXPECT
TSK_HASH_HIT
TSK_IMPHASH
TSK_MALWARE
UNCOMMON_LNK_FOUND
UNEXPECTED_SERVICE_EXE
UNUSUAL_PORT
USED_REMOTE_ADMIN_SHARE
USER_ACCOUNT_ACTIVITY_STARTED
USER_LOGIN_10FAILED
USER_LOGIN_20FAILED
USER_LOGIN_NOLOCAL
USER_LOGIN_RECENT_REMOTE
USER_RECENTLY_CREATED
USER_REMEXEC_3HOSTS
VOLATILITY_MALFIND
VOLUME_SHADOW_DELETED
VOLUME_SHADOW_DISABLED
VOLUME_SHADOW_STORAGE_SIZE_CHANGED
WDFILTER_SERVICE_NOT_RUNNING
WDFILTER_SERVICE_STARTUP_NOT_AUTO
WINDOWS_DEFENDER_EXCLUSION_RULE
WINDOWS_DEFENDER_FEATURE_DISABLED
WINDOWS_DEFENDER_REGISTRY_KEY_MODIFICATION
WIN_DEFENDER_ACTION_FAILED
WIN_DEFENDER_FILTER_TAMPERING
WIN_DEFENDER_PROTECTED_FOLDER_REMOVED
WIN_DEFENDER_QUARANTINE_FILE_RESTORED
WIN_DEFENDER_SERVICE_NOT_RUNNING
WIN_DEFENDER_SERVICE_STARTUP_NOT_AUTO
WIN_EVENT_LOG_CLEARED
WIN_EVENT_LOG_SERVICE_NOT_RUNNING
WIN_EVENT_LOG_SERVICE_STARTUP_NOT_AUTO
WIN_EVENT_LOG_SERVICE_STOPPED
WIN_PE_ENABLED
WIN_PREFETCH_SETTING_DISABLED
WMI_EVENTSUB_CONS_UNEXPECT
WMI_EVENTSUB_NAMESPACE_UNEXPECT
WMI_EVENTSUB_PERS
YARA_HIT
```
