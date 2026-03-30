# ct-to-timesketch Gap Report

> **Date**: 2026-03-09  
> **Companions**: [CYBERTRIAGE_JSON_GZ_SPEC.md](CYBERTRIAGE_JSON_GZ_SPEC.md) | [CLOUDRULES_SPEC.md](CLOUDRULES_SPEC.md) | [CT_PROCESSING_PIPELINE.md](CT_PROCESSING_PIPELINE.md)  
> **Scope**: Differences between the authoritative Java data model and current Go parser implementation

---

## Priority 1 -- Critical Data Loss

### 1.1 Chunked File Content Not Reassembled

**Current behavior**: `internal/cache/index.go` skips entries with `chunkCount > 0`.

**Impact**: Large collected files (Security.evtx, NTUSER.DAT, SYSTEM hive, large prefetch, etc.) are not processed. These are often the most forensically valuable files in a capture.

**Java behavior**: `StreamingJSONParser.extractProperties()` handles `chunkData` as a streaming field -- each occurrence is Base64-decoded and appended to a temp file. When `chunkCount` is encountered, the assembled file is verified via MD5 and saved.

**Fix guidance**:
- The `chunkData` JSON key appears **multiple times** within a single JSON object. Standard Go `json.Unmarshal` into `map[string]interface{}` will silently overwrite all but the last chunk.
- Use `json.Decoder` in streaming mode or implement a custom token-level parser that captures each `chunkData` value sequentially.
- After all chunks are read, verify the reassembled file against `md5hash`.
- Chunk size is typically ~8 MB. The `chunkLength` field gives the uncompressed size hint.

### 1.2 Six Section Types Completely Missing

The base scan does not extract these section types:

| Section Type | Count in Sample | Forensic Value |
|---|---|---|
| `logonSession` | Varies | Start/end times, source/dest IP, logon type, failure reasons -- critical for lateral movement analysis |
| `triggeredTask` | Varies | Scheduled task definitions with actions, triggers, run-as user -- persistence mechanism detection |
| `webArtifact` | Low count but high value | Pre-parsed browser downloads/visits from CT (not raw browser DB) -- initial access artifacts |
| `attachedDevice` | ~27 per capture | USB device history with first/last connect times, serial numbers -- data exfiltration analysis |
| `logLine` | Varies | Parsed log file entries with structured payload -- additional event sources |
| `osConfigSetting` | ~22 per capture | Firewall state, audit policy, PATH -- environment context |

**Fix guidance**: Add scanners similar to `system_state.go` that byte-scan for these section markers and dispatch to appropriate converters.

---

## Priority 2 -- Field Mapping Errors

### 2.1 `userAccount.dateCreated` Field Name Mismatch

**Go code** (`methods.go:192`):
```go
ts := GetStr(a, "dateCreated_str")
```

**Java record** (`UserAccount.java`):
```java
String dateCreated
```

The field is `dateCreated`, not `dateCreated_str`. This means user account creation timestamps are never extracted.

### 2.2 `sourceInfo` vs `sources` Inconsistency

The Go code inconsistently accesses source information:

| Section Type | Java Field | Expected JSON Key | Go Access |
|---|---|---|---|
| `process` | `List<SourceInfo> sources` | `sources` (array) | `GetMap(a, "sourceInfo")` -- **wrong for SystemAPI processes** |
| `configItem` | `SourceInfo sourceInfo` | `sourceInfo` (object) | `GetMap(a, "sourceInfo")` -- correct |
| `dnsCacheEntry` | `SourceInfo sourceInfo` | `sourceInfo` (object) | Not accessed -- OK |

For `process` entries from `CollectionTool`, the JSON may contain a singular `sourceInfo` object (legacy format) OR a `sources` array. The Go code should check both:

```go
si := GetMap(a, "sourceInfo")
if si == nil {
    if sources := GetSlice(a, "sources"); len(sources) > 0 {
        si = sources[0]
    }
}
```

### 2.3 `windowsEvent.logName` Not Used

**Java record** has both `logName` (top-level) and `sourceInfo.eventLogName`. The Go code only checks `sourceInfo.eventLogName` via the payload, but the `logName` field is directly on the `windowsEvent` object and is more reliable.

### 2.4 `analysisResults` Never Extracted

Every major section type can carry `analysisResults` with:
- `significance`: `"LIKELY_NOTABLE"`, `"LIKELY_BENIGN"`, `"UNKNOWN"`
- `analysisResultType`: `"BADLIST_HIT"`, `"MALWARE_HIT"`, `"YARA_HIT"`, etc.
- `justification`: Human-readable reasoning
- `mitre_ids`: MITRE ATT&CK technique IDs (e.g. `T1560_001`)

These are never passed through to Timesketch events. For incident response timeline analysis, the significance/score and MITRE mappings are high-value fields.

**Recommendation**: Add standard Timesketch attributes:
```json
{
  "ct_significance": "LIKELY_NOTABLE",
  "ct_analysis_type": "BADLIST_HIT",
  "ct_justification": "Tool to archive files",
  "mitre_attack_ids": ["T1560.001"]
}
```

---

## Priority 3 -- Missing Fields on Existing Converters

### 3.1 Process Converter

| Java Field | Currently Extracted | Notes |
|---|---|---|
| `rawPathData` | No | Original path before CT normalization -- useful for exact matching |
| `elevatedAdminPriv` | No | Admin privilege indicator -- critical for privilege escalation analysis |
| `ppid` | Only in `ConvertRunningProcess` | Missing from `ConvertProcessCollection` and `ConvertProcessSystemAPI` |
| `parentPath` | No | Parent process path -- key for process tree reconstruction |
| `isService` | No | Service indicator |

### 3.2 File/MFT Converter

| Java Field | Currently Extracted | Notes |
|---|---|---|
| `fileMimeType` | No | Detected MIME type |
| `isDeleted` | No | Deletion flag -- critical for deleted file analysis |
| `isNameDel` | No | Name record deletion flag |
| `peHeaderInfo` | No | PE header data (company, product, imphash) |
| `volumeOffset` | No | Volume offset for cross-referencing |
| `metaDataAddr` | No | MFT entry number |
| `attrID` | No | NTFS attribute ID |

### 3.3 Network Connection Converter

| Java Field | Currently Extracted | Notes |
|---|---|---|
| `state` | No | Connection state (ESTABLISHED, TIME_WAIT, etc.) |
| `direction` | No | Inbound/outbound |
| `localHostName` | No | Local hostname |
| `localDomain` | No | Local domain |
| `remoteDomain` | No | Remote domain |

### 3.4 AttachedDevice (new section -- not yet implemented)

Full field list for implementation:

```go
type AttachedDevice struct {
    BusType            string `json:"busType"`
    VendorId           string `json:"vendorId"`
    ProductId          string `json:"productId"`
    SerialNum          string `json:"serialNum"`
    FirstConnectTime   int64  `json:"firstConnectTime"`
    LastConnectTime    int64  `json:"lastConnectTime"`
    LastDisconnectTime int64  `json:"lastDisconnectTime"`
    Extractor          string `json:"extractor"`
}
```

Each device has a `sources` array where `sources[].payload` contains `DeviceDesc`, `HardwareID`, `Mfg`, `Service`, `ClassGUID`.

---

## Priority 4 -- Structural Risks

### 4.1 Brace-Counting Parser

`findClosingBrace` in `mft.go` and `scanner.go` counts `{` and `}` bytes to find JSON object boundaries. This breaks on:
- Escaped braces in string values (e.g. `"args": "echo \\{test\\}"`)
- Deeply nested objects where the counter overflows the 64KB `maxObjSize` limit

**Recommendation**: Consider switching to `json.Decoder` with `Token()` for boundary detection, or at minimum track whether the cursor is inside a JSON string literal.

### 4.2 Regex-Based Cache Index

`index.go` uses regex patterns (`reCollected`, `reFilename`, `rePath`) to find collected files. Edge cases:
- Filenames containing `"Collected"` as a substring
- Paths with escaped double quotes
- Malformed JSON from interrupted collections

### 4.3 64KB Object Size Limit

`mft.go` sets `maxObjSize = 64 * 1024`. File entries with:
- Large `fileContent` (inline small files)
- Extensive `peHeaderInfo`
- Multiple `analysisResults`
- Multiple `sources` with payloads

...may exceed this limit and be silently truncated.

---

## Appendix A -- Section Type Quick Reference

For each section type, the "timestamp field" is the primary temporal anchor:

| Section | Timestamp Field | Format | Extractor Filter |
|---|---|---|---|
| `process` | `startTime` | epoch ms (number) | CollectionTool, SystemAPI |
| `configItem` | `sourceInfo.lastWriteTime` | epoch ms (string/number) | CollectionTool |
| `windowsEvent` | `time` | epoch ms (number) | SystemAPI |
| `nwConnectionDescriptor` | `time` | ISO 8601 (string) | SystemAPI |
| `dnsCacheEntry` | *(none -- use collection time)* | -- | SystemAPI |
| `arpCacheEntry` | *(none -- use collection time)* | -- | SystemAPI |
| `routingTableEntry` | *(none -- use collection time)* | -- | SystemAPI |
| `userAccessedData` | `maxLastAccessDate` | epoch ms (number) | CollectionTool |
| `logonData` | `sourceInfo.lastWriteTime` | epoch ms (string/number) | CollectionTool |
| `logonSession` | `startTime` | epoch ms (number) | SystemAPI |
| `webArtifact` | `dateAccessed` or `dateCreated` | epoch ms (string) | CyberTriage |
| `attachedDevice` | `firstConnectTime` / `lastConnectTime` | epoch ms (number) | CollectionTool |
| `triggeredTask` | `dateModified` or `dateCreated` | epoch ms (number) | CollectionTool |
| `userAccount` | `dateCreated` or `lastLoginDate` | string (various formats) | CollectionTool |
| `file` | `dateModified` / `dateCreated` / `dateAccessed` / `dateChanged` | epoch ms (number) | TSK |
| `logLine` | `time` | epoch ms (number) | varies |
| `osConfigSetting` | *(none -- use collection time)* | -- | CollectionTool |
| `error` | `errTimestamp` | ISO 8601 (string) | -- |

## Appendix B -- Recommended Go Struct Definitions

Based on the authoritative Java records, here are typed Go structs for section types not yet handled:

```go
type LogonSession struct {
    StartTime           *int64  `json:"startTime"`
    EndTime             *int64  `json:"endTime"`
    LoginStatus         string  `json:"loginStatus"`
    FailureReasons      string  `json:"failureReasons"`
    UserID              string  `json:"userID"`
    UserSID             string  `json:"userSID"`
    UserDomain          string  `json:"userDomain"`
    RemoteUser          string  `json:"remoteUser"`
    RemoteDomain        string  `json:"remoteDomain"`
    RemoteHostName      string  `json:"remoteHostName"`
    RemoteIP            string  `json:"remoteIP"`
    LocalIP             string  `json:"localIP"`
    LocalHostName       string  `json:"localHostName"`
    SourceHostName      string  `json:"sourceHostName"`
    SourceIP            string  `json:"sourceIP"`
    DestinationHostName string  `json:"destinationHostName"`
    DestinationIP       string  `json:"destinationIP"`
    Direction           string  `json:"direction"`
    LogonProcess        string  `json:"logonProcess"`
    LoginType           string  `json:"loginType"`
    Extractor           string  `json:"extractor"`
}

type TriggeredTask struct {
    SubType      string    `json:"subType"`
    Name         string    `json:"name"`
    Description  string    `json:"description"`
    State        string    `json:"state"`
    Triggers     string    `json:"triggers"`
    Actions      []Action  `json:"actions"`
    DateModified *int64    `json:"dateModified"`
    DateCreated  *int64    `json:"dateCreated"`
    Extractor    string    `json:"extractor"`
    UserID       string    `json:"userID"`
    UserDomain   string    `json:"userDomain"`
    UserSID      string    `json:"userSID"`
}

type Action struct {
    ActionType  string `json:"actionType"`
    Path        string `json:"path"`
    RawPathData string `json:"rawPathData"`
    Args        string `json:"args"`
}

type WebArtifact struct {
    UserID         string `json:"userID"`
    UserSID        string `json:"userSID"`
    UserDomain     string `json:"userDomain"`
    Type           string `json:"type"`
    VisitType      string `json:"visitType"`
    URL            string `json:"url"`
    Title          string `json:"title"`
    RefURL         string `json:"refURL"`
    RemoteHostName string `json:"remoteHostName"`
    DateAccessed   string `json:"dateAccessed"`
    DateCreated    string `json:"dateCreated"`
    VisitCount     string `json:"visitCount"`
    Path           string `json:"path"`
    RawPathData    string `json:"rawPathData"`
    Query          string `json:"query"`
    Extractor      string `json:"extractor"`
}

type LogLine struct {
    LogName   string                 `json:"logName"`
    LogPath   string                 `json:"logPath"`
    RecordID  *int64                 `json:"recordID"`
    EventID   *int64                 `json:"eventID"`
    Time      *int64                 `json:"time"`
    UserID    string                 `json:"userID"`
    UserDomain string                `json:"userDomain"`
    UserSID   string                 `json:"userSID"`
    Payload   map[string]interface{} `json:"payload"`
}

type OSConfigSetting struct {
    Setting    string     `json:"setting"`
    Group      string     `json:"group"`
    Value      string     `json:"value"`
    Extractor  string     `json:"extractor"`
    SourceInfo SourceInfo `json:"sourceInfo"`
}

type SourceInfo struct {
    SourceType       string                 `json:"sourceType"`
    SubType          string                 `json:"subType"`
    Path             string                 `json:"path"`
    KeyName          string                 `json:"keyName"`
    ValueName        string                 `json:"valueName"`
    EventLogName     string                 `json:"eventLogName"`
    EventLogRecordId string                 `json:"eventLogRecordId"`
    WmiNameSpace     string                 `json:"wmiNameSpace"`
    LastWriteTime    interface{}            `json:"lastWriteTime"`
    EventLogEventId  string                 `json:"eventLogEventId"`
    Payload          map[string]interface{} `json:"payload"`
}

type AnalysisResult struct {
    AnalysisResultType     string       `json:"analysisResultType"`
    Conclusion             string       `json:"conclusion"`
    Significance           string       `json:"significance"`
    Priority               string       `json:"priority"`
    MethodCategory         string       `json:"methodCategory"`
    Justification          string       `json:"justification"`
    Configuration          string       `json:"configuration"`
    AnalysisResultTypeDesc string       `json:"analysisResultTypeDesc"`
    MitreIDs               []MitreType  `json:"mitre_ids"`
}

type MitreType struct {
    ID string `json:"id"`
}
```
