# CyberTriage json.gz Format Specification

> **Version**: 1.0 -- Derived from `com-basistech-df-cyberTriage-core.jar` v3.16.0  
> **Date**: 2026-03-09  
> **Source of Truth**: Decompiled Java records in `com.basistech.df.cybertriage.core.ingest.datamodel`  
> **Parser**: `StreamingJSONParser.java` using Google Gson `JsonReader` (streaming)  
> **Companions**: [CLOUDRULES_SPEC.md](CLOUDRULES_SPEC.md) | [CLOUDRULES_ANALYSIS.md](CLOUDRULES_ANALYSIS.md) | [CT_PROCESSING_PIPELINE.md](CT_PROCESSING_PIPELINE.md)

---

## 1. Envelope Structure

Every `.json.gz` file is a gzip-compressed JSON document with this top-level shape:

```json
{
  "cyberTriageAgentOutput": [
    {
      "cyberTriageOutputSection": [
        { "<sectionKey>": { ...fields... } },
        { "<sectionKey>": { ...fields... } }
      ]
    },
    {
      "cyberTriageOutputSection": [
        ...phase 2 items...
      ]
    },
    {
      "cyberTriageEndOfSection": "..."
    }
  ]
}
```

### Parsing Rules

1. The root is a JSON **object** (not array).
2. The parser iterates top-level keys looking for one containing `"cyberTriageAgentOutput"`.
3. That key's value is a JSON **array**. Each element is an object.
4. Each element object has either `"cyberTriageOutputSection"` (array of section items) or `"cyberTriageEndOfSection"` (string, ignored).
5. The first `cyberTriageOutputSection` array is **Phase 1** (triage collection). The second is **Phase 2** (full disk scan). Phase 2 may be absent if `skip_full_scan` was `"yes"` in the `params` section.
6. Each section item is a JSON object with exactly **one key** -- the section type name -- whose value is the section data object.
7. The section type name is resolved via `DataTypeName.fromString()` (case-insensitive match against the enum labels).

### Unparsed Section Types

The following keys are silently skipped by the parser:
- `"severityCount"`
- `"Category Counts"`

### Unknown Section Types

Any key not matching a `DataTypeName` enum value is logged as a warning and skipped.

---

## 2. DataTypeName Enum -- Canonical JSON Key Mapping

This is the authoritative list of all recognized section keys. The **label** column is the exact JSON key string.

| Enum Constant | JSON Key (label) | Display Name | Notes |
|---|---|---|---|
| `FILE` | `file` | File | TSK filesystem entries |
| `PROCESS` | `process` | Process | Running/historical processes |
| `CONFIG_ITEM` | `configItem` | Configuration Item | Startup items, services |
| `WINDOWS_EVENT` | `windowsEvent` | Windows Event | Pre-parsed event log entries |
| `NW_CONNECTION_DESCRIPTOR` | `nwConnectionDescriptor` | Network Connection | Active connections + listeners |
| `DNS_CACHE_ENTRY` | `dnsCacheEntry` | DNS Cache Entry | Live DNS cache snapshot |
| `ARP_CACHE_ENTRY` | `arpCacheEntry` | ARP Cache Entry | Live ARP cache snapshot |
| `ROUTING_TABLE_ENTRY` | `routingTableEntry` | Routing Table Entry | Routing table snapshot |
| `USER_ACCESSED_DATA` | `userAccessedData` | User Accessed Data | MRU, recent docs, shellbags |
| `ATTACHED_DEVICE` | `attachedDevice` | Attached Device | USB/PCI device history |
| `OS_CONFIG_SETTING` | `osConfigSetting` | OS Configuration Setting | Firewall, audit, PATH, etc. |
| `LOGON_DATA` | `logonData` | Logon Data | RDP/logon history from registry |
| `HOST_INFO` | `hostInfo` | Host Info | Hostname, IPs, OS version |
| `COLLECTION_INFO` | `collectionInfo` | Collection Info | Agent version, collection params |
| `USER` | `userAccount` | User Account | SAM user accounts |
| `IMAGE_INFO` | `imageInfo` | Image Info | Disk image properties |
| `VOLUME_SYSTEM` | `volumeSystem` | Volume System | Partition table metadata |
| `VOLUME` | `volume` | Volume | Individual partitions |
| `FILE_SYSTEM` | `fileSystem` | File System | NTFS/exFAT filesystem info |
| `WEB_ARTIFACT` | `webArtifact` | Web artifact | Browser downloads/visits |
| `PARAMS` | `params` | Command Line parameters | Collection parameters |
| `PROGRESS` | `progress` | Progress | Status messages (informational) |
| `ERROR` | `error` | Error | Collection errors |
| `LOGON_SESSION` | `logonSession` | Logon Session | Detailed logon session data |
| `LOG_LINE` | `logLine` | Log File Line | Parsed log file entries |
| `ATTACHED_DEVICE_INSTANCE` | `attachedDeviceInstance` | Attached Device Instance | -- |
| `TRIGGERED_TASK` | `triggeredTask` | -- | Scheduled task definitions |
| `TARGET_INFO` | `targetInfo` | Target Info | -- |
| `INFO` | `info` | Info | -- |
| `FILE_DATA` | `fileData` | File Data | -- |
| `WATCHLIST` | `watchlistEntry` | Watchlist Entry | -- |
| `SESSION` | `session` | Session | -- |
| `CATEGORY` | `category` | Category | -- |
| `ANALYSIS_RESULT` | `analysisResult` | Analysis Result | Nested in other types |
| `EVENT` | `event` | Event | -- |
| `USER_LOGIN` | `userLoginEvent` | User Login | -- |
| `HOST` | `host` | Host | -- |
| `COMMENT` | `comment` | Comment | -- |
| `STARTUP_ITEM` | `startupItem` | Startup Item | -- |
| `SCHEDULED_TASK` | `scheduledTask` | Scheduled Task | -- |
| `REGISTRY_ENTRY` | `registryEntry` | Registry Entry | -- |
| `KNOWNFILEENTRY` | `knownFileEntry` | Known File Entry | -- |
| `MALWARE_SCAN_ERROR` | `malwareScanError` | Malware Scan Error | -- |
| `THREAT_ITEM` | `threatItem` | Threat Item | Analytics layer |
| `USER_ITEM` | `userItem` | User Item | Analytics layer |
| `DATA_INCOMPLETE_DETAIL` | `dataIncompleteDetail` | Data Incomplete Detail | -- |
| `IP_CACHE` | `ipCache` | IP Cache | -- |
| `INCIDENT` | `incident` | Incident | -- |
| `MEMBERS` | `members` | Members | -- |
| `ACTION` | `action` | Action | Nested in triggeredTask |
| `ACTIONS` | `actions` | Actions | -- |
| `SOURCE_INFO` | `sourceInfo` | Source Info | Nested in most types |
| `PE_HEADER_INFO` | `peHeaderInfo` | PE Header Info | Nested in file |
| `DYNAMIC_DNS_ENTRY` | `dynamicDNSEntry` | Dynamic DNS Entry | -- |
| `PROGRAM_RUN` | `programRunEvent` | Program Run | -- |
| `PROCESS_CONFIG` | `processConfig` | Program Run | -- |
| `PROCESS_GROUP` | `processGroup` | Process Group | -- |
| `PROCESS_INSTANCE` | `processInstance` | Process | -- |
| `FILE_CHUNK` | `fileChunk` | File Chunk | -- |
| `SOURCE_FILE` | `sourceFile` | Source File | -- |
| `LOGON_SESSION_GROUP` | `logonSessionGroup` | Logon Session Group | -- |
| `COUNTERS` | `counters` | Timing counters | -- |
| `FILE_UPDATE` | `fileUpdate` | File Update | -- |
| `LABELED_ITEMS` | `labeledItems` | Labeled Items | -- |
| `DRIVE_INFO` | `driveInfo` | Drive info | Nested in hostInfo |
| `ATTACHED_DEVICE_GROUP` | `attachedDeviceGroupd` | Attached Device Group | Note: typo in source |

---

## 3. Section Type Field Definitions

All field definitions are derived from the Java `record` declarations. Fields are serialized to JSON using the record component name as the key. Null/empty fields may be omitted from the JSON output.

### 3.1 `params`

Collection parameters. Always the first item in Phase 1.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `input` | String | string | Target path (e.g. `\\.\PHYSICALDRIVE0`) |
| `remote` | String | string | `"yes"` or `"no"` |
| `skip_full_scan` | String | string | `"yes"` or `"no"` -- controls Phase 2 |
| `skip_file_contents` | String | string | `"yes"` or `"no"` |
| `skip_source_file_contents` | String | string | `"yes"` or `"no"` |
| `request_rule_sets` | String | string | Rule set identifiers |
| `ruleset_file` | String | string | Path to custom ruleset |
| `s3_upload_config` | String | string | S3 upload configuration |
| `azure_upload_config` | String | string | Azure upload configuration |
| `cert_hash` | String | string | Certificate hash for verification |
| `encrypt_outfile` | String | string | Output encryption flag |

### 3.2 `collectionInfo`

Collection metadata. Appears near the beginning and may appear multiple times with different fields populated.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `agentVersion` | String | string | Collector version (e.g. `"3.9.0"`) |
| `typesCollected` | String | string | Comma-separated list of collected data types |
| `time` | String | string | ISO 8601 timestamp of collection start |
| `targetImageSize` | String | string | Target disk size in bytes (as string) |
| `inputPath` | String | string | Target path |
| `targetOperatingSystem` | String | string | Target OS identifier |
| `hostID` | String | string | Unique host identifier (hash-based) |

### 3.3 `hostInfo`

Host identification. May appear multiple times with different field subsets.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `localHostName` | String | string | Computer name |
| `encryptionDetected` | String | string | BitLocker/encryption status |
| `localIps` | List\<String\> | string[] | **Note**: Also appears as singular `localIp` (string) in older formats |
| `winNTVersion` | String | string | Windows NT version (e.g. `"10.0"`) |
| `winNTBuildNumber` | String | string | Build number (e.g. `"19043"`) |
| `windowsProductName` | String | string | Product name (e.g. `"Windows 10 Pro"`) |
| `osName` | String | string | Generic OS name |
| `winInstallDate` | String | string | Windows install date |
| `domainController` | String | string | Domain controller name |
| `DHCPServer` | String | string | DHCP server address |
| `systemBootTime` | String | string | Last boot time (ISO 8601) |
| `publicIp` | String | string | External IP address |
| `deviceId` | String | string | Device identifier |
| `collectionGroupId` | String | string | Group identifier |
| `imageCreationTime` | Long | number | Image creation epoch ms |
| `referenceTime` | Long | number | Reference time epoch ms |
| `driveInfos` | List\<DriveInfo\> | object[] | **Note**: Appears as `driveInfo` (array of objects) in JSON |

#### DriveInfo (nested)

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `drivePath` | String | string | Drive letter/path (e.g. `"C:\\"`) |
| `volumeName` | String | string | Volume label |
| `fileSystemName` | String | string | `"NTFS"`, `"exFAT"`, etc. |
| `driveType` | String | string | `"Fixed"`, `"Removable"`, etc. |

### 3.4 `imageInfo`

Disk image properties (TSK extractor).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `type` | String | string | Image type code |
| `sectorSize` | String | string | Sector size in bytes |
| `size` | String | string | Total size in bytes |
| `extractor` | String | string | Always `"TSK"` |
| `sourceInfo` | SourceInfo | object | Source information (singular) |

### 3.5 `volumeSystem`

Partition table metadata (TSK extractor).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `type` | String | string | Volume system type code |
| `imgOffset` | String | string | Offset into image (bytes) |
| `blockSize` | String | string | Block size |
| `extractor` | String | string | Always `"TSK"` |
| `sources` | List\<SourceInfo\> | object[] | Source information |

### 3.6 `volume`

Individual partition (TSK extractor). Multiple volumes per capture.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `addr` | String | string | Volume address/index |
| `start` | String | string | Start sector |
| `length` | String | string | Length in sectors |
| `desc` | String | string | Partition description (e.g. `"EFI system partition"`) |
| `flags` | String | string | Volume flags |
| `extractor` | String | string | Always `"TSK"` |
| `sources` | List\<SourceInfo\> | object[] | Source information |

### 3.7 `fileSystem`

Filesystem metadata (TSK extractor).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `imgOffset` | String | string | Offset into image |
| `type` | String | string | FS type code (8=NTFS, etc.) |
| `blockSize` | String | string | Block size |
| `blockCount` | String | string | Total blocks |
| `rootInum` | String | string | Root inode number |
| `firstInum` | String | string | First inode number |
| `lastInum` | String | string | Last inode number |
| `extractor` | String | string | Always `"TSK"` |
| `sources` | List\<SourceInfo\> | object[] | Source information |

### 3.8 `file`

**The most numerous section type.** Full filesystem enumeration from TSK plus collected file artifacts from CollectionTool.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `path` | String | string | Parent directory path (forward slashes) |
| `fileName` | String | string | File/directory name |
| `fileContentStatus` | String | string | See File Content Status table below |
| `metaType` | String | string | `"File"`, `"Dir"`, `"Virt"`, `"VirtDir"` |
| `volumeOffset` | Long | number | Volume offset in bytes |
| `metaDataAddr` | Long | number | MFT entry address |
| `attrID` | Long | number | NTFS attribute ID |
| `userSID` | String | string | File owner SID |
| `fileSize` | Long | number | File size in bytes |
| `dateModified` | Long | number | $STANDARD_INFORMATION modified (epoch ms) |
| `dateAccessed` | Long | number | $STANDARD_INFORMATION accessed (epoch ms) |
| `dateCreated` | Long | number | $STANDARD_INFORMATION created (epoch ms) |
| `dateChanged` | Long | number | $STANDARD_INFORMATION MFT entry changed (epoch ms) |
| `fn_dateModified` | Long | number | $FILE_NAME modified (epoch ms) |
| `fn_dateAccessed` | Long | number | $FILE_NAME accessed (epoch ms) |
| `fn_dateCreated` | Long | number | $FILE_NAME created (epoch ms) |
| `fn_dateChanged` | Long | number | $FILE_NAME changed (epoch ms) |
| `md5hash` | String | string | MD5 hash (empty string if not computed) |
| `sha1hash` | String | string | SHA-1 hash |
| `sha256hash` | String | string | SHA-256 hash |
| `fileMimeType` | String | string | Detected MIME type |
| `isDeleted` | String | string | `"true"` / `"false"` |
| `isNameDel` | String | string | `"true"` / `"false"` (name record deleted) |
| `peHeaderInfo` | Map | object | PE header fields (see below) |
| `extractor` | String | string | `"TSK"` or `"CollectionTool"` or `"CyberTriage"` |
| `analysisResults` | List\<AnalysisResult\> | object[] | Automated analysis results |
| `sources` | List\<SourceInfo\> | object[] | Source information |

#### File Content Fields (inline with file, handled specially by parser)

These fields appear within a `file` section when `fileContentStatus` is `"Collected"`:

| Field | JSON Type | Description |
|---|---|---|
| `fileContent` | string | **Base64-encoded** file content. The parser decodes and saves to the file store. |
| `fileContentLength` | number | Original file size (used for memory allocation check) |
| `chunkData` | string | Base64-encoded chunk for large files (appears multiple times) |
| `chunkLength` | number | Uncompressed length of the chunk |
| `chunkCount` | number | Total expected chunks. Appears AFTER all `chunkData` entries. |

**CRITICAL**: The parser processes `fileContent` and `chunkData`/`chunkCount` as special streaming fields -- they are NOT stored in the properties map. They are decoded, written to the file store keyed by `md5hash`, and then discarded from memory.

#### File Content Status Values

| Status | Description |
|---|---|
| `Collected` | Full content available (inline or chunked) |
| `NotAttempted` | File exists but content was not collected |
| `NotRegularFile` | Directory, symlink, or special file |
| `NotFound` | Referenced but not found on disk (likely deleted) |
| `Unresolved` | Path resolution failed |
| `HashOnly` | Only hash was computed, no content |
| `EmptyFile` | Zero-byte file |
| `SAVE_ERROR` | Parser failed to save content (set at parse time) |

#### peHeaderInfo (nested object)

Arbitrary key-value map from PE header parsing. Common fields:

| Key | Description |
|---|---|
| `companyName` | PE Company Name |
| `productName` | PE Product Name |
| `originalFileName` | PE Original File Name |
| `internalName` | PE Internal Name |
| `fileDescription` | PE File Description |
| `fileVersion` | PE File Version |
| `productVersion` | PE Product Version |
| `imphash` | Import hash |
| `Signature` | Digital signature info |

### 3.9 `process`

Process execution evidence from multiple sources (CollectionTool registry artifacts, SystemAPI live processes).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `name` | String | string | Process executable name |
| `path` | String | string | Full path (forward slashes) |
| `rawPathData` | String | string | Original path data before normalization |
| `args` | String | string | Command-line arguments |
| `observationType` | String | string | `"LocalTrace"`, `"LiveSnapshot"`, `"HistoricalLive"` |
| `pid` | String | string | Process ID (live processes only) |
| `ppid` | String | string | Parent process ID (live processes only) |
| `parentPath` | String | string | Parent process path |
| `startTime` | Long | number | Process start time (epoch ms) |
| `isService` | String | string | `"true"` / `"false"` |
| `extractor` | String | string | `"CollectionTool"`, `"SystemAPI"`, `"CyberTriage"` |
| `userID` | String | string | Username |
| `userDomain` | String | string | Domain name |
| `userSID` | String | string | User SID |
| `elevatedAdminPriv` | String | string | Elevated privilege indicator |
| `analysisResults` | List\<AnalysisResult\> | object[] | Automated analysis results |
| `sources` | List\<SourceInfo\> | object[] | Source information |

**Extractor-based interpretation:**
- `"CollectionTool"` + `observationType:"LocalTrace"` = Registry evidence (UserAssist, MRU, Prefetch, ShimCache, BAM, AppCompat)
- `"SystemAPI"` + `observationType:"LiveSnapshot"` = Currently running process
- `"SystemAPI"` + `observationType:"HistoricalLive"` = Previously running process (from event logs)

### 3.10 `configItem`

Startup programs, services, and persistent configurations.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `type` | String | string | Item type (see values below) |
| `description` | String | string | Item path/description |
| `details` | String | string | Full details including registry key path |
| `args` | String | string | Command-line arguments |
| `userID` | String | string | Associated user |
| `userSID` | String | string | User SID |
| `extractor` | String | string | `"CollectionTool"` |
| `sourceInfo` | SourceInfo | object | **Note: singular**, not array |

**configItem type values:**
- `"Startup Program"` -- Run/RunOnce registry keys
- `"Service"` -- Windows services
- `"Driver"` -- Kernel drivers
- `"Scheduled Task"` -- Basic task reference

### 3.11 `windowsEvent`

Pre-parsed Windows Event Log entries. These come from SystemAPI (live event log query) and may also come from CollectionTool for specific event sources.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `logName` | String | string | Event log name (e.g. `"Security"`) |
| `logPathName` | String | string | Full log file path |
| `eventID` | long | number | Windows Event ID |
| `path` | String | string | Source process path |
| `payload` | Map\<String, Object\> | object | Event-specific key/value data |
| `recordID` | long | number | Event log record ID |
| `time` | long | number | Event timestamp (epoch ms) |
| `userDomain` | String | string | User domain |
| `userID` | String | string | Username |
| `userSID` | String | string | User SID |
| `extractor` | String | string | `"SystemAPI"` or `"CollectionTool"` |

**Common payload fields by Event ID:**

| Event ID | Channel | Key Payload Fields |
|---|---|---|
| 4624 | Security | `LogonType`, `TargetLogonId`, `IpAddress`, `IpPort`, `WorkstationName` |
| 4625 | Security | `LogonType`, `FailureReason`, `Status`, `SubStatus` |
| 4648 | Security | `TargetServerName`, `TargetInfo` |
| 4688 | Security | `NewProcessName`, `CommandLine`, `ParentProcessName`, `TokenElevationType` |
| 4720 | Security | `TargetUserName`, `TargetDomainName`, `TargetSid` |
| 1 | Sysmon | `Image`, `CommandLine`, `ParentImage`, `Hashes`, `IntegrityLevel` |
| 3 | Sysmon | `Image`, `DestinationIp`, `DestinationPort`, `Protocol` |
| 7045 | System | `ServiceName`, `ImagePath`, `ServiceType`, `StartType` |
| 4104 | PowerShell | `ScriptBlockText`, `ScriptBlockId`, `Path` |

### 3.12 `nwConnectionDescriptor`

Network connections and listening ports (SystemAPI live snapshot).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `type` | String | string | `"listeningPort"`, `"establishedConnection"`, `"udpListener"` |  
| `localIP` | String | string | Local IP address |
| `localHostName` | String | string | Local hostname |
| `localDomain` | String | string | Local domain |
| `localPort` | String | string | Local port number |
| `remoteIP` | String | string | Remote IP address |
| `remoteHostName` | String | string | Remote hostname |
| `remoteDomain` | String | string | Remote domain |
| `remotePort` | String | string | Remote port number |
| `connectionType` | String | string | `"TCP"` or `"UDP"` |
| `time` | String | string | ISO 8601 timestamp |
| `pid` | String | string | Process ID |
| `state` | String | string | Connection state (for `ActiveConnection`) |
| `direction` | String | string | Connection direction (for `ActiveConnection`) |
| `extractor` | String | string | `"SystemAPI"` |
| `sources` | List\<SourceInfo\> | object[] | Source information |

**Note**: The Java model has separate `ActiveConnection` and `ListeningPort` records, but in the json.gz output they both appear under `nwConnectionDescriptor` differentiated by the `type` field.

### 3.13 `dnsCacheEntry`

DNS cache snapshot (SystemAPI).

| Field | JSON Type | Description |
|---|---|---|
| `remoteHostName` | string | DNS name |
| `remoteIP` | string | Resolved IP address |
| `extractor` | string | `"SystemAPI"` |
| `sourceInfo` | object | Source (typically `sourceType: "Memory"`) |

### 3.14 `userAccount`

Local and domain user accounts.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `userID` | String | string | Username |
| `userDomain` | String | string | Domain name |
| `userSID` | String | string | Full SID |
| `userHomeDir` | String | string | Profile path |
| `accountType` | String | string | `"Regular"`, `"Administrator"`, `"Service"` |
| `adminPriv` | String | string | `"none"`, `"true"`, `"domain"` |
| `dateCreated` | String | string | Account creation date (may be empty string) |
| `lastLoginDate` | String | string | Last login date (may be empty string) |
| `loginCount` | String | string | Login count (as string, may be empty) |
| `extractor` | String | string | `"CollectionTool"` |
| `sources` | List\<SourceInfo\> | object[] | Source information |

**Warning for parsers**: `dateCreated` and `lastLoginDate` are strings, NOT epoch milliseconds. They may be empty strings, ISO 8601, or other date formats. The `accountStatus` field appears in the JSON but is NOT in the Java record -- it comes from the `sourceInfo` or a CT-specific annotation.

### 3.15 `osConfigSetting`

Operating system configuration settings (firewall, audit policy, PATH, etc.).

| Field | JSON Type | Description |
|---|---|---|
| `setting` | string | Setting name (see values below) |
| `group` | string | `"SECURITY"`, `"DATA"`, `"PROCESS"` |
| `value` | string | Setting value |
| `extractor` | string | `"CollectionTool"` |
| `sourceInfo` | object | Registry source |

**Setting names include**: `PATH`, `WIN_FIREWALL_DOMAINPROFILE_ENABLED`, `WIN_FIREWALL_PUBLICPROFILE_ENABLED`, `WIN_FIREWALL_PRIVATEPROFILE_ENABLED`, `WIN_LOGON_AUDIT`, `WIN_LOGOFF_AUDIT`, `WIN_CREDENTIAL_VALIDATION_AUDIT`, and more.

### 3.16 `userAccessedData`

Files accessed by users (MRU, recent documents, shellbags).

| Field | JSON Type | Description |
|---|---|---|
| `path` | string | Accessed file/folder path |
| `maxLastAccessDate` | number | Latest access date (epoch ms) |
| `userID` | string | Username |
| `userSID` | string | User SID |
| `userDomain` | string | Domain |
| `extractor` | string | `"CollectionTool"` |
| `sourceInfo` | object | Registry source with `subType` |

**sourceInfo.subType values**: `"Windows Open/Save MRU"`, `"Recent Docs"`, `"ShellBags"`, `"TypedPaths"`, `"LastVisited MRU"`

### 3.17 `logonData`

RDP and logon history from registry (CollectionTool).

| Field | JSON Type | Description |
|---|---|---|
| `userID` | string | Local username |
| `userSID` | string | User SID |
| `remoteUser` | string | Remote username |
| `remoteDomain` | string | Remote domain |
| `remoteHostName` | string | Remote host |
| `extractor` | string | `"CollectionTool"` |
| `sourceInfo` | object | Registry key source (Terminal Server Client) |

**Note**: Timestamp comes from `sourceInfo.lastWriteTime`, not from a top-level field.

### 3.18 `logonSession`

Detailed logon session data (SystemAPI, richer than `logonData`).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `startTime` | Long | number | Session start (epoch ms) |
| `endTime` | Long | number | Session end (epoch ms) |
| `loginStatus` | String | string | Success/failure status |
| `failureReasons` | String | string | Failure reason text |
| `userID` | String | string | Username |
| `userSID` | String | string | User SID |
| `userDomain` | String | string | Domain |
| `remoteUser` | String | string | Remote username |
| `remoteDomain` | String | string | Remote domain |
| `remoteHostName` | String | string | Remote hostname |
| `remoteIP` | String | string | Remote IP |
| `localIP` | String | string | Local IP |
| `localHostName` | String | string | Local hostname |
| `sourceHostName` | String | string | Source hostname |
| `sourceIP` | String | string | Source IP |
| `destinationHostName` | String | string | Destination hostname |
| `destinationIP` | String | string | Destination IP |
| `direction` | String | string | `"inbound"` / `"outbound"` |
| `logonProcess` | String | string | Logon process (e.g. `"NtLmSsp"`) |
| `loginType` | String | string | Logon type number |
| `analysisResults` | List | object[] | Analysis results |
| `extractor` | String | string | `"SystemAPI"` |
| `sources` | List | object[] | Source information |

### 3.19 `webArtifact`

Browser artifacts (downloads, page visits).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `userID` | String | string | Username |
| `userSID` | String | string | User SID |
| `userDomain` | String | string | Domain |
| `type` | String | string | `"DOWNLOAD"`, `"PAGE_VISIT"` |
| `visitType` | String | string | Visit type |
| `url` | String | string | Full URL |
| `title` | String | string | Page/download title |
| `refURL` | String | string | Referrer URL |
| `remoteHostName` | String | string | Remote hostname |
| `dateAccessed` | String | string | Access date (epoch ms as string) |
| `dateCreated` | String | string | Created date (epoch ms as string) |
| `visitCount` | String | string | Number of visits |
| `path` | String | string | Local file path (downloads) |
| `rawPathData` | String | string | Raw path before normalization |
| `query` | String | string | URL query string |
| `extractor` | String | string | `"CyberTriage"` |
| `sources` | List | object[] | Source (browser history DB path) |

### 3.20 `attachedDevice`

USB and other attached device history.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `busType` | String | string | `"USB"`, `"PCI"`, etc. |
| `vendorId` | String | string | Vendor identifier |
| `productId` | String | string | Product identifier |
| `serialNum` | String | string | Serial number |
| `firstConnectTime` | Long | number | First connection (epoch ms) |
| `lastConnectTime` | Long | number | Last connection (epoch ms) |
| `lastDisconnectTime` | Long | number | Last disconnection (epoch ms) |
| `extractor` | String | string | `"CollectionTool"` |
| `sources` | List\<SourceInfo\> | object[] | Registry sources (multiple, with `payload`) |

**Note**: `sources` may contain rich payload data including `DeviceDesc`, `HardwareID`, `Mfg`, `Service`, `ClassGUID`.

### 3.21 `triggeredTask`

Scheduled task definitions.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `subType` | String | string | Task sub-type |
| `name` | String | string | Task name |
| `description` | String | string | Task description |
| `state` | String | string | Task state |
| `triggers` | String | string | Trigger configuration |
| `actions` | List\<Action\> | object[] | Task actions (see below) |
| `dateModified` | Long | number | Last modified (epoch ms) |
| `dateCreated` | Long | number | Created (epoch ms) |
| `extractor` | String | string | `"CollectionTool"` |
| `userID` | String | string | Run-as user |
| `userDomain` | String | string | Domain |
| `userSID` | String | string | User SID |
| `analysisResults` | List | object[] | Analysis results |
| `sources` | List | object[] | Source information |

#### Action (nested)

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `actionType` | String | string | Action type |
| `path` | String | string | Executable path |
| `rawPathData` | String | string | Raw path data |
| `args` | String | string | Arguments |

### 3.22 `logLine`

Parsed log file entries.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `logName` | String | string | Log name |
| `logPath` | String | string | Log file path |
| `recordID` | Long | number | Record identifier |
| `eventID` | Long | number | Event identifier |
| `time` | Long | number | Event time (epoch ms) |
| `userID` | String | string | Username |
| `userDomain` | String | string | Domain |
| `userSID` | String | string | User SID |
| `analysisResults` | List | object[] | Analysis results |
| `payload` | Map | object | Arbitrary key-value data |

### 3.23 `error`

Collection errors.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `errTimestamp` | String | string | ISO 8601 timestamp |
| `errSeverity` | ERR_SEVERITY | string | `"MINOR"` or `"WARNING"` |
| `message` | String | string | Error message |
| `details` | String | string | Error details |

### 3.24 `progress`

Status/progress messages (informational, no forensic value).

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `message` | String | string | Progress message text |
| `controlMessage` | String | string | Control directive |
| `logName` | String | string | Log name context |
| `logPathName` | String | string | Log path context |

---

## 4. Shared/Nested Types

### 4.1 SourceInfo

Appears as `sourceInfo` (singular object) or `sources` (array of objects) depending on the parent type.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `sourceType` | String | string | `"RegistryKey"`, `"File"`, `"Memory"`, `"FileSystem"`, `"EventLog"`, `"WMI"` |
| `subType` | String | string | Sub-category (e.g. `"Run MRU"`, `"UserAssist"`, `"ShellBags"`, `"ShimCache"`, `"BAM"`) |
| `path` | String | string | Source path (registry hive, file path, etc.) |
| `keyName` | String | string | Registry key path |
| `valueName` | String | string | Registry value name |
| `eventLogName` | String | string | Event log channel name |
| `eventLogRecordId` | String | string | Record ID within event log |
| `wmiNameSpace` | String | string | WMI namespace |
| `lastWriteTime` | String | string | Last write time (epoch ms as string or number) |
| `eventLogEventId` | String | string | Event ID within source |
| `payload` | Map | object | Additional source-specific data |

**IMPORTANT**: The `sourceInfo` / `sources` distinction is inconsistent across types:
- `configItem`, `osConfigSetting`, `imageInfo` use singular `sourceInfo` (object)
- `process`, `file`, `attachedDevice`, `logonSession`, `webArtifact`, `volume`, `volumeSystem`, `fileSystem`, `userAccount` use `sources` (array)
- `dnsCacheEntry` uses singular `sourceInfo` (object)

#### SourceType Values

| `sourceType` value | Origin | Description |
|---|---|---|
| `"RegistryKey"` | Collector agent | Registry hive artifact |
| `"File"` | Collector agent / TSK | File system artifact |
| `"Memory"` | Volatility / MemProcFS | Memory forensics artifact |
| `"FileSystem"` | TSK extractor | File system metadata |
| `"EventLog"` | EVTX parser | Windows Event Log entry |
| `"WMI"` | WMI persistence collector | WMI event subscription |
| `"ONLINE_API"` | MDE integration | Microsoft Defender for Endpoint telemetry (Graph API or CSV import) |

#### ONLINE_API Source Type (MDE Integration)

When `sourceType` is `"ONLINE_API"`, the artifact originated from the Microsoft Defender for Endpoint integration (see [CT_PROCESSING_PIPELINE.md](CT_PROCESSING_PIPELINE.md) Section 10). The `subType` field contains a `DefenderSubType` enum value that identifies the exact MDE data source:

**API-sourced subtypes** (`DEFENDER_HUNT_*`):

| `subType` value | MDE source |
|---|---|
| `"Windows Defender Hunt"` | Generic hunt query fallback |
| `"Windows Defender Hunt - ProcessCreated"` | `DeviceProcessEvents` |
| `"Windows Defender Hunt - LogonSuccess"` | `DeviceLogonEvents` (success) |
| `"Windows Defender Hunt - LogonFailed"` | `DeviceLogonEvents` (failure) |
| `"Windows Defender Hunt - LogonAttempted"` | `DeviceLogonEvents` (attempt) |
| `"Windows Defender Hunt - ServiceInstalled"` | `DeviceEvents` (ServiceInstalled) |
| `"Windows Defender Hunt - ConnectionSuccess"` | `DeviceNetworkEvents` (outbound) |
| `"Windows Defender Hunt - InboundConnectionAccepted"` | `DeviceNetworkEvents` (inbound) |
| `"Windows Defender Hunt - ListeningConnectionCreated"` | `DeviceNetworkEvents` (listen) |
| `"Windows Defender Hunt - ListeningSocketCreated"` | `DeviceNetworkEvents` (socket) |
| `"Windows Defender Hunt - FileCreated"` | `DeviceFileEvents` (create) |
| `"Windows Defender Hunt - FileModified"` | `DeviceFileEvents` (modify) |
| `"Windows Defender Hunt - FileDeleted"` | `DeviceFileEvents` (delete) |
| `"Windows Defender Hunt - ScheduledTaskCreated"` | `DeviceEvents` (task) |

**CSV-sourced subtypes** (`DEFENDER_TIMELINE_*`):

| `subType` value | MDE source |
|---|---|
| `"Windows Defender Timeline - ProcessCreated"` | Timeline CSV process row |
| `"Windows Defender Timeline - LogonSuccess"` | Timeline CSV logon row (success) |
| `"Windows Defender Timeline - LogonFailed"` | Timeline CSV logon row (failure) |
| `"Windows Defender Timeline - LogonAttempted"` | Timeline CSV logon row (attempt) |
| `"Windows Defender Timeline - ServiceInstalled"` | Timeline CSV service row |
| `"Windows Defender Timeline - ConnectionSuccess"` | Timeline CSV connection row |
| `"Windows Defender Timeline - InboundConnectionAccepted"` | Timeline CSV inbound row |
| `"Windows Defender Timeline - ListeningConnectionCreated"` | Timeline CSV listen row |
| `"Windows Defender Timeline - ListeningSocketCreated"` | Timeline CSV socket row |
| `"Windows Defender Timeline - FileCreated"` | Timeline CSV file row (create) |
| `"Windows Defender Timeline - FileModified"` | Timeline CSV file row (modify) |
| `"Windows Defender Timeline - FileDeleted"` | Timeline CSV file row (delete) |
| `"Windows Defender Timeline - ScheduledTaskCreated"` | Timeline CSV task row |

**Parser note**: MDE-sourced captures set `params.input` to `"Win Defender EDR Hunting Queries"` (API) or `"Win Defender EDR csv"` (CSV) and `skip_full_scan: "yes"`. The `CollectionInfo.typesCollected` field is `"ENUM_FS, PROCESSES, USERS, USER_LOGINS, SCHEDULED_TASKS, NETWORK, WEB, ALL_FILES"` for both paths. The `extractor` field on individual artifacts within MDE captures may differ from collector-generated captures.

### 4.2 AnalysisResult

Automated analysis findings attached to artifacts.

| Field | Java Type | JSON Type | Description |
|---|---|---|---|
| `analysisResultType` | String | string | `"BADLIST_HIT"`, `"GOODLIST_HIT"`, `"MALWARE_HIT"`, `"YARA_HIT"`, etc. |
| `conclusion` | String | string | Conclusion text |
| `significance` | String | string | `"LIKELY_NOTABLE"`, `"LIKELY_BENIGN"`, `"UNKNOWN"` |
| `priority` | String | string | Priority value |
| `methodCategory` | String | string | Analysis method category |
| `justification` | String | string | Human-readable justification |
| `configuration` | String | string | Rule/configuration reference |
| `analysisResultTypeDesc` | String | string | Type description |
| `mitre_ids` | List\<CTMITREType\> | object[] | MITRE ATT&CK technique IDs |

#### CTMITREType (nested)

| Field | JSON Type | Description |
|---|---|---|
| `id` | string | MITRE technique ID (e.g. `"T1560_001"`) |

---

## 5. Extractor Types

The `extractor` field on each section identifies the data source:

| Extractor | Description | Produces |
|---|---|---|
| `TSK` | The Sleuth Kit filesystem parser | `file`, `volume`, `volumeSystem`, `fileSystem`, `imageInfo` |
| `CollectionTool` | Registry/artifact parser | `process`, `configItem`, `userAccount`, `logonData`, `userAccessedData`, `osConfigSetting`, `attachedDevice`, `triggeredTask` |
| `SystemAPI` | Live system query | `process`, `windowsEvent`, `nwConnectionDescriptor`, `dnsCacheEntry`, `arpCacheEntry`, `routingTableEntry`, `logonSession` |
| `CyberTriage` | CT internal analysis | `webArtifact`, `file` (derived artifacts), `process` (derived) |
| `Volatility` | Memory forensics (Volatility 2.6) | All types with `sourceType: "Memory"` |

**MDE-sourced captures**: When `params.input` is `"Win Defender EDR Hunting Queries"` or `"Win Defender EDR csv"`, the data originates from the Microsoft Defender for Endpoint integration rather than a local collector agent. The artifact structure is identical to collector-generated data, but `sourceInfo.sourceType` will be `"ONLINE_API"` with a `DefenderSubType` subtype (see Section 4.1 above). No file content or EVTX logs are collected via MDE -- only metadata and telemetry.

---

## 6. File Content and Chunking

### Inline File Content

For files with `fileContentStatus: "Collected"` and small size, the file content appears inline:

```json
{
  "file": {
    "path": "/windows/system32/config",
    "fileName": "SAM",
    "fileContentStatus": "Collected",
    "md5hash": "abc123...",
    "fileSize": 262144,
    "fileContentLength": 262144,
    "fileContent": "<base64-encoded-bytes>",
    ...other fields...
  }
}
```

The `fileContent` value is **standard Base64** of the raw file bytes.

### Chunked File Content

Large files are split into chunks within the same JSON object:

```json
{
  "file": {
    "path": "/windows/system32/winevt/logs",
    "fileName": "Security.evtx",
    "fileContentStatus": "Collected",
    "md5hash": "def456...",
    "fileSize": 20971520,
    "chunkLength": 8388608,
    "chunkData": "<base64-chunk-1>",
    "chunkData": "<base64-chunk-2>",
    "chunkData": "<base64-chunk-3>",
    "chunkCount": 3,
    ...other fields...
  }
}
```

**CRITICAL parsing notes:**
1. The `chunkData` key appears **multiple times** in the same JSON object. Standard JSON parsers that build a map will only keep the last one. The `StreamingJSONParser` uses Gson's streaming API to process each `chunkData` as it is encountered.
2. The chunks are Base64-encoded raw bytes.
3. The `chunkCount` field appears AFTER all `chunkData` entries and triggers the final assembly/verification.
4. The parser computes an MD5 hash of the reassembled content using a `Md5HashComputeStream` + `InflaterOutputStream` chain to verify against `md5hash`.
5. Chunk size is typically 8 MB (`chunkLength`).

### File Store Layout

Saved files are keyed by MD5 hash in a hex-bucketed directory structure:
```
<datadir>/files/CyberTriage/<first-2-hex-chars>/<md5hash>
```

---

## 7. Timestamp Formats

Timestamps in the json.gz format use multiple representations:

| Format | Used By | Example |
|---|---|---|
| Epoch milliseconds (number) | `file.dateModified`, `process.startTime`, `windowsEvent.time`, `attachedDevice.firstConnectTime`, `logonSession.startTime` | `1761886044708` |
| Epoch milliseconds (string) | `sourceInfo.lastWriteTime`, `webArtifact.dateAccessed` | `"1758280710000"` |
| ISO 8601 (string) | `collectionInfo.time`, `error.errTimestamp`, `nwConnectionDescriptor.time`, `hostInfo.systemBootTime` | `"2025-11-12T10:32:32.000000000Z"` |
| Empty string | `userAccount.dateCreated`, `userAccount.lastLoginDate` | `""` |

**Parser guidance**: Always check both number and string types for timestamp fields. Use defensive parsing that handles both epoch ms and ISO 8601.

---

## 8. CloudRules json.gz Format

> **Full specification**: See [CLOUDRULES_SPEC.md](CLOUDRULES_SPEC.md) for the complete CloudRules format specification, including all 12 plugin type schemas, match semantics, enumeration catalogs, and the ct-to-timesketch post-processing integration spec.

CloudRules are a separate json.gz format used for threat intelligence rules distributed to CT instances. The file contains 398 rules across 12 plugin types that perform pattern matching against artifacts to produce `analysisResult` enrichments.

**Summary**: 12 plugin types, 150 unique `analysisResultType` values, 24 MITRE ATT&CK IDs, 3 score levels, template variable syntax for dynamic justification strings.

**Plugin types** (rule count in rv3160001):

- `FileCorrelatedCloudRulePlugin_v1` (122) -- file/process name, path, arguments regex matching
- `PowershellArgsCloudRulePlugin_v1` (78) -- PowerShell command line token detection
- `DomainCloudRulePlugin_v1` (64) -- exfiltration/cloud storage domain flagging
- `RemoteManagementCloudRulePlugin_v1` (45) -- RMM tool detection
- `EventsMatchingCloudRulePlugin_v1` (38) -- Windows event log pattern matching
- `ExecutableTypeCloudRulePlugin_v1` (18) -- data transfer tool detection
- `LibNotOnDiskCloudRulePlugin_v1` (16) -- DLL injection / EDR presence detection
- `MalwareDowngradeCloudRulePlugin_v1` (11) -- severity downgrade for false positives
- `AnalysisResultImpactMappingCloudRulePlugin_v1` (2) -- human-readable impact descriptions
- `CommonBitsJobDomainCloudRulePlugin_v1` (2) -- benign BITS domain exclusions
- `HayabusaCloudRulePlugin_v1` (1) -- Hayabusa/Sigma rule exclusions
- `HostPortExclusionCloudRulePlugin_v1` (1) -- network false positive exclusions

---

## 9. Gap Analysis: ct-to-timesketch Go Parsers

### Section Types NOT Currently Handled by Go

| Section Type | In Java | In Go | Impact |
|---|---|---|---|
| `logonSession` | Full record | Missing | Detailed logon sessions (start/end time, source/dest IP, logon type) lost |
| `triggeredTask` | Full record with actions | Missing | Scheduled task definitions not extracted |
| `webArtifact` | Full record | Missing from base scan | Browser downloads/visits from CT pre-parsing not extracted |
| `logLine` | Full record | Missing | Parsed log file entries not extracted |
| `attachedDevice` | Full record with rich sources | Missing | USB device history not extracted from base scan |
| `osConfigSetting` | Full record | Missing | Security configuration state not extracted |
| `error` | Full record | Missing | Collection error context lost |
| `hostInfo` | Full record | Partial (hostname only) | OS version, IPs, drive info not fully captured |
| `collectionInfo` | Full record | Partial (hostname extraction) | Agent version, collection params not preserved |
| `arpCacheEntry` | Supported | Implemented | OK |
| `routingTableEntry` | Supported | Implemented | OK |
| `accountStatus` (on userAccount) | Not in Java record | Go reads it | Field exists in JSON but not in Java record -- likely from CT annotation |

### File Content / Chunking Gaps

| Issue | Impact |
|---|---|
| Chunked files (`chunkCount > 0`) are **skipped** in cache index | Large EVTX logs, registry hives, and other collected files exceeding chunk threshold are not processed |
| No `chunkData` reassembly logic | Missing files include large Security.evtx, NTUSER.DAT, and other critical forensic sources |
| `fileContent` only -- no chunk concatenation | Approximately 5-15% of collected files may be lost depending on capture |

### Field Mapping Gaps

| Go Converter | Java Field | Go Field | Issue |
|---|---|---|---|
| `ConvertProcessCollection` | `sourceInfo` (singular) | `GetMap(a, "sourceInfo")` | Correct for CollectionTool, but `process` Java record has `sources` (List) |
| `ConvertConfigItem` | `sourceInfo` (singular) | `GetMap(a, "sourceInfo")` | OK -- configItem does use singular `sourceInfo` |
| `ConvertUserAccount` | `dateCreated` | `dateCreated_str` | **Field name mismatch** -- Java field is `dateCreated` not `dateCreated_str` |
| `ConvertFileMFT` | `fileContentLength` | Not extracted | File content length not passed to timeline |
| `ConvertWindowsEvent` | `logName` | Not used | Go reads `sourceInfo.eventLogName` but Java also has top-level `logName` and `logPathName` |
| All converters | `analysisResults` | Not extracted | MITRE ATT&CK IDs, significance scores, and automated analysis never extracted |
| All converters | `rawPathData` | Not extracted | Original path data before CT normalization |
| All converters | `elevatedAdminPriv` | Not extracted | Admin privilege elevation indicator on processes |

### Structural Parsing Risks

| Risk | Description |
|---|---|
| Brace counting | MFT/scanner use `findClosingBrace` byte scanning rather than JSON parsing. Escaped braces or deeply nested payloads could cause miscounts. |
| Repeated JSON keys | `chunkData` appears multiple times in one object. Standard `json.Unmarshal` into `map[string]interface{}` loses all but the last chunk. |
| Object size limit | MFT extractor caps objects at 64KB (`maxObjSize`). Large file entries with inline content or PE header info may be truncated. |
| Regex-based field extraction | Cache index uses regex for `"Collected"`, `"fileName"`, etc. Edge cases with escaped quotes or unusual formatting could cause misses. |

---

## 10. PostgreSQL Database Cross-Reference

For parsers that need to understand how json.gz data maps to the server-side database:

### Incident Database (per-case)

| JSON Section | Primary DB Table | Key Columns |
|---|---|---|
| `file` | `tsk_files` | `obj_id`, `name`, `parent_path`, `size`, `md5`, `sha1`, `sha256` |
| `process` | `ct_process_instances` | (CT-specific) |
| `windowsEvent` | `ct_windows_events` | (CT-specific) |
| `logonSession` | `ct_logon_sessions` | (CT-specific) |
| `userAccessedData` | `ct_user_accessed_data` | (CT-specific) |
| `attachedDevice` | `ct_device_instances` | (CT-specific) |
| File content | `tsk_files` + file store | `has_layout`, content in file store by MD5 |
| AnalysisResult | `tsk_analysis_results` / `tsk_aggregate_score` | Linked via `obj_id` |
| SourceInfo | `ct_source_info` / `ct_source_file_info` | Linked to parent items |

### Analytics Database (cross-incident)

| JSON Section | Analytics Table | Purpose |
|---|---|---|
| `process` | `ct_process`, `ct_process_path_args` | Process path/args correlation |
| `configItem` | `ct_startupitem`, `ct_startupitem_path_args` | Startup item correlation |
| `file` | `ct_file_md5`, `ct_file_path` | File hash/path correlation |
| `nwConnectionDescriptor` | `ct_active_connection_v2`, `ct_listening_port_v2` | Network correlation |
| `osConfigSetting` | `ct_os_config_setting` | Configuration comparison |
| `webArtifact` | `ct_web_artifact` | Web artifact correlation |
| `attachedDevice` | `ct_attached_device` | Device correlation |

Full DDL available in the `schema/` directory of this analysis workspace.
