# CyberTriage JSON.GZ Export Format

## Overview

CyberTriage exports forensic captures as compressed JSON files (`.json.gz`). The format contains:
- File system metadata from TSK (The Sleuth Kit)
- File content (base64 + zlib encoded)
- Artifacts from multiple extractors

## Extractors

| Extractor | Description | Sections | Purpose |
|-----------|-------------|----------|---------|
| **TSK** | The Sleuth Kit - filesystem parsing | 995,940 | Complete filesystem metadata + targeted file content |
| **CollectionTool** | Parsed registry/file artifacts | 5,373 | Pre-parsed forensic data (UserAssist, MRU, etc.) |
| **SystemAPI** | Live memory/event log collection | 4,544 | Current state (processes, network, DNS cache) |

**Total artifacts in sample capture**: ~1,005,857

### TSK (The Sleuth Kit)
Parses the NTFS filesystem from a disk image. Provides complete filesystem enumeration with selective file content collection.

#### Section Types

| Section | Count | Description |
|---------|-------|-------------|
| `file` | 995,930 | All files and directories with full metadata |
| `volume` | 4 | Disk partition information |
| `fileSystem` | 4 | Filesystem type info (NTFS/exFAT) |
| `volumeSystem` | 1 | Volume system metadata |
| `imageInfo` | 1 | Disk image properties |

#### File Content Status

| Status | Count | Description |
|--------|-------|-------------|
| `NotAttempted` | 775,683 | File exists, content not collected |
| `NotRegularFile` | 213,737 | Directories and special files |
| `Collected` | 3,225 | **Full content extracted (base64+zlib)** |
| `NotFound` | 1,584 | Referenced but not found (deleted?) |
| `Unresolved` | 96 | Path resolution failed |
| `HashOnly` | 13 | Only hash computed |
| `EmptyFile` | 4 | Zero-byte files |

#### File Collection Logic

TSK collects ~3,200 files (0.32% of filesystem) using two mechanisms:

**1. Targeted Forensic Artifacts (`isSourceFile=true`)**
~570 files that CyberTriage specifically targets:

| Category | Examples |
|----------|----------|
| Registry Hives | SOFTWARE, SYSTEM, SAM, SECURITY, NTUSER.DAT, UsrClass.dat |
| Registry Logs | *.LOG1, *.LOG2, *.blf, *.regtrans-ms |
| Event Logs | *.evtx files |
| Prefetch | *.pf files |
| Scheduled Tasks | /Windows/Tasks/*.job |
| Browser Data | WebCacheV01.dat, cookies |

**2. Referenced Files (no `isSourceFile` flag)**
~2,500+ files collected because they were found in other artifacts:

| Trigger Artifact | What Gets Collected |
|-----------------|---------------------|
| UserAssist (process) | Executables that were run by users |
| Startup Items (configItem) | Executables in Run keys, services |
| Scheduled Tasks | Task executable binaries |
| Running Processes | Process binaries |
| LNK Shortcuts | Shortcut target files |
| Loaded Modules | DLLs loaded by processes |

**Example**: `slack.exe` is collected because it appears in UserAssist (program execution history). `wow64cpu.dll` is collected because it's referenced in configItem (startup/services).

#### File Metadata Fields

Every file entry includes full NTFS metadata:
```json
{
  "path": "/windows/system32/config/",
  "fileName": "SOFTWARE",
  "fileContentStatus": "Collected",
  "isSourceFile": "true",
  "metaType": "Dir|File",
  "volumeOffset": 105906176,
  "metaDataAddr": 312299,
  "userSID": "S-1-5-32-544",
  "fileSize": 134742016,
  
  "dateModified": 1675532649373,
  "dateAccessed": 1675532649373,
  "dateCreated": 1575709424555,
  "dateChanged": 1675532633143,
  
  "fn_dateModified": 1675532633111,
  "fn_dateAccessed": 1675532633111,
  "fn_dateCreated": 1575709424555,
  "fn_dateChanged": 1625832029577,
  
  "md5hash": "6978121de2e9d23fb56f5a3ce532c373",
  "sha256hash": "303edfd44bc62a723ca8c3e3d3dfae9af9a82d7a01124696a6f371278ad5d57c",
  "sha1hash": "014507ca746a4ba1c6d24d0594adaf7c7f54af98",
  "fileContentLength": 134742016,
  "fileContent": "eJz...(base64+zlib)..."
}
```

**Dual Timestamp Sets** (for timestomping detection):
- `dateModified/dateAccessed/dateCreated/dateChanged` - Standard Information attribute (easily modified)
- `fn_dateModified/fn_dateAccessed/fn_dateCreated/fn_dateChanged` - $FILE_NAME attribute (harder to fake)

### CollectionTool
Collects parsed artifacts from registry and files. These are pre-parsed forensic artifacts ready for timeline analysis.

| Section Type | Description | Source | Timestamp Field |
|-------------|-------------|--------|-----------------|
| `configItem` | Startup programs, services | Registry (Run keys) | `lastWriteTime` |
| `logonData` | RDP/Remote login history | Registry (Terminal Server Client) | `lastWriteTime` |
| `nwConnectionDescriptor` | Mounted network drives | Registry (MountPoints2) | `lastWriteTime` |
| `osConfigSetting` | System settings (PATH, etc.) | Registry (Environment) | - |
| `process` | Historical process execution | Registry (UserAssist) | `startTime` |
| `userAccessedData` | Recently accessed files | Registry (OpenSaveMRU) | `maxLastAccessDate` |
| `userAccount` | User account details | Registry (SAM, ProfileList) | `dateCreated`, `lastLoginDate` |

**Example Artifact Counts** (from sample capture):
| Artifact Type | Count |
|--------------|-------|
| userAccessedData | 2,027 |
| process | 1,858 |
| configItem | 1,291 |
| logonData | 99 |
| osConfigSetting | 44 |
| nwConnectionDescriptor | 34 |
| userAccount | 20 |
| **Total** | **5,373** |

#### configItem (Startup Programs)
```json
{
  "type": "Startup Program",
  "description": "/Program Files/.../program.exe",
  "details": "Group = Logon; KeyPath = SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "args": "-autostart",
  "userID": "username",
  "userSID": "S-1-5-21-...",
  "userDomain": "DOMAIN",
  "extractor": "CollectionTool",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "path": "/users/username/ntuser.dat",
    "keyName": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "valueName": "ProgramName",
    "lastWriteTime": 1664483144000
  }
}
```
> **Timestamp**: `sourceInfo.lastWriteTime` = Registry key last modified (epoch ms)

#### logonData (RDP History)
```json
{
  "userID": "username",
  "userSID": "S-1-5-21-...",
  "userDomain": "DOMAIN",
  "remoteUser": "username",
  "remoteDomain": "DOMAIN",
  "remoteHostName": "server-name",
  "extractor": "CollectionTool",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "path": "/users/username/ntuser.dat",
    "keyName": "Software\\Microsoft\\Terminal Server Client\\Servers\\server-name",
    "lastWriteTime": 1625856979000
  }
}
```
> **Timestamp**: `sourceInfo.lastWriteTime` = Last RDP connection time (epoch ms)

#### nwConnectionDescriptor (Network Shares)
```json
{
  "type": "mountedDrive",
  "remoteHostName": "fileserver.domain.com",
  "remoteShareName": "ShareName/Folder",
  "userID": "username",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "keyName": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\##server#share"
  }
}
```

#### process (UserAssist - Program Execution)
```json
{
  "name": "program.exe",
  "path": "/windows/system32/program.exe",
  "args": null,
  "observationType": "LocalTrace",
  "startTime": 1557494761000,
  "userID": "username",
  "userSID": "S-1-5-21-...",
  "userDomain": "DOMAIN",
  "extractor": "CollectionTool",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "subType": "UserAssist",
    "path": "/users/username/ntuser.dat",
    "keyName": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
  }
}
```
> **Timestamp**: `startTime` = Program execution time (epoch ms)

#### userAccessedData (Recent Files)
```json
{
  "path": "//server/share/document.docx",
  "maxLastAccessDate": 1667405712000,
  "userID": "username",
  "userSID": "S-1-5-21-...",
  "userDomain": "DOMAIN",
  "extractor": "CollectionTool",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "subType": "Windows Open/Save MRU",
    "path": "/users/username/ntuser.dat",
    "keyName": "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\*",
    "valueName": "0"
  }
}
```
> **Timestamp**: `maxLastAccessDate` = Last file access time (epoch ms)

#### userAccount
```json
{
  "userID": "username",
  "userDomain": "DOMAIN",
  "userSID": "S-1-5-21-...",
  "userHomeDir": "/users/username",
  "accountType": "Regular",
  "accountStatus": "Enabled",
  "adminPriv": "local",
  "dateCreated": "2021-07-09T18:48:49.000000000Z",
  "lastLoginDate": "2019-06-14T15:42:20.000000000Z",
  "loginCount": "12",
  "sourceInfo": {
    "sourceType": "RegistryKey",
    "path": "/windows/system32/config/sam",
    "keyName": "SAM\\Domains\\Account\\Users\\000003E9"
  }
}
```

### SystemAPI
Windows API-based live collection from memory and event logs. These artifacts represent the **current state** at collection time, not historical data.

| Section Type | Description | Source | Count | Timestamp Field |
|--------------|-------------|--------|-------|-----------------|
| `windowsEvent` | Parsed Windows Event Log entries | Event Logs | 2,742 | `time` |
| `process` | Process execution from Task Scheduler | Event Logs | 1,486 | `startTime` |
| `nwConnectionDescriptor` | Active network connections | Memory | 144 | `time` (ISO) |
| `dnsCacheEntry` | DNS resolver cache | Memory | 112 | - |
| `arpCacheEntry` | ARP cache entries | Memory | 35 | - |
| `logonData` | Current login sessions | Memory | 18 | `time` |
| `routingTableEntry` | IP routing table | Memory | 7 | - |
| **Total** | | | **4,544** | |

#### windowsEvent (Parsed Event Log Entries)
```json
{
  "eventID": 21,
  "recordID": 776,
  "time": 1675555668002,
  "userID": "ladmin",
  "userDomain": "local",
  "extractor": "SystemAPI",
  "payload": {
    "User": "IS-CH-DTS\\ladmin",
    "SessionID": "3",
    "Address": "LOCAL"
  }
}
```
> **Timestamp**: `time` = Event timestamp (epoch ms)

#### process (Task Scheduler Audit)
```json
{
  "name": "wermgr.exe",
  "path": "/windows/system32/wermgr.exe",
  "args": "",
  "observationType": "LocalTrace",
  "startTime": 1675556891000,
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "EventLog",
    "subType": "Task Action Audit",
    "eventLogName": "Microsoft-Windows-TaskScheduler/Operational",
    "eventLogRecordId": "1846878",
    "eventLogEventId": "200"
  }
}
```
> **Timestamp**: `startTime` = Task execution time (epoch ms)

#### logonData (Current Sessions)
```json
{
  "time": 1675555656000,
  "userID": "ladmin",
  "userSID": "S-1-5-21-3960477883-2982344637-2545769739-500",
  "userDomain": "local",
  "logonType": "2",
  "logonID": "0x6a0ad43",
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "Memory"
  }
}
```
> **Timestamp**: `time` = Session login time (epoch ms)
> **logonType**: 2=Interactive, 3=Network, 10=RemoteInteractive (RDP)

#### nwConnectionDescriptor (Active Connections)
```json
{
  "type": "listeningPort",
  "localIP": "0.0.0.0",
  "localPort": "135",
  "remoteIP": "",
  "remotePort": "",
  "connectionType": "TCP",
  "pid": "1100",
  "time": "2023-02-05T00:32:25.000000000Z",
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "Memory"
  }
}
```
> **Timestamp**: `time` = Collection timestamp (ISO 8601)
> **type**: `listeningPort`, `establishedConnection`, `udpListener`

#### dnsCacheEntry (DNS Cache)
```json
{
  "remoteHostName": "fa000000006.resources.office.net",
  "remoteIP": "52.96.x.x",
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "Memory"
  }
}
```
> No timestamp - represents current DNS cache state

#### arpCacheEntry (ARP Cache)
```json
{
  "remoteIP": "224.0.2.3",
  "physicalAddress": "01:00:5E:00:02:03",
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "Memory"
  }
}
```
> No timestamp - represents current ARP table

#### routingTableEntry (IP Routing)
```json
{
  "remoteIP": "10.151.0.0",
  "nextHopAddress": "0.0.0.0",
  "extractor": "SystemAPI",
  "sourceInfo": {
    "sourceType": "Memory"
  }
}
```
> No timestamp - represents current routing table

## JSON Structure

```
{
  "cyberTriageAgentOutput": [
    {
      "cyberTriageOutputSection": [
        { "sectionType": { ...section data... } }
      ]
    }
  ]
}
```

### Section Types

| Section Type | Description |
|--------------|-------------|
| `file` | File metadata and optional content |
| `process` | Running process information |
| `windowsEvent` | Parsed Windows Event Log entries |
| `networkConnection` | Network connections |
| `userAccount` | User account information |
| `webArtifact` | Browser history/downloads |
| `dnsCache` | DNS cache entries |

## File Section Structure

```json
{
  "file": {
    "path": "/windows/system32/config/",
    "fileName": "SOFTWARE",
    "fileContentStatus": "Collected",
    "fileSize": 134742016,
    "dateModified": 1675553652233,
    "dateCreated": 1625856549584,
    "md5hash": "...",
    "sha256hash": "...",
    "sha1hash": "...",
    "fileContentLength": 134742016,
    "fileContent": "eJz...BASE64+ZLIB..."
  },
  "extractor": "TSK",
  "sourceInfo": {
    "sourceType": "FileSystem"
  }
}
```

### fileContentStatus Values

| Status | Description |
|--------|-------------|
| `Collected` | File content is included (base64 + zlib) |
| `NotAttempted` | File exists but content not collected |
| `NotRegularFile` | Directory or special file |
| `NotFound` | File referenced but not found |
| `HashOnly` | Only hash was collected |
| `EmptyFile` | Zero-byte file |
| `Unresolved` | Unable to resolve path |

## File Content Encoding

Collected files are stored as:
1. Original file bytes
2. Zlib compressed
3. Base64 encoded

To decode:
```python
import base64, zlib
decoded = base64.b64decode(fileContent)
if decoded[0] == 0x78:  # zlib magic byte
    decoded = zlib.decompress(decoded)
```

## Timestamp Formats

CyberTriage uses two timestamp formats:

### Epoch Milliseconds (numeric)
Used in: `startTime`, `maxLastAccessDate`, `lastWriteTime`, `dateModified`, etc.
```python
from datetime import datetime
ts_ms = 1667405712000
dt = datetime.fromtimestamp(ts_ms / 1000)
# Result: 2022-11-02 12:15:12
```

### ISO 8601 String
Used in: `dateCreated`, `lastLoginDate`, `winInstallDate`
```
"2021-07-09T18:48:49.000000000Z"
```

### Timestamp Fields by Artifact Type

| Artifact Type | Field | Description |
|--------------|-------|-------------|
| `configItem` | `sourceInfo.lastWriteTime` | Registry key modified |
| `process` | `startTime` | Program execution time |
| `userAccessedData` | `maxLastAccessDate` | File last accessed |
| `logonData` | `sourceInfo.lastWriteTime` | RDP connection time |
| `userAccount` | `dateCreated` | Account creation |
| `userAccount` | `lastLoginDate` | Last login |
| `file` | `dateModified` | File modified |
| `file` | `dateCreated` | File created |
| `file` | `dateAccessed` | File accessed |

## Key Forensic Artifacts in Windows Captures

### Registry Hives
| Path | Description |
|------|-------------|
| `/windows/system32/config/SOFTWARE` | System software registry |
| `/windows/system32/config/SYSTEM` | System configuration |
| `/windows/system32/config/SAM` | Security Account Manager |
| `/windows/system32/config/SECURITY` | Security policies |
| `/users/<user>/ntuser.dat` | User registry hive |
| `/users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat` | User class registry |

### Event Logs
| Path | Description |
|------|-------------|
| `/windows/system32/winevt/logs/Application.evtx` | Application events |
| `/windows/system32/winevt/logs/Security.evtx` | Security events |
| `/windows/system32/winevt/logs/System.evtx` | System events |

### Browser Artifacts
| Path | Description |
|------|-------------|
| `/users/<user>/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat` | IE/Edge web cache |
| `/users/<user>/AppData/Local/Google/Chrome/User Data/` | Chrome profile |

### Other Artifacts
| Path | Description |
|------|-------------|
| `/Windows/Prefetch/` | Prefetch files |
| `/Windows/System32/Tasks/` | Scheduled tasks |
| `/Windows/System32/drivers/etc/hosts` | Hosts file |
| `/$MFT` | Master File Table |
| `/$RECYCLE.BIN/` | Deleted files |

## Example Capture Statistics

From a typical Windows workstation capture:
- **Total files indexed**: 171,038
- **Files with content collected**: 672 (2.96 GB)
- **By status**:
  - NotAttempted: 116,662
  - NotRegularFile: 52,993
  - Collected: 672
  - NotFound: 613

## Caching Strategy

For efficient processing:
1. Decompress `.json.gz` to `.cache` file (one-time)
2. Build index of all files to `.index.json`
3. Subsequent queries use cached index (<1 second)

## Tools

### ct_quick_extract.py - File Extraction
Extract collected files (binaries, registry hives, event logs):
```bash
# Summary of collected files
python3 ct_quick_extract.py capture.json.gz --summary

# List collected files
python3 ct_quick_extract.py capture.json.gz --list --filter .evtx

# Extract by extractor type
python3 ct_quick_extract.py capture.json.gz --extract ./output --extractor-filter TSK

# Export full listing to CSV
python3 ct_quick_extract.py capture.json.gz --full-listing --output-csv files.csv
```

### ct_extract_artifacts.py - Artifact Extraction for DFIR
Extract pre-parsed forensic artifacts to CSV/JSON for timeline analysis:
```bash
# List CollectionTool artifacts
python3 ct_extract_artifacts.py capture.json.gz --list

# List SystemAPI artifacts (live memory + event logs)
python3 ct_extract_artifacts.py capture.json.gz --list --extractor SystemAPI

# Extract CollectionTool artifacts to CSV
python3 ct_extract_artifacts.py capture.json.gz --extract ./artifacts

# Extract SystemAPI artifacts to CSV
python3 ct_extract_artifacts.py capture.json.gz --extract ./systemapi --extractor SystemAPI

# Extract specific artifact type
python3 ct_extract_artifacts.py capture.json.gz --extract ./artifacts --type windowsEvent

# Export to JSON instead of CSV
python3 ct_extract_artifacts.py capture.json.gz --extract ./artifacts --format json
```

**CollectionTool Output** (parsed registry/file artifacts):
| File | Contents | Key Timestamp |
|------|----------|---------------|
| `configItem.csv` | Startup programs, services | `source_lastWriteTime` |
| `process.csv` | UserAssist program execution | `startTime` |
| `userAccessedData.csv` | Recently opened files | `maxLastAccessDate` |
| `logonData.csv` | RDP connection history | `source_lastWriteTime` |
| `userAccount.csv` | User accounts | `dateCreated`, `lastLoginDate` |
| `nwConnectionDescriptor.csv` | Mounted network shares | `source_lastWriteTime` |
| `osConfigSetting.csv` | System settings (PATH) | - |

**SystemAPI Output** (live memory + event log artifacts):
| File | Contents | Key Timestamp |
|------|----------|---------------|
| `windowsEvent.csv` | Parsed Windows Event entries | `time` |
| `process.csv` | Task Scheduler execution | `startTime` |
| `logonData.csv` | Current login sessions | `time` |
| `nwConnectionDescriptor.csv` | Active network connections | `time_str` |
| `dnsCacheEntry.csv` | DNS resolver cache | - |
| `arpCacheEntry.csv` | ARP cache entries | - |
| `routingTableEntry.csv` | IP routing table | - |

All timestamps are converted to **ISO 8601 format** for easy import into:
- Timeline Explorer
- Splunk / ELK
- Plaso / log2timeline
- Excel / Google Sheets

### ct_to_timesketch - Timesketch Timeline Export
Convert CyberTriage captures to Timesketch JSONL format for collaborative timeline analysis.

> **Full documentation**: See [ct_to_timesketch/README.md](../ct_to_timesketch/README.md)

```bash
# Install dependencies
pip install rich python-evtx python-registry LnkParse3 libesedb-python

# Convert all artifacts with all available parsers
python3 -m ct_to_timesketch capture.json.gz --parse-all

# Convert base artifacts only (CollectionTool + SystemAPI)
python3 -m ct_to_timesketch capture.json.gz

# Selective parsing
python3 -m ct_to_timesketch capture.json.gz \
    --parse-evtx \
    --parse-registry \
    --parse-browser \
    --parse-lnk \
    --parse-powershell \
    --parse-webcache

# List available extractors
python3 -m ct_to_timesketch --list-extractors
```

**Available Parsers**:
| Flag | Description | Events |
|------|-------------|--------|
| (base) | CyberTriage pre-parsed artifacts | ~5-10k |
| `--parse-evtx` | Raw Windows Event Logs (.evtx) | ~100k+ |
| `--parse-registry` | Registry hives (ShellBags, UserAssist, USB) | ~5k |
| `--parse-browser` | Chrome/Edge/Firefox history | ~10k+ |
| `--parse-lnk` | Windows shortcut files | ~2k |
| `--parse-powershell` | PowerShell command history | varies |
| `--parse-webcache` | IE/Edge WebCache ESE database | ~2k |
| `--parse-prefetch` | Prefetch files (Windows only) | varies |

**Event Types Generated**:
| Source | Event Type | Description |
|--------|-----------|-------------|
| Base | `process_execution` | UserAssist program execution |
| Base | `startup_item` | Startup programs/services |
| Base | `rdp_connection` | RDP connection history |
| Base | `file_access` | Recently accessed files (MRU) |
| Base | `windows_event` | Pre-parsed Windows events |
| Base | `session_logon` | Current login sessions |
| EVTX | `evtx_logon` | Logon/logoff events |
| EVTX | `evtx_process` | Process creation events |
| EVTX | `evtx_service` | Service state changes |
| EVTX | `evtx_powershell` | PowerShell script events |
| EVTX | `evtx_rdp` | RDP session events |
| Registry | `registry_shellbag` | Folder access history |
| Registry | `registry_userassist` | Program execution counts |
| Registry | `registry_usb` | USB device history |
| Browser | `browser_history` | URL visits |
| LNK | `lnk_target` | Shortcut target information |
| PowerShell | `powershell_history` | PS command history |
| WebCache | `webcache_history` | IE/Edge URL visits |

### Timesketch JSONL Validation
Validate JSONL files against official Timesketch format requirements:
```bash
# Using the package validator
python3 -c "from ct_to_timesketch.validators.timesketch import validate_jsonl; validate_jsonl('timeline.jsonl')"

# Or using the standalone script (if available)
python3 validate_timesketch.py timeline.jsonl
```

