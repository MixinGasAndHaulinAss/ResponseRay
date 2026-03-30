# ct-to-timesketch --directory Mode Implementation Spec

## Overview

Add `--directory` mode to ct-to-timesketch that processes a ResponseRay Collector output directory
instead of a CyberTriage JSON file. This enables the full artifact collection pipeline to work
end-to-end with the new Windows standalone collector.

## CLI Changes

### New Flag
```
--directory <path>    Process a ResponseRay Collector output directory instead of a CyberTriage JSON file
```

When `--directory` is specified, the positional CyberTriage input file argument is not required.

### Example Invocations
```bash
# Existing CyberTriage mode (unchanged)
ct-to-timesketch input.json.gz --output timeline.jsonl --artifacts-dir /data/artifacts/uuid --cloudrules

# New directory mode
ct-to-timesketch --directory /data/uploads/uuid/extracted --output timeline.jsonl --artifacts-dir /data/artifacts/uuid --cloudrules
```

## Processing Pipeline in Directory Mode

### 1. Parse manifest.json
- Read `manifest.json` from the directory root
- Extract hostname, OS version, domain, collection timestamp
- Use hostname for the `host_name` field in output events

### 2. Process File-Based Artifacts (artifacts/ subdirectory)
Populate `cache.Index.ArtifactFiles` from the manifest's file list and run all existing extractors:

| Subdirectory | Extractor | Notes |
|---|---|---|
| `artifacts/evtx/` | EVTX extractor | Copy .evtx files to artifacts-dir |
| `artifacts/registry/` | Registry extractor | Copy hives to artifacts-dir under simulated Windows paths |
| `artifacts/prefetch/` | Prefetch extractor | Copy .pf files |
| `artifacts/srum/` | SRUM extractor | Copy SRUDB.dat |
| `artifacts/browser/` | Browser extractor | Map History/places.sqlite files |
| `artifacts/timeline/` | Timeline extractor | ActivitiesCache.db |
| `artifacts/wmi/` | WMI extractor | OBJECTS.DATA |
| `artifacts/recyclebin/` | RecycleBin extractor | $I files |
| `artifacts/tasks/` | Tasks extractor | Scheduled task XML |
| `artifacts/powershell/` | PowerShell extractor | ConsoleHost_history.txt |
| `artifacts/lnk/` | LNK extractor | .lnk files |
| `artifacts/dhcp/` | DHCP extractor | DhcpSrvLog files |

The key insight: each extractor expects files in the `artifacts-dir` under a Windows-like path structure.
The directory mode should:
1. Copy/symlink files from the collector output into `artifacts-dir` with appropriate path mapping
2. Build the `ArtifactFiles` index from the manifest
3. Run each extractor as normal

### 3. Parse Raw $MFT (mft/ subdirectory)
- Read `mft/$MFT` (raw NTFS Master File Table)
- Parse using a Go MFT parser (e.g., `github.com/AgitoReiworworker/go-mft` or Velocidex `ntfs` package)
- Generate MACB timeline events for each MFT entry:
  ```json
  {
    "datetime": "2024-01-15T10:30:00Z",
    "event_type": "file_system",
    "data_type": "fs:ntfs:mft",
    "message": "Created: C:\\Windows\\System32\\cmd.exe",
    "host_name": "WORKSTATION01",
    "source_short": "MFT",
    "timestamp_desc": "Creation Time",
    "MFTEntryNumber": 12345,
    "FileName": "cmd.exe",
    "FilePath": "C:\\Windows\\System32\\cmd.exe",
    "FileSize": 289792,
    "IsAllocated": true,
    "IsDirectory": false
  }
  ```
- Generate 4 events per entry (MACB): Modified, Accessed, Changed ($MFT), Born (Created)
- This is typically the largest event source (1-2M+ events per system)

### 4. Process Live System State (live/ subdirectory)
Read each JSON file in `live/` and convert to timeline events using the existing `Convert*` methods:

| File | Converter Method | Event Type |
|---|---|---|
| `processes.json` | `ConvertRunningProcess` | `running_process` |
| `connections.json` | `ConvertActiveConnection` | `active_connection` |
| `dns_cache.json` | `ConvertDNSCache` | `dns_cache` |
| `arp_cache.json` | `ConvertARPCache` | `arp_cache` |
| `routing_table.json` | `ConvertRoutingTable` | `routing_table` |
| `logon_sessions.json` | `ConvertLogonSession` / `ConvertLogonDataCollection` | `logon_session` |
| `user_accounts.json` | `ConvertUserAccount` | `user_account` |
| `services.json` | `ConvertConfigItem` (service) | `config_item` |
| `startup_items.json` | `ConvertConfigItem` (startup) | `config_item` |
| `devices.json` | `ConvertAttachedDevice` | `attached_device` |

Each entry in the JSON arrays should be converted to a timeline event with:
- `datetime` from the `collection_timestamp` field
- `host_name` from the manifest
- Fields mapped to match the existing converter output format

### 5. Write Combined timeline.jsonl
All events from steps 2-4 are written to the single output JSONL file, same format as CyberTriage mode.

## Implementation Notes

### Go Code Structure
Add to `main.go` / entry point:
```go
var directoryMode = flag.String("directory", "", "Process a ResponseRay Collector directory")

func main() {
    // ... existing flag parsing ...
    
    if *directoryMode != "" {
        processDirectory(*directoryMode, *outputPath, *artifactsDir, *cloudRules)
    } else {
        // existing CyberTriage JSON flow
    }
}
```

### New Files
- `internal/directory/processor.go` - Main directory mode orchestration
- `internal/directory/manifest.go` - Parse manifest.json
- `internal/directory/live.go` - Process live/*.json files
- `internal/directory/mft.go` - MFT parsing and event generation

### MFT Parsing
Recommended Go library: `www.velocidex.com/golang/go-ntfs/parser` (already used by Velociraptor)
- Parse MFT records
- Extract MACB timestamps
- Reconstruct file paths from parent directory references
- Handle both resident and non-resident attributes

## ResponseRay Worker Integration
The worker already detects .zip uploads and extracts them. It passes the extracted directory
to ct-to-timesketch with `--directory`. See `backend/cmd/worker/main.go`.
