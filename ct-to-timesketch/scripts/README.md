# Utility Scripts

This directory contains utility scripts for analyzing and extracting data from CyberTriage timeline JSONL files.

## Scripts

### `analyze_sysvol_quick.py`

Quick analysis tool to examine SYSVOL folder structure and Group Policy Objects (GPOs) from Domain Controller timeline files.

**Purpose**: Determine if a timeline file contains SYSVOL data and identify GPOs with their creation/modification dates.

**Usage**:
```bash
# From project root
python scripts/analyze_sysvol_quick.py reports/DC00_timeline.jsonl

# Or from scripts directory
cd scripts
python analyze_sysvol_quick.py ../reports/DC00_timeline.jsonl
```

**Output**:
- Summary statistics (total SYSVOL entries, unique paths, directories, GPOs)
- Timestamp type breakdown
- Directory structure sample
- GPOs identified with creation/modification dates
- File type breakdown

**Example Output**:
```
SYSVOL data present: YES
Total SYSVOL MFT entries: 5,822
Group Policy Objects (GPOs) found: 5

GPO GUID: {31B2F340-016D-11D2-945F-00C04FB984F9}
  Created:  2007-05-08 17:02:19.593000+00:00
  Modified: 2020-05-11 08:34:08.292000+00:00
```

**Requirements**:
- Python 3.6+
- Standard library only (json, re, collections, pathlib, datetime)

---

### `export_collected_files.py`

Export a CSV list of all files that were collected (content extracted) by CyberTriage from a timeline JSONL file.

**Purpose**: Generate a comprehensive list of collected files with metadata including paths, sizes, timestamps, and hashes.

**Usage**:
```bash
# From project root
python scripts/export_collected_files.py reports/KAN-GW2_timeline.jsonl

# Specify custom output path
python scripts/export_collected_files.py reports/DC00_timeline.jsonl output/my_files.csv

# Or from scripts directory
cd scripts
python export_collected_files.py ../reports/KAN-GW2_timeline.jsonl
```

**Output CSV Columns**:
- `file_path` - Full file path
- `file_name` - Filename only
- `file_size` - Size in bytes
- `date_created` - Creation timestamp (ISO 8601)
- `date_modified` - Modification timestamp (ISO 8601)
- `date_accessed` - Last access timestamp (ISO 8601)
- `date_changed` - MFT entry changed timestamp (ISO 8601)
- `md5`, `sha1`, `sha256` - File hashes (if available)
- `mft_entry` - MFT entry number
- `content_status` - Collection status (always "Collected" for this export)
- `meta_type` - File or directory
- `user_sid` - Owner SID

**Example Output**:
```
Processed 1,316,702 total entries
Found 1,480 collected file entries
Unique collected files: 185
✓ Exported 185 collected files to reports/KAN-GW2_timeline_collected_files.csv
```

**Requirements**:
- Python 3.6+
- Standard library only (json, csv, pathlib, collections, datetime)

---

### `export_installed_software.py`

Export a comprehensive list of installed software from timeline JSONL files, combining data from Registry Uninstall keys and Amcache InventoryApplication entries.

**Purpose**: Extract installed software inventory with metadata including program names, versions, publishers, installation dates, MSI codes, and more.

**Usage**:
```bash
# From project root
python scripts/export_installed_software.py reports/DC00_timeline.jsonl

# Specify custom output path
python scripts/export_installed_software.py reports/KAN-GW2_timeline.jsonl output/software.csv

# Or from scripts directory
cd scripts
python export_installed_software.py ../reports/DC00_timeline.jsonl
```

**Output CSV Columns**:
- `program_name` - Program name
- `publisher` - Software publisher
- `version` - Installed version
- `install_date` - Installation date (ISO format)
- `install_source` - Installation method (MSI, AppxPackage, Registry, etc.)
- `install_path` - Installation directory
- `uninstall_string` - Uninstall command
- `registry_key_path` - Registry key path
- `msi_product_code` - MSI product code GUID
- `msi_package_code` - MSI package code GUID
- `data_source` - Source of data (Registry, Amcache, or Both)
- `hidden_from_arp` - Hidden from Add/Remove Programs
- `is_inbox_app` - Windows built-in app
- `store_app_type` - Windows Store app type
- `package_full_name` - Package full name
- `timestamp` - Event timestamp
- `hostname` - Hostname

**Data Sources**:
- **Registry Uninstall Keys**: `windows:registry:uninstall` entries from SOFTWARE hive
- **Amcache InventoryApplication**: `windows:registry:amcache:inventory_application` entries (if Amcache.hve was collected)

**Deduplication**: If the same program appears in both sources, Amcache data is preferred (more complete). Programs are deduplicated by MSI product code (if available) or program name + publisher.

**Example Output**:
```
Processed timeline entries
  Registry Uninstall entries: 19
  Amcache InventoryApplication entries: 0
  Unique software programs: 19
✓ Exported 19 software programs to reports/DC00_timeline_installed_software.csv
```

**Requirements**:
- Python 3.6+
- Standard library only (json, csv, pathlib, datetime, collections)

---

### `export_sessions_rdp.py`

Export interactive console sessions and RDP (Remote Desktop Protocol) sessions from timeline JSONL files, combining data from Windows Event Logs, Terminal Services events, and Registry RDP history.

**Purpose**: Extract interactive console and RDP session information for DFIR analysis focused on "hands-on-keyboard" activity. Filters out network logons and service accounts to focus on user interactive sessions.

**Usage**:
```bash
# From project root
python scripts/export_sessions_rdp.py reports/DC00_timeline.jsonl

# Specify custom output path
python scripts/export_sessions_rdp.py reports/KAN-GW2_timeline.jsonl output/sessions.csv

# Or from scripts directory
cd scripts
python export_sessions_rdp.py ../reports/DC00_timeline.jsonl
```

**Output CSV Columns**:
- `session_id` - Session identifier
- `logon_id` - Logon session ID (unique per session)
- `connection_type` - Interactive Console, RDP, Network, or Failed Logon
- `username` - Username
- `domain` - Domain name
- `source_ip` - Source IP address
- `source_hostname` - Source computer name
- `target_hostname` - Target computer (this system)
- `logon_time` - Session start time (ISO format)
- `logoff_time` - Session end time (ISO format)
- `duration_seconds` - Session duration in seconds (if logoff found)
- `logon_type` - Windows logon type (2, 3, 10, etc.)
- `logon_type_desc` - Human-readable logon type description
- `authentication_method` - Authentication package name
- `logon_process` - Logon process name
- `workstation_name` - Workstation name
- `event_ids` - Comma-separated list of related event IDs
- `data_source` - Source of data (EventLog, Registry, Memory)
- `hostname` - System hostname

**Data Sources**:
- **Windows Security Events**: Event IDs 4624 (successful logon), 4625 (failed logon), 4634 (logoff), 4647 (user-initiated logoff)
- **Terminal Services Events**: Event IDs 21 (RDP logon), 23 (RDP logoff), 24 (disconnect), 25 (reconnect)
- **Registry RDP History**: Terminal Server Client registry entries from NTUSER.DAT
- **SystemAPI**: Current sessions from memory (if available)

**Session Correlation**: Logon and logoff events are correlated by:
- `LogonID` / `TargetLogonId` (most reliable)
- `SessionID` + `Username` (for RDP sessions)
- `Username` + `Source IP` + time window (fallback)

**Connection Type Detection**:
- **Interactive Console**: LogonType 2 with LOCAL address or localhost IP
- **RDP**: LogonType 10 (RemoteInteractive) or Terminal Services events
- **Failed Logon**: Event ID 4625 for Interactive/RDP logon types only

**Filtering**: The script filters out Network logons (LogonType 3) and Unknown connection types to focus on "hands-on-keyboard" activity. Only Interactive Console and RDP sessions are included in the output.

**Example Output**:
```
Processed timeline entries
  Security logon events (4624/4672): 1,234
  Security logoff events (4634/4647): 1,200
  Failed logon attempts (4625): 45
  Terminal Services RDP events: 234
  Unique sessions: 1,250
✓ Exported 1,295 session entries to reports/DC00_timeline_sessions_rdp.csv
```

**Requirements**:
- Python 3.6+
- Standard library only (json, csv, pathlib, datetime, collections)

---

## Common Use Cases

### Check if a system is a Domain Controller
```bash
python scripts/analyze_sysvol_quick.py reports/system_timeline.jsonl
```
If SYSVOL data is present, the system is likely a Domain Controller.

### Export all collected files for analysis
```bash
python scripts/export_collected_files.py reports/system_timeline.jsonl
```
Opens the CSV in Excel/Google Sheets for further analysis.

### Export installed software inventory
```bash
python scripts/export_installed_software.py reports/system_timeline.jsonl
```
Generates a comprehensive software inventory CSV for security and compliance analysis.

### Find GPOs and their modification dates
```bash
python scripts/analyze_sysvol_quick.py reports/DC_timeline.jsonl | grep -A 5 "GPO GUID"
```

### Export all user sessions and RDP connections
```bash
python scripts/export_sessions_rdp.py reports/system_timeline.jsonl
```
Generates a comprehensive session timeline CSV showing all interactive and remote sessions with connection details.

---

## Future Enhancements

These scripts may evolve into more full-featured tools:

- **SYSVOL Reconstruction**: Full directory tree reconstruction with GPO mapping
- **File Collection Analysis**: Advanced filtering and reporting on collected files
- **Timeline Comparison**: Compare collected files across multiple systems
- **GPO Name Resolution**: Map GPO GUIDs to display names from Active Directory or gpt.ini files
- **Software Vulnerability Mapping**: Map installed software versions to known CVEs
- **Software Version Comparison**: Compare software versions across multiple systems
- **Enhanced Registry Parsing**: Extract additional fields from SOFTWARE hive if content is collected

---

## Notes

- All scripts work with paths relative to the project root or absolute paths
- Scripts handle both field name variations (`filePath` vs `file_path`, etc.)
- Output files are written to the same directory as the input file by default
- Scripts are designed to be memory-efficient for large timeline files (process line-by-line)

---

## Contributing

When adding new utility scripts:

1. Add a shebang: `#!/usr/bin/env python3`
2. Include a docstring describing the script's purpose
3. Handle paths relative to project root
4. Add usage examples in the script's `if __name__ == '__main__'` block
5. Update this README with script documentation
6. Use standard library when possible, or document dependencies

