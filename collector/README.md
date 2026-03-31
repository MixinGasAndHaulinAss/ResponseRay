# ResponseRay Collector

A standalone Windows forensic artifact collector that captures a comprehensive set of DFIR artifacts from a live system. Produces a structured ZIP archive ready for upload to the [ResponseRay](https://github.com/NCLGISA/ResponseRay) platform.

**Current version:** `2026.3.30.9`

## Key Design Principles

- **No installation required** — single self-contained `.exe`, runs from USB, network share, or local disk
- **No VSS dependency** — uses `reg save` for locked system registry hives and `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS` + `SeBackupPrivilege` for other locked files
- **Multi-drive support** — captures MFT from all NTFS fixed/removable volumes (C:, D:, E:, etc.)
- **Raw MFT capture** — reads the Master File Table directly from the raw volume device using NTFS boot sector parsing
- **Minimal footprint** — collects to temp directory, compresses to a single ZIP, cleans up after itself

## Requirements

- **Administrator privileges** — required for `SeBackupPrivilege`, raw volume access, and `reg save`
- **Windows 10/11 or Windows Server 2016+**
- **.NET 8 SDK** for building (the published executable is self-contained and needs no runtime)

## Quick Start

```
ResponseRayCollector.exe
```

Run as Administrator. The collector will:

1. Detect all NTFS volumes
2. Enable `SeBackupPrivilege` and `SeManageVolumePrivilege`
3. Collect all artifacts (~60-90 seconds on a typical system)
4. Package everything into `{hostname}_{timestamp}.zip` in the current directory
5. Clean up temporary files

Upload the ZIP through the ResponseRay web UI.

## Command Line Options

```
ResponseRayCollector.exe [--output <path>] [--skip <collectors>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output <path>` | Directory to write the output ZIP | Current directory |
| `--skip <list>` | Comma-separated collector names to skip | None |

### Examples

```bash
# Collect everything, output to current directory
ResponseRayCollector.exe

# Output to a USB drive
ResponseRayCollector.exe --output E:\collections

# Skip MFT and event logs (faster collection)
ResponseRayCollector.exe --skip mft,eventlogs
```

## Collectors

The tool runs 25 collectors in sequence. Each can be skipped individually using the `--skip` flag.

### Artifact Collectors

| Collector | Skip Name | Description |
|-----------|-----------|-------------|
| EventLogs | `eventlogs` | All `.evtx` files from `%SystemRoot%\System32\winevt\Logs` |
| Registry | `registry` | System hives (SAM, SYSTEM, SOFTWARE, SECURITY) via `reg save`; user hives (NTUSER.DAT, UsrClass.dat) and Amcache.hve via backup copy |
| Prefetch | `prefetch` | All `.pf` files from `%SystemRoot%\Prefetch` |
| SRUM | `srum` | `SRUDB.dat` (System Resource Usage Monitor) |
| Browser | `browser` | Chrome/Edge/Firefox History databases per user profile |
| WindowsTimeline | `windowstimeline` | `ActivitiesCache.db` per user |
| WMI | `wmi` | `OBJECTS.DATA` for WMI persistence detection |
| RecycleBin | `recyclebin` | `$I` metadata files from `$Recycle.Bin` |
| ScheduledTasks | `scheduledtasks` | Task XML files from `%SystemRoot%\System32\Tasks` |
| PowerShellHistory | `powershellhistory` | `ConsoleHost_history.txt` per user |
| LnkFiles | `lnkfiles` | `.lnk` shortcut files from user Recent folders |
| DHCP | `dhcp` | DHCP server log files (if present) |
| MFT | `mft` | Raw Master File Table from all NTFS volumes |
| FileSystem | `filesystem` | File system metadata collection |

### Live System State Collectors

These capture the current state of the running system as JSON files.

| Collector | Skip Name | Description |
|-----------|-----------|-------------|
| Processes | `processes` | Running processes with PID, path, command line, MD5 hash, parent PID |
| NetworkConnections | `networkconnections` | TCP/UDP connections with local/remote addresses and owning PID |
| DnsCache | `dnscache` | DNS resolver cache entries |
| ArpCache | `arpcache` | ARP table |
| RoutingTable | `routingtable` | IP routing table |
| LogonSessions | `logonsessions` | Active logon sessions |
| UserAccounts | `useraccounts` | Local user accounts with group membership |
| Services | `services` | Windows service configuration and state |
| StartupItems | `startupitems` | Autostart entries from registry Run keys and startup folders |
| Devices | `devices` | Attached devices (USB, PnP) |
| UserAccessedData | `useraccesseddata` | Recently accessed files and user activity |
| OsConfig | `osconfig` | OS version, hardware, network configuration |

## Output Format

The collector produces `{hostname}_{timestamp}.zip` containing:

```
manifest.json              # Collection metadata, file inventory, collector results
artifacts/
  evtx/                    # Windows Event Log files (.evtx)
  registry/                # SAM, SYSTEM, SOFTWARE, SECURITY, {user}_NTUSER.DAT,
                           #   {user}_UsrClass.dat, Amcache.hve
  prefetch/                # Prefetch files (.pf)
  srum/                    # SRUDB.dat
  browser/
    {user}/                # Chrome/Edge/Firefox History databases per user
  timeline/                # ActivitiesCache.db
  wmi/                     # OBJECTS.DATA
  recyclebin/              # $I metadata files
  tasks/                   # Scheduled task XML files
  powershell/              # ConsoleHost_history.txt per user
  lnk/                     # .lnk shortcut files
  dhcp/                    # DHCP server logs (if applicable)
mft/
  $MFT                     # Raw MFT from C: drive
  $MFT_E                   # Raw MFT from E: drive (if present)
  $MFT_D                   # Raw MFT from D: drive (if present)
live/
  processes.json           # Running processes with MD5 hashes
  connections.json         # TCP/UDP connections with owning PIDs
  dns_cache.json           # DNS resolver cache
  arp_cache.json           # ARP table
  routing_table.json       # IP routing table
  logon_sessions.json      # Active logon sessions
  user_accounts.json       # Local user accounts
  services.json            # Windows services
  startup_items.json       # Autostart entries
  devices.json             # Attached devices (USB, PnP)
  user_accessed_data.json  # Recent file access
  os_config.json           # OS and hardware configuration
```

### manifest.json

The manifest contains:

- `collector_version` — CalVer version string
- `hostname` — Machine name
- `os_version` — Windows version
- `domain` — Domain or workgroup
- `collection_timestamp` — UTC ISO 8601 timestamp
- `collection_duration_seconds` — Total collection time
- `user_profiles` — Discovered user profile names
- `total_files` — Number of files collected
- `total_bytes` — Total data size
- `collector_results` — Per-collector status (files collected, bytes, elapsed time, errors)
- `collected_files` — File inventory with original paths, relative paths, categories, and sizes

## How It Works

### Privilege Elevation

The collector enables `SeBackupPrivilege` and `SeManageVolumePrivilege` at startup before any collectors run. These allow reading locked files and raw volume access.

### Registry Capture Strategy

System hives (SAM, SYSTEM, SOFTWARE, SECURITY) are captured using `reg save`, which uses the Windows registry API to export a consistent copy regardless of file locks. This is more reliable than file-level copy for hives held exclusively by the system.

User hives (NTUSER.DAT, UsrClass.dat) and Amcache.hve are captured using `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS`, which respects `SeBackupPrivilege` to bypass ACL restrictions.

### MFT Capture Strategy

The MFT collector uses a three-tier approach for each NTFS volume:

1. **Raw volume read** (primary) — Opens `\\.\X:` as a raw device, parses the NTFS boot sector to locate the MFT, reads data runs from MFT entry 0, and copies the entire MFT
2. **NtCreateFile** (fallback) — Uses the NT native API with `FILE_OPEN_FOR_BACKUP_INTENT`
3. **Direct FileStream** (last resort) — Standard file I/O on `X:\$MFT`

### Multi-Drive Support

The collector automatically discovers all NTFS fixed and removable drives. MFT files are named by drive letter:

- `$MFT` — C: drive (primary)
- `$MFT_D` — D: drive
- `$MFT_E` — E: drive

## Building

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build Command

```bash
cd collector/src/ResponseRayCollector
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ../../../collector/publish
```

The output is a single executable at `collector/publish/ResponseRayCollector.exe` (~65 MB).

### Version

The version is set in `ResponseRayCollector.csproj` using CalVer format (`Year.Month.Day.Revision`):

```xml
<Version>2026.3.30.9</Version>
```

## Upload to ResponseRay

1. Open the ResponseRay web UI
2. Navigate to your site (or create one)
3. Click **Upload Capture**
4. Select the `.zip` file produced by the collector
5. The worker automatically detects collector archives, extracts them, and processes all artifacts

## Compatibility

| OS | Status |
|----|--------|
| Windows 11 24H2 | Tested |
| Windows 10 22H2 | Tested |
| Windows Server 2022 | Tested |
| Windows Server 2019 | Expected to work |
| Windows Server 2016 | Expected to work |

## License

Internal use — Currituck County, NC.
