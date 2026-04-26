# ResponseRay Collector

A standalone Windows forensic artifact collector that captures a comprehensive set of DFIR artifacts from a live system. Produces a structured ZIP archive ready for upload to the [ResponseRay](https://github.com/NCLGISA/ResponseRay) platform.

**Current version:** `2026.4.26.1`

## Key Design Principles

- **No installation required** — single self-contained `.exe`, runs from USB, network share, or local disk
- **VSS-aware locked-file handling** — automatically creates a Volume Shadow Copy of `C:\` at start and reads locked files (registry hives, NTDS.dit, Defender, EventTranscript, etc.) from the shadow path. If VSS is unavailable, falls back to `reg save` and `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS` + `SeBackupPrivilege`. Use `--no-vss` to disable.
- **Binalyze AIR parity** — covers the full Windows acquisition profile (317+ evidence types) plus several artifacts AIR does not collect (raw MFT/USN/MBR, EventTranscript, Iconcache/Thumbcache, etc.)
- **Multi-drive support** — captures MFT from all NTFS fixed/removable volumes (C:, D:, E:, etc.)
- **Raw MFT/USN/MBR capture** — reads the Master File Table, USN journal, and MBR/GPT directly from the raw volume device using NTFS boot sector parsing
- **Optional memory** — `--include-memory` captures `pagefile.sys`, `hiberfil.sys`, and `swapfile.sys` (off by default; large)
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
ResponseRayCollector.exe [--output <path>] [--skip <collectors>] [--no-vss] [--include-memory]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output <path>` | Directory to write the output ZIP | Current directory |
| `--skip <list>` | Comma-separated collector names to skip | None |
| `--no-vss` | Skip Volume Shadow Copy creation; use Backup-API copies only | VSS enabled |
| `--include-memory` | Capture pagefile.sys, hiberfil.sys, swapfile.sys (large; gigabytes) | Disabled |

### Examples

```bash
# Collect everything, output to current directory
ResponseRayCollector.exe

# Output to a USB drive
ResponseRayCollector.exe --output E:\collections

# Skip MFT and event logs (faster collection)
ResponseRayCollector.exe --skip mft,eventlogs

# Full forensic with memory artifacts
ResponseRayCollector.exe --include-memory --output E:\collections
```

## Collectors

The tool runs 60+ collectors in sequence. Each can be skipped individually using the `--skip` flag. The list below is grouped by purpose; for the authoritative list see `Program.cs`.

### Artifact Collectors

| Collector | Skip Name | Description |
|-----------|-----------|-------------|
| EventLogs | `eventlogs` | All `.evtx` files from `%SystemRoot%\System32\winevt\Logs` |
| Registry | `registry` | System hives (SAM, SYSTEM, SOFTWARE, SECURITY) via `reg save`/VSS; user hives (NTUSER.DAT, UsrClass.dat) and Amcache.hve via VSS or backup copy |
| RegBack | `regback` | Older registry backups from `%SystemRoot%\System32\config\RegBack` |
| Hosts | `hosts` | `%SystemRoot%\System32\drivers\etc\hosts`, `lmhosts`, `networks`, `services` |
| Prefetch | `prefetch` | All `.pf` files from `%SystemRoot%\Prefetch` |
| SRUM | `srum` | `SRUDB.dat` (System Resource Usage Monitor) |
| Browser | `browser` | Chrome/Edge/Firefox/Brave/Opera/Vivaldi/Arc + IE legacy WebCacheV01.dat: history, cookies, login data, web data, bookmarks, sessions, extension manifests |
| WindowsTimeline | `windowstimeline` | `ActivitiesCache.db` per user |
| WMI | `wmi` | `OBJECTS.DATA` for WMI persistence detection |
| RecycleBin | `recyclebin` | `$I` metadata files from `$Recycle.Bin` |
| ScheduledTasks | `scheduledtasks` | Task XML files from `%SystemRoot%\System32\Tasks` |
| PowerShellHistory | `powershellhistory` | `ConsoleHost_history.txt` per user |
| LnkFiles | `lnkfiles` | `.lnk` shortcut files from user Recent folders |
| DHCP | `dhcp` | DHCP server log files (if present) |
| MFT | `mft` | Raw Master File Table from all NTFS volumes |
| NtfsMetafiles | `ntfsmetafiles` | `$Boot`, `$LogFile`, `$Secure`, `$Volume`, `$Bitmap`, `$AttrDef` |
| MBR | `mbr` | First 512 bytes (MBR/GPT) of every physical disk |
| UsnJournal | `usnjournal` | `$UsnJrnl:$J` from each NTFS volume |
| EventTranscript | `eventtranscript` | Telemetry log from `%ProgramData%\Microsoft\Diagnosis\EventTranscript` |
| RdpCache | `rdpcache` | `Cache0000.bin`, `bcache22.bmc` per user |
| QuickAssist | `quickassist` | Quick Assist log + recent connections |
| CrashDumps | `crashdumps` | Mini-dumps from `%SystemRoot%\Minidump` and per-app WER dumps |
| IconThumbCache | `iconthumbcache` | `iconcache_*.db` and `thumbcache_*.db` per user |
| EtlLogs | `etllogs` | Selected ETL traces from `%SystemRoot%\System32\WDI\LogFiles` and `WMI\Autologger` |
| ShimDb | `shimdb` | `sysmain.sdb`, `drvmain.sdb` Application Compatibility shim databases |
| WerFiles | `werfiles` | Windows Error Reporting `Report.wer` and `Queue` reports |
| DefenderLogs | `defenderlogs` | Defender quarantine, MpClient.log, MpDetours.log, signature/version dirs |
| Ntds | `ntds` | `NTDS.dit` + `edb.log` on domain controllers (VSS only) |
| ApplicationLogs | `applicationlogs` | Common app log dirs: IIS, Apache, MySQL, Exchange, Sysmon, etc. |
| ZoneIdentifier | `zoneidentifier` | `:Zone.Identifier` ADS streams from Downloads / Desktop / temp |
| MemoryArtifacts | `memoryartifacts` | `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` (only with `--include-memory`) |
| FileSystem | `filesystem` | NDJSON timeline of `$STANDARD_INFORMATION` MACB across all volumes |

### Live System State Collectors

These capture the current state of the running system as JSON files.

| Collector | Skip Name | Description |
|-----------|-----------|-------------|
| Processes | `processes` | Running processes with PID, path, command line, MD5 hash, parent PID |
| NetworkConnections | `networkconnections` | TCP/UDP connections with local/remote addresses and owning PID |
| DnsCache | `dnscache` | DNS resolver cache entries |
| DnsServers | `dnsservers` | Per-interface DNS server configuration |
| ArpCache | `arpcache` | ARP table |
| RoutingTable | `routingtable` | IP routing table |
| LogonSessions | `logonsessions` | Active logon sessions |
| UserAccounts | `useraccounts` | Local user accounts with group membership |
| Services | `services` | Windows service configuration and state |
| Drivers | `drivers` | Loaded kernel drivers (path, version, signer) |
| Antivirus | `antivirus` | Registered AV/AM products via WMI SecurityCenter2 |
| InstalledApps | `installedapps` | Installed apps from Uninstall registry keys (32 + 64-bit + per-user) |
| StoreApps | `storeapps` | Microsoft Store / UWP apps via AppX |
| StartupItems | `startupitems` | Autostart entries from registry Run keys and startup folders |
| Devices | `devices` | Attached devices (USB, PnP) |
| NetworkAdapters | `networkadapters` | Adapters with config, IPs, gateways, DHCP info |
| NetworkShares | `networkshares` | SMB shares + per-share permissions |
| WirelessHistory | `wirelesshistory` | Saved Wi-Fi profiles + interface state |
| FirewallRules | `firewallrules` | Full inbound/outbound firewall ruleset |
| VolumeShadowCopies | `volumeshadowcopies` | Enumerate persistent VSC snapshots |
| VolumeInfo | `volumeinfo` | Disks, volumes, partitions, BitLocker status |
| RestorePoints | `restorepoints` | System restore points |
| EnvironmentVariables | `environmentvariables` | System and per-user environment variables |
| DefaultBrowser | `defaultbrowser` | Default browser association |
| Proxy | `proxy` | WinHTTP and per-user WinINet proxy config |
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
- `platform` — Always `windows` for this collector (used to disambiguate from Linux/macOS/ESXi captures)
- `vss_used` — `true` if a Volume Shadow Copy was created during this run
- `vss_path` — Shadow copy device path (e.g., `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`)
- `collector_results` — Per-collector status (files collected, bytes, elapsed time, errors)
- `collected_files` — File inventory with original paths, relative paths, categories, and sizes

## How It Works

### Privilege Elevation

The collector enables `SeBackupPrivilege`, `SeManageVolumePrivilege`, `SeRestorePrivilege`, and `SeSecurityPrivilege` at startup before any collectors run. These allow reading locked files, raw volume access, and SACL inspection.

### Volume Shadow Copy

Unless `--no-vss` is supplied, the collector creates a one-shot Volume Shadow Copy of `C:\` at start (`wmic shadowcopy call create "ClientAccessible","C:\\"`). All locked-file collectors (Registry, NTDS, EventTranscript, Defender, NTUSER.DAT, etc.) automatically read from the shadow path:

```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\Windows\System32\config\SAM
```

If VSS is unavailable (e.g., the VSS service is disabled, the volume isn't snappable, or `--no-vss` was used), each collector silently falls back to:

1. `reg save` (for system hives) — captures a consistent dump via the registry API
2. `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS` + `SeBackupPrivilege` — bypasses ACLs to copy the live file

The shadow copy is automatically released at the end of the run.

### Registry Capture Strategy

System hives (SAM, SYSTEM, SOFTWARE, SECURITY) are preferentially copied from the VSS shadow. If unavailable, they fall back to `reg save`. User hives (NTUSER.DAT, UsrClass.dat) and Amcache.hve are also copied from the shadow when present, otherwise via Backup-API copy.

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
<Version>2026.4.26.1</Version>
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
