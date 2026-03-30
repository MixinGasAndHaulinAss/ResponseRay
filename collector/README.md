# ResponseRay Capture Tool

A standalone Windows artifact collection tool for digital forensics and incident response (DFIR). Designed for rapid deployment on live Windows systems, it collects forensic artifacts and live system state into a single `.zip` archive ready for upload to [ResponseRay](https://github.com/NCLGISA/ResponseRay) for automated timeline analysis.

## Features

- **Single executable** -- self-contained .NET 8 binary, no runtime installation required
- **Administrator check** -- verifies elevated privileges before collection
- **VSS snapshot** -- attempts Volume Shadow Copy for reliable access to locked files (registry hives, SRUM, $MFT), with automatic fallback to direct methods
- **Structured output** -- `manifest.json` describes every collected artifact for downstream processing
- **Modular collectors** -- each artifact type is an independent, skippable collector
- **ZIP packaging** -- final output is a single compressed archive

## Collected Artifacts

### File-Based Artifacts

| Collector | Description |
|-----------|-------------|
| EventLogs | Windows EVTX event log files from `C:\Windows\System32\winevt\Logs` |
| Registry | System and user registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT, UsrClass.dat) with `reg save` fallback |
| Prefetch | Windows Prefetch files (`.pf`) for program execution history |
| SRUM | System Resource Usage Monitor database (`SRUDB.dat`) |
| Browser | Chromium and Firefox browser history, downloads, cookies, and login databases |
| WindowsTimeline | Windows Timeline / ActivitiesCache database |
| WMIRepository | WMI persistence repository (`OBJECTS.DATA`) |
| RecycleBin | Recycle Bin `$I` metadata files for deleted file tracking |
| ScheduledTasks | Scheduled Task XML definitions |
| PowerShellHistory | PowerShell `ConsoleHost_history.txt` for all user profiles |
| LnkFiles | Windows shortcut (`.lnk`) files from Recent and Startup |
| DHCP | DHCP lease files |
| MFT | Raw Master File Table (`$MFT`) for full filesystem metadata, with filesystem enumeration fallback |

### Live System State

| Collector | Description |
|-----------|-------------|
| Processes | Running processes with PID, path, command line, parent, owner, loaded modules, hashes, and memory usage |
| NetworkConnections | Active TCP/UDP connections with owning process (via `netstat`) |
| DNSCache | Resolved DNS cache entries using native Windows API (`DnsGetCacheDataTable`) |
| ARPCache | ARP table entries via `iphlpapi.dll` P/Invoke |
| RoutingTable | IP routing table via `iphlpapi.dll` P/Invoke |
| LogonSessions | Active logon sessions via WMI (`Win32_LogonSession`) |
| UserAccounts | Local user accounts via WMI (`Win32_UserAccount`) |
| Services | Windows services with name, state, start type, path, and description |
| StartupItems | Autostart entries from registry Run/RunOnce keys, Startup folders, and Winlogon |
| Devices | Attached devices via WMI (`Win32_PnPEntity`) |
| UserAccessedData | Recent documents, jump lists, and MRU data from user profiles |
| OsConfig | OS configuration including hostname, network adapters, installed software, environment variables, and security settings |
| FileSystem | Full filesystem walk with creation, modification, access, and change (MACB) timestamps |

## Requirements

- **Windows 10/11 or Windows Server 2016+**
- **Administrator privileges** (required for VSS, registry hive export, $MFT access, and process enumeration)
- **.NET 8 SDK** (build only -- the published binary is self-contained)

## Building

```powershell
dotnet publish src/ResponseRayCollector/ResponseRayCollector.csproj `
    -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
    -o ./publish
```

The output is a single `ResponseRayCollector.exe` in the `publish/` folder.

## Usage

Run from an **elevated** (Administrator) command prompt or PowerShell:

```powershell
# Collect to the current directory
.\ResponseRayCollector.exe

# Collect to a specific output directory
.\ResponseRayCollector.exe --output D:\collections

# Skip specific collectors (comma-separated, case-insensitive)
.\ResponseRayCollector.exe --skip filesystem,browser
```

### Options

| Flag | Description |
|------|-------------|
| `--output <path>` | Directory to save the output `.zip` file (default: current directory) |
| `--skip <names>` | Comma-separated list of collector names to skip |

### Skippable Collector Names

`EventLogs`, `Registry`, `Prefetch`, `SRUM`, `Browser`, `WindowsTimeline`, `WMIRepository`, `RecycleBin`, `ScheduledTasks`, `PowerShellHistory`, `LnkFiles`, `DHCP`, `MFT`, `Processes`, `NetworkConnections`, `DNSCache`, `ARPCache`, `RoutingTable`, `LogonSessions`, `UserAccounts`, `Services`, `StartupItems`, `Devices`, `UserAccessedData`, `OsConfig`, `FileSystem`

## Output Structure

The tool produces a `.zip` archive named `<HOSTNAME>_<YYYYMMDD_HHMMSS>.zip` containing:

```
manifest.json               # Collection metadata and file inventory
artifacts/
  evtx/                     # Windows Event Log files
  registry/                 # Registry hives (SAM, SYSTEM, SOFTWARE, etc.)
  prefetch/                 # Prefetch files
  srum/                     # SRUDB.dat
  browser/                  # Browser databases
  timeline/                 # ActivitiesCache.db
  wmi/                      # OBJECTS.DATA
  recyclebin/               # $I files
  tasks/                    # Scheduled Task XML
  powershell/               # ConsoleHost_history.txt per user
  lnk/                      # Shortcut files
  dhcp/                     # DHCP lease files
mft/
  $MFT                      # Raw Master File Table (if collected)
live/
  processes.json            # Running processes
  connections.json          # Network connections
  dns_cache.json            # DNS resolver cache
  arp_cache.json            # ARP table
  routing_table.json        # IP routing table
  logon_sessions.json       # Active logon sessions
  user_accounts.json        # Local user accounts
  services.json             # Windows services
  startup_items.json        # Autostart entries
  devices.json              # Attached devices
  user_accessed_data.json   # Recent documents & MRU data
  os_config.json            # System configuration
  filesystem.jsonl          # Full MACB filesystem timeline
```

## ResponseRay Integration

Upload the `.zip` archive directly to ResponseRay. The backend worker automatically:

1. Detects `.zip` uploads from this collector
2. Extracts the archive
3. Processes file artifacts through `ct-to-timesketch` extractors (EVTX, Registry, Prefetch, SRUM, etc.)
4. Converts live system state JSON into timeline events
5. Runs CloudRules threat detection
6. Ingests all events into the database for analysis

## Architecture

```
Program.cs                     # Entry point, orchestration, ZIP packaging
Collectors/
  ICollector.cs                # Collector interface and context types
  VssManager.cs                # Volume Shadow Copy management
  EventLogCollector.cs         # EVTX collection
  RegistryCollector.cs         # Registry hive collection (VSS + reg save fallback)
  ...                          # One file per collector
Models/
  CollectionManifest.cs        # manifest.json serialization model
  LiveData.cs                  # POCOs for live system state JSON
Native/
  NativeMethods.cs             # P/Invoke declarations (iphlpapi, dnsapi)
Utils/
  ConsoleOutput.cs             # Colored console output
  FileHelper.cs                # File copy, hash, and size utilities
```

## License

Private -- Currituck County / NCLGISA
