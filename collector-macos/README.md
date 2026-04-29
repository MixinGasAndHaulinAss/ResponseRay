# ResponseRay macOS Collector

A standalone macOS forensic artifact collector. Produces a `tar.gz` archive with the same `manifest.json` schema as the Windows and Linux collectors, ready for upload to the [ResponseRay](https://github.com/NCLGISA/ResponseRay) platform.

**Current version:** `2026.4.29.1`

## Key Design Principles

- **Single static binary** — Go 1.22 produces one self-contained executable. The default ResponseRay build targets Apple Silicon (`darwin/arm64`); Intel (`darwin/amd64`) and Universal 2 builds via `lipo` are documented below.
- **In-OS capture (no raw imaging)** — uses `dscl`, `system_profiler`, `log show`, plist + SQLite copies, `sysctl`, `ioreg`. Never reads raw disks. This works on T2/Apple Silicon hosts where direct disk access is restricted by SIP.
- **Comprehensive macOS coverage** — 216+ evidence types including unified logs, ASL, launchd, login items, KnowledgeC, TCC, FSEvents, Quarantine events, Time Machine, Wireless history, Mail, Messages, browsers, and more
- **TCC-aware** — when granted Full Disk Access, captures user-space TCC.db, KnowledgeC.db, Messages chat.db; without FDA, gracefully skips and reports the missing categories in the manifest
- **Optional memory** — `--include-memory` captures `sleepimage` and `swapfile*` (off by default; large)
- **Minimal footprint** — collects to `/var/tmp`, compresses to a single `tar.gz`, cleans up after itself

## Requirements

- **root** — required for system files; user TCC-protected files additionally require Full Disk Access for the parent terminal
- **macOS 11 (Big Sur) or later** — uses unified logs (`log show`) and modern Background Items DB (`backgrounditems.btm` on macOS 13+)
- **Go 1.22+** for building

## Quick Start

```bash
sudo ./responseray-collector-macos
```

The collector will:

1. Verify it is running as root and warn if not
2. Run all 32 collectors in sequence
3. Package everything into `/var/tmp/ResponseRay_<host>_<ts>.tar.gz`
4. Clean up its temp directory

Upload the `.tar.gz` through the ResponseRay web UI.

## Granting Full Disk Access

For complete coverage of TCC-protected paths (user `Library/Mail`, `Messages`, `Knowledge`, `Safari/History.db`, `Cookies.binarycookies`, etc.), grant Full Disk Access to the parent terminal:

1. **System Settings → Privacy & Security → Full Disk Access**
2. Click **+** and add **Terminal.app** (or iTerm/Ghostty/whatever you use)
3. Quit & relaunch the terminal, then run the collector

If FDA is not granted, the collector still completes successfully but skips protected paths and records `0 files` for those collector entries in the manifest.

## Command Line Options

```
responseray-collector-macos [--output <dir>] [--skip <list>] [--include-memory]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output <dir>` | Directory to write the output archive | `/var/tmp/<host>-<ts>` |
| `--skip <list>` | Comma-separated collector names to skip (case-insensitive) | None |
| `--include-memory` | Capture sleepimage + swapfiles (large) | Disabled |

### Examples

```bash
sudo ./responseray-collector-macos

sudo ./responseray-collector-macos --output /Volumes/USB

sudo ./responseray-collector-macos --skip Browsers,Mail
```

## Collectors

| Collector | Description |
|-----------|-------------|
| `SystemInfo` | `sw_vers`, `uname -a`, `system_profiler` (SPHardware/SPSoftware), `sysctl kern.*`, `ioreg`, `csrutil status`, `spctl --status`, `fdesetup status` |
| `Users` | `dscl . list /Users`, `dscl . readall /Users`, `last`, `who`, `groups`, `dscacheutil -q user` |
| `UnifiedLogs` | `/var/db/diagnostics`, `/var/db/uuidtext`, `log show --last 24h` filtered to security-interesting events, `log stats` |
| `LegacyLogs` | `/var/log/system.log*`, `install.log`, `secure.log`, `wifi.log`, `appfirewall.log`, `apache2/`, `cups/` |
| `ASLLogs` | `/var/log/asl/*.{asl,asldb}`, `syslog -d 1` recent events |
| `ShellHistory` | `.bash_history`, `.zsh_history`, `.sh_history`, `.python_history`, etc. per user (incl. `/var/root`) |
| `SSH` | `/etc/ssh/{sshd_config,ssh_config,sshd_config.d/*}`, per-user `~/.ssh/{authorized_keys,known_hosts,config,*.pub}` |
| `LaunchAgentsDaemons` | `/Library/Launch{Agents,Daemons}`, `/System/Library/Launch{Agents,Daemons}`, per-user `~/Library/LaunchAgents`, `launchctl list`, `launchctl print system` |
| `LoginItems` | `backgrounditems.btm` (macOS 13+), legacy `com.apple.loginitems.plist`, `sfltool dumpbtm`, `osascript` login item names |
| `Persistence` | cron tabs, periodic, at jobs, `/etc/{rc.common,rc.local,launchd.conf,profile,zshrc,bashrc}`, per-user shell init files, `Info.plist` of every kext + system extension |
| `NetworkLive` | `ifconfig`, `netstat -an/-rn/-s`, `arp -a`, `ndp -an`, `scutil --dns/--proxy`, `networksetup -listall*`, `lsof -i`, `smbutil view`, `/etc/{hosts,resolv.conf,services}`, DHCP leases |
| `Firewall` | `pfctl -s all/rules/info`, `socketfilterfw --getglobalstate/--listapps`, `/etc/pf.conf`, `/etc/pf.anchors`, `com.apple.alf.plist` |
| `Processes` | `ps auxwwe`, `lsof -n -P`, `top -l 1 -n 0`, `vm_stat`, `fs_usage` 5s sample |
| `Kernel` | `kextstat -l`, `systemextensionsctl list`, `sysctl -a`, `nvram -p` |
| `Mounts` | `mount`, `df -h/-i`, `diskutil list/info -all/apfs list` |
| `Applications` | `Info.plist` of every app under `/Applications`, `/System/Applications`, and per-user `~/Applications`; `system_profiler SPApplicationsDataType` and `SPInstallHistoryDataType`; `pkgutil --pkgs` |
| `Browsers` | Safari (History.db, Bookmarks, Downloads, TopSites, LastSession, Extensions.plist, CloudTabs, Cookies.binarycookies); Chrome / Chromium / Edge / Brave / Opera / Vivaldi / Arc / Yandex (History, Cookies, Login Data, Web Data, Bookmarks, Preferences, Sessions); Firefox (places, cookies, formhistory, logins, key4.db, prefs.js, extensions, sessionstore) |
| `Mail` | `~/Library/Mail/V*/Envelope Index*`, `Mailboxes.plist`, `SmartMailboxes.plist`, `Rules.plist`, `Signatures.plist`, container preferences |
| `Messages` | `~/Library/Messages/chat.db{,-wal,-shm}`, `Attachments/` (capped) |
| `Quarantine` | `com.apple.LaunchServices.QuarantineEventsV2{,-shm,-wal}` per user |
| `KnowledgeC` | System `knowledgeC.db` (CoreDuet) and per-user `~/Library/Application Support/Knowledge/knowledgeC.db` |
| `TCC` | System `/Library/Application Support/com.apple.TCC/TCC.db` and per-user TCC.db |
| `CrashReports` | System `/Library/Logs/DiagnosticReports/*.{ips,crash,diag,panic,spin,hang}` and per-user reports |
| `InstallHistory` | `/Library/Receipts/InstallHistory.plist`, `/var/db/receipts/*.{bom,plist}`, `softwareupdate --history` |
| `TimeMachine` | `tmutil status/destinationinfo/listbackups/latestbackup`, `com.apple.TimeMachine.plist` |
| `Wireless` | `com.apple.airport.preferences.plist`, `com.apple.wifi.message-tracer.plist`, NetworkInterfaces.plist, `airport -I/-s` |
| `RecentItems` | `com.apple.recentitems.plist`, `com.apple.spotlight.*`, `com.apple.dock.plist`, `com.apple.finder.plist`, sharedfilelist `*.sfl2/*.sfl3` |
| `Spotlight` | `mdutil -sav` status |
| `FSEvents` | `/.fseventsd/*` (file system event log) |
| `Auditd` | `/etc/security/audit_*`, `/var/audit/*`, `praudit -l /var/audit/current` |
| `FileSystemEnum` | NDJSON timeline of `/Applications`, `/Library`, `/private/etc`, `/usr/local/bin`, per-user homes (excluding caches and `/private/var/folders`) with full MACB + birthtime |
| `MemoryArtifacts` | `/private/var/vm/sleepimage`, `swapfile*` (only with `--include-memory`) |

## Output Format

Same schema as the Windows and Linux collectors. The `manifest.json` includes a `"platform": "macos"` field so the backend can route platform-specific extractors.

## Server-side raw artifact parsing

As of `2026.4.29.1`, the ResponseRay backend parses macOS raw artifacts in-process (rather than just hashing/preserving them on the timeline). The native parser lives at `backend/internal/collectoringest/macos/` and runs automatically when an upload's manifest declares `"platform": "macos"`.

| Captured artifact | Parser | Event types emitted |
|-------------------|--------|---------------------|
| `artifacts/tcc/{system,users/<u>}/TCC.db` | `tcc.go` | `tcc_grant` (one per `access` row) |
| `artifacts/quarantine/<u>/QuarantineEventsV2` | `quarantine.go` | `file_downloaded` (one per `LSQuarantineEvent` row) |
| `artifacts/knowledgec/{system,users/<u>}/knowledgeC.db` | `knowledgec.go` | `application_usage`, `application_focus`, `device_locked`, `device_unlocked`, `display_on`, `display_off`, `battery_level`, `web_history`, `app_intent`, `app_activity`, `web_usage` |
| `artifacts/browsers/<browser>/<u>/{History,Cookies,Login Data}` | `browsers.go` | `web_history`, `web_download`, `web_cookie`, `web_login` (Chromium family) |
| `artifacts/browsers/safari/<u>/History.db` | `browsers.go` | `web_history` |
| `artifacts/browsers/firefox/<u>/{places,cookies,formhistory,downloads}.sqlite` | `browsers.go` | `web_history`, `web_cookie`, `form_history`, `web_download` |
| `artifacts/launch/{...,users/<u>/...}/*.plist` | `launchd.go` | `startup_item` with parsed `Label`, `ProgramArguments`, `RunAtLoad`, `KeepAlive`, `StartInterval`, `StartCalendarInterval`, `WatchPaths`, etc. |
| `artifacts/unified_logs/` (`.tracev3` archive) | `unifiedlog.go` | `os_log` per record via the bundled `unifiedlog_iterator` Rust binary (parses the *full* on-disk archive, not just the 24h `log show` snapshot, so events older than 7 days are preserved) |

The Go SQLite reading uses `modernc.org/sqlite` (pure Go, no cgo) so the worker stays statically linked. Plist decoding uses `howett.net/plist` and handles both binary (bplist00) and XML formats.

### Raw application logs

The macOS collector now also captures raw text logs from the apps the [Binalyze macOS collections KB](https://kb.binalyze.com/air/features/acquisition/supported-evidence/macos-collections) calls out as missing in their default profile:

- Homebrew (`/usr/local/var/log`, `/opt/homebrew/var/log`, `/opt/homebrew/Library/Logs`)
- MySQL (`/usr/local/var/mysql/*.log`, `*.err`)
- PostgreSQL (`/usr/local/var/postgres/log/`, `pg_log/`)
- NGINX (`/usr/local/var/log/nginx`, `/opt/homebrew/var/log/nginx`)
- MongoDB (`/usr/local/var/log/mongodb`, `/opt/homebrew/var/log/mongodb`)
- Apache (`/var/log/apache2`)
- AnyDesk (`/Library/Application Support/AnyDesk`, `~/Library/Application Support/AnyDesk`)
- TeamViewer (`/Library/Application Support/TeamViewer`, `~/Library/Application Support/TeamViewer`)
- Sophos (`/Library/Application Support/Sophos`)
- Splashtop (`/Library/Application Support/Splashtop`, `~/Library/Application Support/Splashtop`)
- Parallels (`/Library/Application Support/Parallels`, `~/Library/Application Support/Parallels`)
- Discord (`~/Library/Application Support/discord/logs`)
- Docker Desktop (`~/Library/Containers/com.docker.docker/Data/log`, `~/Library/Logs/Docker`)
- All of `/private/var/log` (system-wide pf, install, secure, daily/weekly/monthly, ...)

## Building

### For Apple Silicon (arm64)

```bash
cd collector-macos
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '-s -w' \
  -o responseray-collector-macos-arm64 ./cmd/responseray-collector-macos
```

### For Intel (amd64)

```bash
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-s -w' \
  -o responseray-collector-macos-amd64 ./cmd/responseray-collector-macos
```

### Universal binary (both archs in one)

```bash
lipo -create -output responseray-collector-macos \
  responseray-collector-macos-arm64 responseray-collector-macos-amd64
```

### Code signing (recommended for distribution)

```bash
codesign --force --options runtime --sign "Developer ID Application: ..." \
  responseray-collector-macos
```

## Compatibility

| macOS | Status |
|-------|--------|
| 14 Sonoma | Tested |
| 13 Ventura | Tested |
| 12 Monterey | Tested |
| 11 Big Sur | Tested |
| 10.15 Catalina | Expected to work (older Background Items API used) |

## License

Internal use — Currituck County, NC.
