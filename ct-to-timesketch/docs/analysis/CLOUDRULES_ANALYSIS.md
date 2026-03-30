# CloudRules Detection Analysis

> **Version**: 1.0 -- Analysis of `CloudRules_rv3160001.json.gz` (398 rules, 386 enabled)  
> **Date**: 2026-03-10  
> **Companions**: [CLOUDRULES_SPEC.md](CLOUDRULES_SPEC.md) | [CYBERTRIAGE_JSON_GZ_SPEC.md](CYBERTRIAGE_JSON_GZ_SPEC.md) | [CT_PROCESSING_PIPELINE.md](CT_PROCESSING_PIPELINE.md)  
> **Data sources**: Bundled `CloudRules_rv3160001.json.gz` + demo capture `cybertriage_evaldata_2025-11-12.json.gz`

---

## 1. Rule Inventory Summary

### Overall distribution

| Plugin | Enabled | Disabled | Sub-rules | Primary detection target |
|---|---|---|---|---|
| FileCorrelatedCloudRulePlugin_v1 | 117 | 5 | 117 | Process names, file paths, arguments, extensions |
| PowershellArgsCloudRulePlugin_v1 | 78 | 0 | 78 | PowerShell command-line tokens |
| DomainCloudRulePlugin_v1 | 50 | 7 | 57 | DNS/network connections to cloud/exfil services |
| RemoteManagementCloudRulePlugin_v1 | 45 | 0 | 45 | RMM tool binaries and install paths |
| EventsMatchingCloudRulePlugin_v1 | 38 | 0 | 38 | Windows Event Log entries (Defender, system) |
| ExecutableTypeCloudRulePlugin_v1 | 18 | 0 | 48 | Data transfer / exfiltration tool binaries |
| LibNotOnDiskCloudRulePlugin_v1 | 16 | 0 | 16 | In-memory DLLs not backed by disk files |
| MalwareDowngradeCloudRulePlugin_v1 | 11 | 0 | 11 | Score reduction for noisy analysis result types |
| AnalysisResultImpactMappingCloudRulePlugin_v1 | 2 | 0 | 95 | Human-readable impact descriptions |
| CommonBitsJobDomainCloudRulePlugin_v1 | 2 | 0 | 4 | Known-benign BITS transfer domains |
| HayabusaCloudRulePlugin_v1 | 1 | 0 | 3 | Noisy Sigma correlation rules to suppress |
| HostPortExclusionCloudRulePlugin_v1 | 1 | 0 | 2 | Known-benign host:port combinations |
| **Total** | **386** | **12** | | |

### Artifact type coverage heatmap

Which CyberTriage artifact types each plugin evaluates against:

| Artifact type | FileCorr | PsArgs | Domain | RMM | EventsMatch | ExeType | LibNotOnDisk |
|---|---|---|---|---|---|---|---|
| `PROCESS_INSTANCE` | **117** | **78** | - | - | - | **18** | - |
| `FILE` | 39 | - | - | 45 | - | 18 | - |
| `windowsEvent` | - | - | - | - | **38** | - | - |
| `STARTUP_PROGRAM` / `configItem` | 8 | - | - | 45 | - | 18 | - |
| `SERVICE` | 3 | - | - | - | - | - | - |
| `TRIGGERED_TASK` | 1 | - | - | 45 | - | 18 | - |
| `WEB_ARTIFACT` | 39 | - | - | - | - | 18 | - |
| `USER_ACCESSED_DATA` | 39 | - | - | - | - | 18 | - |
| `dnsCacheEntry` / `nwConnection` | - | - | **57** | - | - | - | - |
| Memory-loaded DLLs | - | - | - | - | - | - | **16** |

### Score distribution

| Score | Count | Meaning |
|---|---|---|
| NOTABLE | 168 | High-confidence indicator -- merits immediate analyst attention |
| LIKELY_NOTABLE | 182 | Moderate confidence -- suspicious but may have benign explanations |
| UNKNOWN | 36 | Indeterminate -- present for analyst review (primarily print processor and DLL rules) |

---

## 2. Detection Categories

Rules organized by attacker lifecycle stage, mapped to MITRE ATT&CK where applicable.

### 2.1 Lateral Movement & Remote Execution (89 rules)

**Impacket toolkit detection** -- 78 FileCorrelated rules

Each rule targets `python.exe` or `py.exe` running a specific Impacket script. Covers the full Impacket suite:

| Tool group | Example scripts | Count |
|---|---|---|
| Credential attacks | `secretsdump.py`, `mimikatz.py`, `GetNPUsers.py`, `getTGT.py` | 18 |
| Remote execution | `psexec.py`, `smbexec.py`, `wmiexec.py`, `atexec.py`, `dcomexec.py` | 12 |
| Relay/MitM | `ntlmrelayx.py`, `smbrelayserver.py`, `rawrelayserver.py` | 10 |
| Enumeration | `samrdump.py`, `rpcdump.py`, `GetADUsers.py`, `lookupsid.py` | 15 |
| Exploitation | `goldenPac.py`, `raiseChild.py`, `rbcd.py`, `keylistattack.py` | 8 |
| Utility | `smbserver.py`, `smbclient.py`, `ntfs-read.py`, `esentutl.py` | 15 |

All tagged `NOTABLE` with ATT&CK mappings to tactics TA0006 (Credential Access), TA0008 (Lateral Movement).

**ScreenConnect abuse** -- 5 FileCorrelated rules

Detects ScreenConnect's characteristic GUID-based script execution pattern:
- `powershell.exe` with args matching `[guid]run.ps1`
- `cmd.exe` with args matching `[guid]run.cmd`
- Child processes of ScreenConnect-launched shells

Tagged `LIKELY_NOTABLE` with S0591 (ConnectWise).

**SMBExec detection** -- 3 FileCorrelated rules

Detects smbexec.py remote execution artifacts:
- Services with randomized batch file arguments (`%systemroot%\[a-z]{8}.bat`)
- `cmd.exe` services matching smbexec patterns
- Default service name pattern (`BTOBTO`)

Tagged `NOTABLE` with S0357, T1569.002 (System Services: Service Execution).

**LOLBin download** -- 2 FileCorrelated rules

Detects `certutil.exe` used for file downloads:
- `-urlcache -f` (direct download)
- `-verifyctl -f` (alternate download method)

Tagged `LIKELY_NOTABLE` with T1105 (Ingress Tool Transfer), S0160 (certutil).

**Living-off-the-land tools** -- 8 BADLIST_HIT FileCorrelated rules

| Tool | fileNameNoExt | MITRE | Justification |
|---|---|---|---|
| `reg` | `reg` | T1112 | Tool to edit and view the registry |
| `wmic` | `wmic` | T1047 | Tool to manage local and remote computers |
| `winrs` | `winrs` | TA0002 | Tool to remotely run programs |
| `at` | `at` | T1053.002 | Tool to schedule tasks |
| `psexec` / `psexesvc.exe` | `psexec` | S0029 | Tool to remotely run programs |
| `rar.exe` | - | T1560.001 | Archive tool for data staging |
| `wevtutil.exe` | - | T1070.001, T1562.002 | Tool to clear/disable event logs |

### 2.2 Remote Management / Dual-Use Tools (45 rules)

Each rule detects a known RMM tool by binary name and/or install path. These are flagged because attackers frequently abuse legitimate RMM tools for persistent access.

| Tool | Binary patterns | Install path patterns |
|---|---|---|
| AnyDesk | `AnyDesk.exe` | `/ProgramData/AnyDesk/`, `/Program Files*/AnyDesk*/` |
| TeamViewer | `TeamViewer.exe`, `TeamViewer_Service.exe` | (multiple) |
| ScreenConnect | `ScreenConnect.ClientService.exe` | `/Program files*/ScreenConnect/` |
| Atera | `AteraAgent.exe` | `/Program Files*/ATERA Networks/` |
| Kaseya | `agentmon.exe`, `kserver.exe` | `/Program Files*/Kaseya/`, `/ProgramData/Kaseya/` |
| RustDesk | `rustdesk*.exe` | `/Users/*/AppData/Roaming/RustDesk/` |
| Remote Utilities | `rutclient.exe`, `rutserv.exe` | (multiple) |
| LogMeIn | `LMIIgnition.exe`, `LogMeInToolkit.exe` | `/Users/*/AppData/Local/temp/LogMeIn*/` |
| SplashTop | `SRServerSOS.exe`, `SRService.exe` | (multiple) |
| Ultra Viewer | `UltraViewer_Desktop.exe` | `/Users/*/AppData/Roaming/UltraViewer/` |
| Action1 | `action1_agent.exe` | `/Windows/Action1/` |
| DWAgent | `dwagsvc.exe`, `dwagent.exe` | `/ProgramData/DWAgent*/` |
| Zoho Assist | `agent.exe` | `/ProgramData/ZohoMeeting/` |
| mRemoteNG | `mRemoteNG.exe` | `/Users/*/AppData/*/mRemoteNG/` |
| RealVNC / TightVNC / UltraVNC | Various `vnc*.exe` | Various paths |
| Level | `level.exe` | `/Program Files*/Level/` |
| RAdmin | `Radmin.exe` | `/Windows/SysWOW64/rserver30/` |
| AmmyAdmin | `AA_v3.exe` | `/ProgramData/Ammyy/` |
| SupRemo | `Supremo.exe` | `/ProgramData/SupremoRemoteDesktop/` |
| Xeox | `xeox-agent_x64.exe` | `/Program Files/XEOX/` |
| + 25 more | | (GoToMyPC, PulseWay, NetSupport, MobaXTerm, ISL Online, etc.) |

All 45 tools are WINDOWS-only (`operatingSystemFamilies: ["WINDOWS"]`).

### 2.3 Data Exfiltration & Cloud Storage (75 rules)

**Executable-based exfil detection** -- 18 ExecutableType rules (48 match patterns)

Three-tier age-based scoring: the score changes depending on whether the file is new on an existing system, old, or on a newly-imaged system. This contextual scoring is unique to this plugin.

| Tool | Binary | Category |
|---|---|---|
| Rclone | `rclone.exe` | Cloud sync / exfiltration |
| MegaSync | `megasync.exe`, `megatools.exe` | Cloud storage |
| WinSCP | `winscp.exe` | SCP/SFTP client |
| FileZilla | `filezilla.exe`, `FileZilla server.exe` | FTP client/server |
| Dropbox | `dropbox.exe` | Cloud storage |
| Google Drive | `googledrivefs.exe` | Cloud storage |
| Box Drive | `box.exe` | Cloud storage |
| PCloud | `pcloud.exe` | Cloud storage |
| IDrive | `id_win.exe` | Cloud backup |
| SugarSync | `sugarsync.exe` | Cloud sync |
| FreeFileSync | `freefilesync.exe`, `realtimesync.exe` | File sync |
| Restic | `restic.exe` | Backup tool |
| PuTTY SCP | `pscp.exe` | SCP transfer |
| TeraCopy | `teracopy.exe` | Fast file copy |
| GoodSync | `Goodsync.exe` | Sync tool |
| Robo-FTP | `robo-ftp.exe` | FTP automation |
| IBM Aspera | `asperaconnect.exe` | High-speed transfer |
| Pandora RC | `ehorus_agent.exe` | Remote agent with file transfer |

Each tool also has path-based matching for scheduled tasks, config items, and triggered tasks (e.g., detecting Rclone configs or FileZilla session files even if the binary isn't running).

**Domain-based exfil detection** -- 57 DomainCloudRule rules (50 enabled)

Connections to these services generate `EXTERNAL_STORAGE_DOMAIN` or `EXFIL_DOMAIN` findings:

| Category | Services |
|---|---|
| Cloud storage | Dropbox, Google Drive, Box, iCloud, pCloud, MegaSync, SugarSync, IDrive, OneDrive |
| File sharing | WeTransfer, SendSpace, MediaFire, Gofile, Ufile, Filebin, Filetransfer.io, Anonfiles |
| Paste/text services | Pastebin, Pastebin.pl, Pastie.org, Termbin, Clbin, Ix.io, Sprunge, Paste.ee, Rentry.co, TextBin, ZeroBin, Ideone |
| Cloud platforms | AWS (S3), GCP (storage.googleapis.com), Azure (appdomain.cloud), DigitalOcean Spaces, Wasabi, BackBlaze B2, Linode Objects |
| Hosting/tunneling | Ngrok, Heroku, Replit, Cloudflare Workers, Cloudways, Bluehost, Hostinger, Plesk, InMotion |
| Communication | Telegram (api.telegram.org), Discord, Trello, Notion, Evernote |
| Microsoft | Graph API, Outlook attachments, Office attachments, OneNote sync |

### 2.4 PowerShell Abuse (78 rules)

**Known-malicious script detection** -- 67 rules

Token-based matching against PowerShell process arguments. Each token is the filename of a known offensive security tool:

| Category | Scripts | Count |
|---|---|---|
| Credential theft | `Invoke-Mimikatz.ps1`, `Invoke-PowerDump.ps1`, `Invoke-DCSync.ps1`, `Get-GPPPassword.ps1`, `Invoke-Kerberoast.ps1`, `dumpCredStore.ps1`, `Get-VaultCredential.ps1`, `KeeThief.ps1`, `KeePassConfig.ps1` | 14 |
| Privilege escalation | `PowerUp.ps1`, `Invoke-MS16032.ps1`, `Invoke-MS16135.ps1`, `Invoke-BypassUAC.ps1`, `Invoke-FodHelperBypass.ps1`, `Invoke-SDCLTBypass.ps1`, `Invoke-EventVwrBypass.ps1`, `Invoke-EnvBypass.ps1`, `Invoke-WScriptBypassUAC.ps1`, `Invoke-BypassUACTokenManipulation.ps1` | 11 |
| Lateral movement | `Invoke-PsExec.ps1`, `Invoke-SMBExec.ps1`, `Invoke-DCOM.ps1`, `Invoke-SSHCommand.ps1`, `Invoke-Inveigh.ps1`, `Invoke-InveighRelay.ps1` | 7 |
| Code injection | `Invoke-Shellcode.ps1`, `Invoke-ShellcodeMSIL.ps1`, `Invoke-DllInjection.ps1`, `Invoke-ReflectivePEInjection.ps1`, `Invoke-CredentialInjection.ps1`, `Invoke-TokenManipulation.ps1`, `Install-SSP.ps1` | 8 |
| Reconnaissance | `Get-Keystrokes.ps1`, `Get-USBKeystrokes.ps1`, `Get-Screenshot.ps1`, `Get-ClipboardContents.ps1`, `Get-BrowserData.ps1`, `Get-ChromeDump.ps1`, `Get-FoxDump.ps1`, `Get-SecurityPackages.ps1`, `Get-IndexedItem.ps1`, `Get-SiteListPassword.ps1` | 11 |
| Exploitation | `Exploit-EternalBlue.ps1`, `Exploit-Jenkins.ps1`, `Exploit-JBoss.ps1`, `Invoke-MetasploitPayload.ps1`, `Invoke-SQLOSCmd.ps1`, `Get-SQLQuery.ps1`, `Get-SQLColumnSampleData.ps1` | 7 |
| Persistence / exfil | `PowerBreach.ps1`, `Persistence.psm1`, `Invoke-BackdoorLNK.ps1`, `Invoke-PostExfil.ps1`, `Invoke-ExfilDataToGitHub.ps1`, `Invoke-EgressCheck.ps1`, `Invoke-NetRipper.ps1`, `Invoke-ExecuteMSBuild.ps1`, `Get-System.ps1` | 9 |
| Debug tools (suspicious) | `Invoke-Ntsd.ps1`, `ntsd_x64.exe`, `ntsd_x86.exe`, `ntsdexts_x64.dll`, `ntsdexts_x86.dll` | 5 (tagged `NOTABLE`) |

All 67 tagged `NOTABLE` / `POWERSHELL_SCRIPT_BAD_NAME`.

**Download command detection** -- 6 rules

Tokens: `invoke-webrequest`, `IWR`, `invoke-restmethod`, `IRM`, `curl`, `wget`

Tagged `LIKELY_NOTABLE` / `POWERSHELL_DOWNLOAD`.

**Defender manipulation via PowerShell** -- 5 rules

Detects PowerShell commands that modify Defender settings (Set-MpPreference exclusions, disable features). Tagged `NOTABLE`.

### 2.5 Windows Defender Tampering (38 rules)

All EventsMatching rules target the `Microsoft-Windows-Windows Defender%4Operational.evtx` log (37 rules) or the System log (1 rule).

| Event ID | Description | Detection type | Rules |
|---|---|---|---|
| 5007 | Defender configuration changed | `WINDOWS_DEFENDER_FEATURE_DISABLED`, `WINDOWS_DEFENDER_EXCLUSION_RULE`, `WIN_DEFENDER_PROTECTED_FOLDER_REMOVED` | 8 |
| 5001 | Defender real-time protection disabled | `WINDOWS_DEFENDER_FEATURE_DISABLED` | 1 |
| 1116 | Defender detected malware | `TSK_MALWARE`, `MALWARE_PREVIOUSLY_DETECTED` | 4 |
| 1006 | Defender scan found malware | `TSK_MALWARE`, `MALWARE_PREVIOUSLY_DETECTED` | 4 |
| 1015 | Defender found previously known threat | `TSK_MALWARE`, `MALWARE_PREVIOUSLY_DETECTED` | 4 |
| 1008 | Defender action failed | `WIN_DEFENDER_ACTION_FAILED` | 3 |
| 1118/1119 | Defender remediation failed | `WIN_DEFENDER_ACTION_FAILED` | 3 |
| 1009 | Quarantine file restored | `WIN_DEFENDER_QUARANTINE_FILE_RESTORED` | 3 |
| 7026 | WdFilter driver failed to load | `WDFILTER_SERVICE_NOT_RUNNING` | 1 (System log) |

28 of the 38 rules use `payload` field matching with regex against event XML data fields (e.g., `New Value`, `Threat Name`, `Action ID`). Justifications use template syntax like `${payload.Threat Name}` for dynamic enrichment.

### 2.6 File Masquerading (6 rules)

Double-extension detection via FileCorrelated rules:

- `document.pdf.exe` -- common phishing payload pattern
- `photo.jpg.scr` -- screensaver disguised as image
- `invoice.docx.bat` -- batch file disguised as document
- `report.xlsx.vbs` -- VBScript disguised as spreadsheet
- `shortcut.lnk` files with double extensions (excluding `/Recent/` folder to reduce noise)

All tagged `NOTABLE` with T1036.007 (Masquerading: Double File Extension).

### 2.7 Print Spooler Exploitation (8 rules)

FileCorrelated rules targeting print processor persistence (T1547.012):

- **Known malicious DLLs**: `DEment.dll`, `EntAppsvc.dll` -- tagged `NOTABLE` / `PRINT_PROCESSOR_BAD_NAME`
- **Signature validation**: Rules check print processor DLL signing status via sourceInfo registry key matching (`ControlSet*\Control\Print\Environments\*\Print Processors\*`)
- **Exclusion**: `winprint.dll` (legitimate Windows print processor) handled separately

### 2.8 DLL Injection / Memory Anomalies (16 rules)

LibNotOnDisk rules detect DLLs loaded in memory that don't exist on disk:

| Pattern | Purpose |
|---|---|
| `msc0ree.dll` (typo of mscoree.dll) | .NET CLR hijack |
| `kern3l32.dll` (typo of kernel32.dll) | Kernel32 impersonation |
| `ntd1l.dll` (typo of ntdll.dll) | NTDLL impersonation |
| `scriptcontrol*.dll` in system32 | Script host injection |
| `umppc*.dll` in system32 | Print driver DLL injection |
| SentinelOne agent child DLLs | Known false-positive exclusion |
| Office 16 shared DLLs (`riched20.dll`, `msptls.dll`, `mso.dll`, `aceoledb.dll`) | Known false-positive exclusion |
| Sophos AV DLLs in system32 | Known false-positive exclusion |
| Catch-all (empty pattern) | 2 rules -- flags any unmatched in-memory DLL |

### 2.9 Malware Score Tuning (11 rules)

MalwareDowngrade rules reduce the score of findings that produce excessive false positives:

| Downgraded type | Typical source |
|---|---|
| `PROCESS_PATH_NONSTD` | Processes running from non-standard paths |
| `PROCESS_PATH_SC` | Service control paths |
| `TRIGGERED_CREATION_30DAYS` | Recently created triggered tasks |
| `PORT_PROCESS_UNEXPECT` | Unexpected processes listening on ports |
| `EXE_PACKED` | Packed executables (UPX, etc.) |
| `PORT_PROCESS_PATH_NONSTD` | Non-standard path + listening port combination |
| `PROCESS_PATH_NONSTD_WITHPORT` | Non-standard path with network activity |
| `TRIGGERED_PATH_SC_UNEXPECT` | Unexpected service paths in triggered tasks |
| `TRIGGERED_PATH_NONSTD` | Non-standard triggered task paths |
| `EXE_SIGNATURE` | Unsigned executables |
| `SUSPICIOUS_FILE_NAME` | Suspicious file naming patterns |

These only apply when the artifact has already been scored `MALWARE_EXECUTABLE` by CyberTriage's built-in scoring, and the downgrade modifies the secondary analysis result to reduce noise.

### 2.10 Impact Descriptions (2 rules, 95 entries)

Lookup table mapping `analysisResultType` to human-readable impact text. Used for report generation and analyst context. Selected entries:

| Type | Impact |
|---|---|
| `ACCOUNT_COMPROMISE_DETECTED` | Attacker could be using this account. |
| `LSASS_MEM_DUMP` | Attacker may have access to password hashes for accounts on this system. |
| `RANSOM_NOTE_DETECTED` | Ransomware may have been used. Details could be in note. |
| `REMOTE_ACCESS_SOFTWARE` | Could have been used by attacker to remotely access the system. |
| `DATA_TRANSFER_TOOL` | Data could have been exfiltrated using this tool. |
| `WIN_EVENT_LOG_CLEARED` | Logging could be minimized or disabled. |
| `IMPACKET_TOOL` | Impacket allows attackers to move laterally in a network and exploit other systems. |
| `SLIVER_BINARY` | Sliver allows attackers to remotely control a host. |

Full catalog of 95 entries in [CLOUDRULES_SPEC.md Appendix A](CLOUDRULES_SPEC.md).

### 2.11 Suppressions & Exclusions (4 rules)

**Hayabusa exclusions** -- 1 rule, 3 Sigma correlation rules suppressed:

| GUID | Rule suppressed |
|---|---|
| `49d15187-4203-4e11-8acd-8736f25b6608` | `Sec_4648_Med_ExplicitLogon_PW-Spray_Correlation.yml` |
| `0ae09af3-f30f-47c2-a31c-83e0b918eeee` | `Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml` |
| `23179f25-6fce-4827-bae1-b219deaf563e` | `Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml` |

These Sigma rules produce excessive false positives in normal enterprise environments.

**HostPort exclusions** -- 1 rule, 2 entries:

| Host pattern | Port | Reason |
|---|---|---|
| `.*\.eset\.com$` | 8883 | ESET antivirus MQTT telemetry |
| `.*\.1e100\.net$` | 5228 | Google push notification service |

**CommonBitsJobDomain exclusions** -- 2 rules, 4 domains:

| Domain pattern | Purpose |
|---|---|
| `(\w+\.)*adobe\.com$` | Adobe Update Service |
| `(\w+\.)*live\.com$` | Microsoft Live services |
| `(\w+\.)*gvt1\.com$` | Google update services |
| `(\w+\.)*microsoft\.com$` | Microsoft services |

---

## 3. Evaldata Simulation Results

Simulation of all 386 enabled CloudRules against the bundled demo capture `cybertriage_evaldata_2025-11-12.json.gz`.

### Capture profile

| Metric | Value |
|---|---|
| Hostname | Engineering-Comp3 |
| OS | Windows 10 Pro (19043) |
| Domain | ACME |
| User | jdoe |
| Agent version | 3.9.0 |
| Install date | 2019-08-22 |
| Collection date | 2025-11-12 |
| Total artifacts | 142,641 |

### Artifact breakdown

| Section type | Count | CloudRule plugins that evaluate it |
|---|---|---|
| `file` | 135,907 | FileCorrelated, ExecutableType, RMM |
| `process` | 2,300 | FileCorrelated, PowershellArgs, ExecutableType |
| `progress` | 1,561 | (none -- internal status) |
| `windowsEvent` | 1,309 | EventsMatching |
| `configItem` | 1,158 | FileCorrelated (STARTUP_PROGRAM, SERVICE), RMM |
| `nwConnectionDescriptor` | 170 | HostPortExclusion |
| `dnsCacheEntry` | 122 | DomainCloudRule |
| `userAccessedData` | 38 | FileCorrelated, ExecutableType |
| `attachedDevice` | 27 | (none) |
| `osConfigSetting` | 22 | (none) |
| `logonData` | 7 | (none) |
| Other (volume, imageInfo, etc.) | 18 | (none) |

### Simulation results by plugin

**FileCorrelated** -- 0 true matches

The demo system is clean. No Impacket tools, PsExec, ScreenConnect artifacts, certutil downloads, or double-extension files present. LOLBin tools like `wmic` exist but have no malicious arguments.

Note: the `fileNameNoExt` matching for BADLIST_HIT rules (e.g., `reg`, `wmic`) would flag these tools IF a proper evaluation engine also checked the presence of matching `dataTypes`. In isolation, `wmic.exe` running without suspicious arguments is not flagged -- the rules use `fileNameNoExt` matching, which means the engine must strip the extension before comparing.

**PowershellArgs** -- 0 matches

No PowerShell processes in the evaldata have command-line arguments containing known-malicious script names or download commands.

**EventsMatching** -- 0 matches (disjoint event IDs)

| Evaldata event IDs | CloudRules target event IDs |
|---|---|
| 4624 (217), 1024 (218), 1029 (218), 1102 (217), 21 (217), 24 (216), 4625 (6) | 1006, 1008, 1009, 1015, 1116, 1118, 1119, 5001, 5007, 7026 |

Zero overlap. The evaldata contains standard logon/session events. The CloudRules target Defender operational events. This confirms the demo system has no malware detection or Defender tampering events.

**DomainCloudRule** -- 0 matches

122 DNS cache entries checked against 57 domain patterns. The evaldata domains (googleapis.com, microsoft.com, slack, akamai, etc.) are standard enterprise traffic. No connections to exfiltration services, paste sites, or cloud storage APIs.

**RemoteManagementCloudRule** -- 0 true matches

The simulation produced 29 false positive hits from the Zoho Assist rule, which matches `fileNameNoExt: "agent"` -- this incorrectly matched `default-browser-agent.exe` (Firefox's default browser agent). This is a known limitation: the Zoho rule's `fileNameNoExt` pattern is not anchored, so any process containing "agent" in its name would match without additional path validation. A correct implementation must apply the full match criteria (both `matchesPath` patterns, including the install path check at `/ProgramData/ZohoMeeting/`).

**ExecutableType** -- 0 matches

No data transfer tools (Rclone, WinSCP, FileZilla, etc.) present on the demo system.

**LibNotOnDisk** -- Not simulatable

Requires memory forensics data (loaded DLL lists vs. disk-backed files), which the demo capture's extracted process data doesn't include.

### Key insight

The evaldata is a benign corporate workstation. All CloudRule plugins returned zero true matches, which is the expected result for a clean system. In a live incident, the following would trigger:

- An attacker using `secretsdump.py` would trigger Impacket rules (NOTABLE)
- Rclone or MegaSync for data staging would trigger ExecutableType rules
- DNS connections to Pastebin, Ngrok, or Telegram would trigger Domain rules
- `Set-MpPreference -DisableRealtimeMonitoring` would trigger PowerShell and EventsMatching rules
- AnyDesk or ScreenConnect installed for persistence would trigger RMM rules

---

## 4. Practical Evaluation Flow

### Example A: Benign process from evaldata

**Input artifact** (from evaldata `process` section):

```json
{
  "name": "cmd.exe",
  "path": "/windows/SysWOW64/cmd.exe",
  "observationType": "LocalTrace",
  "userID": "jdoe",
  "userSID": "S-1-5-21-928528450-1818286067-2342123972-1006",
  "extractor": "CollectionTool"
}
```

**Evaluation walkthrough:**

1. **FileCorrelated** (117 rules):
   - Rule: BADLIST_HIT `fileName: ^\Qcmd.exe\E$` -- No such rule exists (cmd.exe is not in fileName patterns)
   - Rule: smbexec `fileName: ^\Qcmd.exe\E$` + `dataTypes: SERVICE` -- `cmd.exe` matches fileName, but artifact is `PROCESS_INSTANCE`, not `SERVICE`. **Skip.**
   - Rule: ScreenConnect parent process -- no parentProcess data available. **Skip.**
   - Rule: DOUBLE_FILE_EXTENSION via arguments -- `cmd.exe` has no args. **Skip.**
   - **Result: No match.** `cmd.exe` without suspicious arguments or service context is benign.

2. **PowershellArgs** (78 rules):
   - Process name is `cmd.exe`, not PowerShell. **Skip entire plugin.**

3. **ExecutableType** (18 rules):
   - No rules match `cmd.exe`. **Skip.**

4. **RemoteManagement** (45 rules):
   - No RMM tool matches `cmd.exe`. **Skip.**

**Final result: 0 enrichments.** The process passes through unchanged.

### Example B: Hypothetical malicious artifact

**Input artifact** (hypothetical -- attacker running Mimikatz via PowerShell):

```json
{
  "name": "powershell.exe",
  "path": "/windows/system32/windowspowershell/v1.0/powershell.exe",
  "args": "-nop -w hidden -ep bypass Invoke-Mimikatz.ps1 -DumpCreds",
  "observationType": "ProcessTrace",
  "userID": "admin",
  "extractor": "CollectionTool"
}
```

**Evaluation walkthrough:**

1. **FileCorrelated** (117 rules):
   - None of the fileName/fileNameNoExt rules target `powershell.exe` directly (except ScreenConnect which requires GUID args). **No match.**

2. **PowershellArgs** (78 rules):
   - Token scan: `"Invoke-Mimikatz.ps1"` found in args
   - **MATCH:** `POWERSHELL_SCRIPT_BAD_NAME` / `NOTABLE`
   - Justification: process arguments contain known malicious PowerShell script name
   - MITRE: (none tagged on this specific rule, but maps to TA0006 Credential Access)

3. **ExecutableType**: Not relevant. **Skip.**

4. **RemoteManagement**: Not an RMM tool. **Skip.**

**Final result: 1 enrichment.**

```
cloudrules_match: true
cloudrules_score: NOTABLE
cloudrules_type: POWERSHELL_SCRIPT_BAD_NAME
cloudrules_justification: "process arguments contain known malicious PowerShell script name"
cloudrules_plugin: PowershellArgsCloudRulePlugin_v1
```

### Example C: Hypothetical exfiltration

**Input artifact** (hypothetical -- Rclone detected as file + process):

```json
{
  "name": "rclone.exe",
  "path": "/users/admin/downloads/rclone.exe",
  "args": "copy C:\\Users\\admin\\Documents remote:exfil-bucket --transfers 16",
  "observationType": "ProcessTrace"
}
```

**Evaluation walkthrough:**

1. **FileCorrelated**: No rules target `rclone.exe` by fileName. **No match.**

2. **PowershellArgs**: Not PowerShell. **Skip.**

3. **ExecutableType**:
   - Rule: Rclone `fileName: rclone.exe`, `dataTypes: PROCESS_INSTANCE` -- **MATCH**
   - Three-tier scoring:
     - System age > 30 days AND file is new? -> `DATA_TRANSFER_TOOL` / `NOTABLE`
     - System age > 30 days AND file is old? -> `DATA_TRANSFER_TOOL` / `LIKELY_NOTABLE`
     - System age <= 30 days? -> `DATA_TRANSFER_TOOL` / `LIKELY_NOTABLE`
   - Additionally, `args` contain `--transfers` which may match Rclone-specific FileCorrelated rules for `RCLONE_ARGS_EXFIL` (if present in future CloudRules revisions)

4. **RemoteManagement**: Not an RMM tool. **Skip.**

**Final result: 1 enrichment** (potentially 2 with Rclone-specific args rules).

---

## 5. Field Availability Matrix

Cross-reference of CloudRule match criteria against CyberTriage artifact fields, indicating which fields are available in the `ct-to-timesketch` converter.Event structure and which have gaps.

### Available fields (already extracted by ct-to-timesketch)

| CloudRule match field | Converter Event field | Used by plugin(s) |
|---|---|---|
| `fileName` | `filename` | FileCorrelated, ExecutableType, RMM |
| `fileNameNoExt` | Derived from `filename` | FileCorrelated, RMM |
| `path` | `filepath` | FileCorrelated, RMM |
| `arguments` / `args` | `extra.args` | FileCorrelated, PowershellArgs |
| `dataTypes` | `data_type` | FileCorrelated, ExecutableType |
| `eventIds` / `eventID` | `event_id` | EventsMatching |
| `logFileName` | `source` (evtx file path) | EventsMatching |
| `payload.*` | `extra.*` (event XML fields) | EventsMatching |
| `remoteHostName` | `domain` / `remote_host` | DomainCloudRule |
| Process name | `process_name` | PowershellArgs |
| Timestamps | `datetime` | (all plugins, for age calculation) |
| `sources.sourceType` | `source_type` | FileCorrelated (print processor rules) |
| `sources.keyName` | `registry_key` | FileCorrelated (print processor rules) |

### Gap fields (not yet extracted, needed for full CloudRules coverage)

| Missing field | Required by | Priority | Remediation |
|---|---|---|---|
| `fileSignedStatus` | FileCorrelated (6 print processor rules) | Medium | Extract `fileSignedStatus` from artifact JSON |
| OS install date / system age | ExecutableType (18 rules, 48 match patterns) | **High** | Derive from `imageInfo` section's `winInstallDate` field |
| `parentProcess` path + args | FileCorrelated (2 ScreenConnect rules) | Medium | Extract parent process correlation from process tree |
| DLL paths from memory analysis | LibNotOnDisk (16 rules) | Low | Only applicable when memory forensics data is present |
| BITS job domain | CommonBitsJobDomain (2 rules) | Low | Only applicable to BITS-specific events |
| `fileNameNoExt` extension stripping | FileCorrelated, RMM (many rules) | **High** | Implement in evaluation engine (trivial string operation) |

### MITRE ATT&CK coverage

24 unique ATT&CK references across all rules:

| ID | Name | Rules using it |
|---|---|---|
| T1036.007 | Masquerading: Double File Extension | 6 |
| T1047 | WMI | 2 (wmic BADLIST) |
| T1053.002 | Scheduled Task/Job: At | 1 |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | 1 (wevtutil) |
| T1105 | Ingress Tool Transfer | 2 (certutil) |
| T1112 | Modify Registry | 2 (reg) |
| T1547.012 | Boot/Logon Autostart: Print Processors | 8 |
| T1560.001 | Archive Collected Data: Archive via Utility | 1 (rar.exe) |
| T1562.001 | Impair Defenses: Disable or Modify Tools | ~15 (Defender rules) |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | 1 |
| T1567 | Exfiltration Over Web Service | 57 (all Domain rules) |
| T1569.002 | System Services: Service Execution | 3 (smbexec) |
| S0029 | PsExec | 3 |
| S0160 | certutil | 2 |
| S0357 | Impacket | 3 (smbexec) |
| S0591 | ConnectWise (ScreenConnect) | 5 |
| TA0001-TA0010 | Tactic-level references | 8 (on Impacket rules) |

---

## 6. Summary

The CloudRules rv3160001 rule set provides **386 active detection rules** organized into a layered defense covering the full attack lifecycle:

1. **Initial access indicators**: Double-extension files, LOLBin downloads, ScreenConnect exploitation
2. **Execution**: PowerShell malicious scripts (67 offensive tools), Impacket suite (78 tools), WMI/WinRS lateral movement
3. **Persistence**: Print processor DLL manipulation, RMM tool installation (45 tools)
4. **Defense evasion**: Defender feature disabling, exclusion rules, event log clearing, malware score downgrading
5. **Credential access**: Mimikatz, Kerberoasting, LSASS dumps (via PowerShell script detection)
6. **Exfiltration**: 18 data transfer tools + 57 cloud/paste/file-sharing domains
7. **Memory forensics**: 16 DLL injection/typosquatting patterns

For the `ct-to-timesketch` integration, the highest-impact plugins to implement first are:

1. **FileCorrelated** -- Covers the most ground with 117 rules across processes, files, and services
2. **PowershellArgs** -- Simple token matching, high-value detections, 78 rules
3. **EventsMatching** -- Critical for Defender tampering detection, 38 rules
4. **DomainCloudRule** -- Easy DNS lookup matching, 57 exfiltration indicators
5. **ExecutableType** -- Data transfer tool detection with contextual scoring, 18 rules
6. **RemoteManagement** -- RMM tool inventory, 45 rules

The remaining plugins (LibNotOnDisk, MalwareDowngrade, ImpactMapping, Hayabusa, HostPort, CommonBits) provide supporting context but are lower priority for initial implementation.
