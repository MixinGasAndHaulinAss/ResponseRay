# CyberTriage Processing Pipeline

> **Version**: 1.0 -- Analysis of CT 3.16.0 installation on CyberTriageSrv  
> **Date**: 2026-03-10  
> **Source of Truth**: CyberTriageSrv file system via Tendril + decompiled `com-basistech-df-cyberTriage-core.jar`  
> **Companions**: [CYBERTRIAGE_JSON_GZ_SPEC.md](CYBERTRIAGE_JSON_GZ_SPEC.md), [CLOUDRULES_SPEC.md](CLOUDRULES_SPEC.md), [CLOUDRULES_ANALYSIS.md](CLOUDRULES_ANALYSIS.md)

---

## 1. Architecture Overview

### 1.1 Processing Components

CyberTriage bundles 16 processing components beyond its core Java application, all installed at `C:\Program Files\Cyber Triage\cybertriage\`:

| Component | Binary | Size | Purpose |
|---|---|---|---|
| Volatility | `volatility-a438e76.exe` | 20.2 MB | Memory forensics (RAM dump analysis) |
| MemProcFS | `memprocfs_packager.exe` + `vmm.dll` | 3.2 MB + 2.4 MB | Memory process filesystem + in-memory YARA |
| YARA | `CyberTriageYara.exe` + `yarac64.exe` | 2.3 MB | File-based malware signature scanning |
| YARA rules | 4 precompiled rule sets | (binary) | Targeted malware detection |
| Hayabusa | `hayabusa.exe` + `encoded_rules.yml` | 11.5 MB + 9.1 MB | Sigma-based EVTX log analysis |
| EVTX tools | `evtexport.exe`, `evtx_dump-v0.9.0.exe` | 2.0 MB | Event log parsing (legacy + modern) |
| BITS parser | `BitsParser_0a2b51e.exe` | 8.4 MB | Background Intelligent Transfer Service jobs |
| WMI persistence | `collectWMIPersistence.exe` | 7.9 MB | WMI event subscription detection |
| ESE DB | `esedbexport_16d65f0.exe` | 543 KB | Extensible Storage Engine extraction |
| Pasco2 | `pasco2-1.0.0.jar` | (Java) | Internet Explorer cache/history |
| Search engine | `SEUQAMappings.xml` | (XML) | Browser URL query extraction |
| GeoLite2 | `GeoLite2-Country.mmdb` | (binary) | MaxMind IP geolocation |
| CloudRules | `CloudRules_rv3160001.json.gz` | 27 KB | Rule-based threat intelligence |
| Autopsy plugin | `cybertriage_importer_1.0.5.nbm` | 18 MB | Autopsy integration for CT data import |
| Collectors | 5 variants (Libs, NoLibs, UAC, Vista, XP) | 1.3-9.4 MB | Windows agent data collection |
| Credential Mgr | `CredentialUpdateManager.exe` | - | License and credential management |

All binaries share a build date of 2026-01-14 (CT 3.16.0 release).

### 1.2 Data Flow

```
Target System                    CyberTriage Server                         Output
=============                    ==================                         ======

  Collector Agent  --json.gz-->  StreamingJSONParser
  (live system)                        |
                                       +--> Phase 1 (filesystem, registry, processes)
                                       |       |
                                       |       +--> BufferedItemIngestConsumer
                                       |       +--> SessionMalwareScanManager.createReputationTask()
                                       |
                                       +--> Phase 2 (full file scan, EVTX, memory)
                                               |
                                               +--> BufferedItemIngestConsumer.buildPipeline()
                                               +--> SessionMalwareScanManager (hash + upload + imphash)
                                               |
                                               +--> External Tool Pipeline:
                                                      |
                                                      +--> YARA scan (CyberTriageYara.exe)
                                                      +--> Hayabusa (hayabusa.exe on EVTX files)
                                                      +--> EVTX parsing (evtx_dump / evtexport)
                                                      +--> BITS parsing (BitsParser)
                                                      +--> WMI persistence (collectWMIPersistence)
                                                      +--> ESE DB extraction (esedbexport)
                                                      +--> GeoIP lookup (GeoLite2)
                                                      |
                                                      +--> CloudRules evaluation (12 plugins)
                                                      |
                                                      +--> Analysis Results --> PostgreSQL
                                                                               --> JSON Report
                                                                               --> Autopsy Import

  Memory Image  --optional-->  Memory Forensics Pipeline:
  (RAM dump)                         |
                                     +--> MemProcFS (memprocfs_packager.exe)
                                     |       +--> vmmyara.dll (in-memory YARA)
                                     |       +--> Artifact extraction --> json.gz format
                                     |
                                     +--> Volatility (volatility-a438e76.exe)
                                             +--> CTJSONGenerator.java wraps output
                                             +--> extractor: "Volatility", sourceType: "Memory"
```

### 1.3 Two-Phase Processing Model

The `StreamingJSONParser` processes the json.gz agent output in two distinct phases, separated by `cyberTriageOutputSection` boundaries:

**Phase 1** -- Filesystem and registry artifacts:
- File metadata, registry keys, user accounts, startup programs, scheduled tasks
- Triggered by the first `cyberTriageOutputSection` array
- Calls `SessionMalwareScanManager.createReputationTask()` for initial reputation lookups
- If `skip_full_scan: "yes"`, Phase 2 is marked `NOT_REQUESTED`

**Phase 2** -- Full scan with file content:
- File content (base64-encoded), EVTX logs, process details, network connections
- Calls `buildPipeline()` to initialize the full analysis pipeline
- Initiates malware scan with file content upload and import hash queries:

```java
SessionMalwareScanManager.get().initSessionMalwareScanAttemptCount(
    collectionId,
    skipFullScan ? 1 : 2,                                    // scan attempts
    collection.isFileContentUploadRequested() ? (count) : 0,  // upload attempts
    collection.isQueryImpHash() ? (count) : 0                 // imphash queries
);
```

### 1.4 Malware Scan Orchestration

`SessionMalwareScanManager` coordinates three tiers of malware analysis:

| Tier | Method | Condition | Output |
|---|---|---|---|
| 1 | Reputation lookup | Always (when `isExternalScanRequested`) | Hash match against Basis Technology cloud |
| 2 | File content upload | When `isFileContentUploadRequested` | Cloud-side analysis of unknown files |
| 3 | Import hash query | When `isQueryImpHash` | PE import hash correlation |

Results surface as `TSK_MALWARE`, `TSK_HASH_HIT`, or `MALWARE_EXECUTABLE` in `analysisResultType`, with severity scores stored in `malwareAttacksScore` and signature details in `malwareAttacksSignature` (from `JsonReportWriter.java`).

---

## 2. Defender / Malware Integration

For **artifact-based** Defender analysis (EVTX logs, registry, services), CyberTriage captures Defender state through multiple indirect channels that are reassembled server-side. For **direct API integration** with Microsoft Defender for Endpoint (MDE) via Microsoft Graph, see **Section 10**.

### 2.1 Data Capture Channels

```
Target System (Defender Data Sources)          CT Processing
=========================================     =============

  Defender EVTX log                     -->  EVTX parsing --> Hayabusa Sigma rules
  (Microsoft-Windows-Windows Defender           |
   %4Operational.evtx)                          +--> CloudRules EventsMatching (38 rules)
                                                       Event IDs: 1006, 1008, 1009, 1015,
                                                                  1116, 1118, 1119, 5001,
                                                                  5007, 7026

  Defender registry keys                -->  Registry parser (CollectionTool extractor)
  (HKLM\SOFTWARE\Microsoft\                    |
   Windows Defender\...)                       +--> CloudRules FileCorrelated
                                                     - Defender exclusion/disable via wmic
                                                     - Defender exclusion/disable via reg.exe
                                                     - Set-MpPreference via PowerShell

  Defender service state                -->  Service enumeration (SystemAPI extractor)
  (WdFilter, WinDefend, WdNisSvc)             |
                                              +--> Analysis results:
                                                     WIN_DEFENDER_SERVICE_NOT_RUNNING
                                                     WIN_DEFENDER_SERVICE_STARTUP_NOT_AUTO
                                                     WDFILTER_SERVICE_NOT_RUNNING
                                                     WDFILTER_SERVICE_STARTUP_NOT_AUTO

  File system (collected files)         -->  YARA scanning (CyberTriageYara.exe)
                                              +--> Results: YARA_HIT

  File hashes (MD5/SHA1/SHA256)         -->  Cloud reputation lookup
                                              +--> Results: TSK_MALWARE, TSK_HASH_HIT
```

### 2.2 Defender-Specific Analysis Results

| analysisResultType | Source | Trigger |
|---|---|---|
| `WINDOWS_DEFENDER_FEATURE_DISABLED` | CloudRules EventsMatching (9 rules) + FileCorrelated (2 rules) | Event 5007/5001 config change, wmic/PowerShell disable commands |
| `WINDOWS_DEFENDER_EXCLUSION_RULE` | CloudRules EventsMatching (3 rules) + FileCorrelated (2 rules) | Event 5007 exclusion added, wmic/PowerShell exclusion commands |
| `WINDOWS_DEFENDER_REGISTRY_KEY_MODIFICATION` | CloudRules FileCorrelated (1 rule) | `reg.exe` modifying Defender registry keys |
| `WIN_DEFENDER_ACTION_FAILED` | CloudRules EventsMatching (6 rules) | Events 1008, 1118, 1119 remediation failures |
| `WIN_DEFENDER_QUARANTINE_FILE_RESTORED` | CloudRules EventsMatching (3 rules) | Event 1009 quarantine restore |
| `WIN_DEFENDER_PROTECTED_FOLDER_REMOVED` | CloudRules EventsMatching (1 rule) | Event 5007 protected folder removal |
| `WIN_DEFENDER_FILTER_TAMPERING` | Built-in analysis | WdFilter driver/service tampering |
| `WIN_DEFENDER_SERVICE_NOT_RUNNING` | Built-in analysis | WinDefend service stopped |
| `WIN_DEFENDER_SERVICE_STARTUP_NOT_AUTO` | Built-in analysis | WinDefend startup type changed |
| `WDFILTER_SERVICE_NOT_RUNNING` | CloudRules EventsMatching (1 rule) | Event 7026 WdFilter driver load failure |
| `WDFILTER_SERVICE_STARTUP_NOT_AUTO` | Built-in analysis | WdFilter startup type changed |
| `TSK_MALWARE` | CloudRules EventsMatching (9 rules) + cloud reputation | Defender malware events 1006/1015/1116, cloud hash match |
| `MALWARE_PREVIOUSLY_DETECTED` | CloudRules EventsMatching (9 rules) | Defender previously detected threat events |

### 2.3 Malware Scoring Pipeline

The full malware determination flows through multiple stages:

1. **Cloud reputation** (Basis Technology): File hash lookup against known-malware database
2. **Import hash correlation**: PE import hash matching for packed/polymorphic malware
3. **YARA scanning**: Signature-based file content analysis (4 targeted rule sets)
4. **CloudRules evaluation**: Rule-based scoring across 12 plugin types
5. **MalwareDowngrade**: CloudRules plugin that reduces false-positive scores for 11 noisy result types (`PROCESS_PATH_NONSTD`, `EXE_PACKED`, `EXE_SIGNATURE`, etc.)
6. **AnalysisResultImpactMapping**: Human-readable impact text for 95 result types

### 2.4 analysisResultType Hierarchy for Malware

From most severe to least:

| Level | Types | Source |
|---|---|---|
| Confirmed malware | `TSK_MALWARE`, `TSK_HASH_HIT` | Cloud reputation, Defender event confirmation |
| Previously detected | `MALWARE_PREVIOUSLY_DETECTED` | Defender historical events |
| Signature match | `YARA_HIT` | YARA file scanning |
| Memory anomaly | `MEMPROCFS_FINDEVIL`, `VOLATILITY_MALFIND` | Memory forensics (MemProcFS, Volatility) |
| Suspicious indicator | `MALWARE_EXECUTABLE` | Heuristic analysis (packed, unsigned, etc.) |
| Downgraded | Various (11 types) | MalwareDowngrade CloudRules reduce severity |

---

## 3. Memory Forensics Pipeline

CyberTriage includes two complementary memory forensics engines for RAM dump analysis.

### 3.1 Volatility

| Property | Value |
|---|---|
| Binary | `volatility\volatility-a438e76.exe` (20.2 MB) |
| Version | Volatility Framework 2.6 (compiled as standalone PyInstaller exe) |
| Build | Commit `a438e76`, shipped 2026-01-14 |
| OS support | Windows XP SP2 through Windows Server 2016, Linux 2.6-4.2, macOS 10.5-10.12 |

**Key plugins available** (from `--info` output):

| Category | Plugins |
|---|---|
| Process analysis | `pslist`, `psscan`, `pstree`, `psxview`, `cmdline`, `consoles` |
| DLL/Module | `dlllist`, `ldrmodules`, `modscan`, `modules` |
| Malware detection | `malfind` (hidden/injected code), `apihooks`, `ssdt` |
| Network | `netscan`, `connections`, `connscan`, `sockets` |
| Credentials | `hashdump`, `cachedump`, `lsadump` |
| Registry | `hivelist`, `printkey`, `shellbags`, `shimcache`, `userassist` |
| File system | `filescan`, `dumpfiles`, `mftparser` |
| Timeline | `timeliner` |
| YARA | `yarascan` (YARA in Volatility's own address space) |

**Integration with CT json.gz format** -- `CTJSONGenerator.java`:

The `CTJSONGenerator` class converts Volatility output into the standard CyberTriage json.gz streaming format:

```java
public final synchronized void writeJSONObject(String name, Map data) {
    if (!"targetInfo".equals(name)) {
        data.put(FieldName.EXTRACTOR.toString(), "Volatility");
        if (!data.containsKey(FieldName.SOURCE_INFO.toString())) {
            data.put(FieldName.SOURCE_INFO.toString(),
                ImmutableMap.of("sourceType", "Memory"));
        }
    }
    // ... write as standard CT json.gz object
}
```

Every artifact from Volatility is tagged with `extractor: "Volatility"` and `sourceType: "Memory"`, making memory-derived findings distinguishable from disk-based collection in the json.gz output. The output uses the same `cyberTriageAgentOutput` / `cyberTriageOutputSection` envelope as collector-generated data, with `skip_full_scan: "yes"`.

**Result types generated**: `VOLATILITY_MALFIND` (from the `malfind` plugin detecting injected/hidden code regions).

### 3.2 MemProcFS

| Property | Value |
|---|---|
| Binary | `memprocfs_packager\memprocfs_packager.exe` (3.2 MB) |
| Core library | `memprocfs\vmm.dll` (2.4 MB) |
| YARA support | `memprocfs\vmmyara.dll` (in-memory YARA scanning) |
| LeechCore | `memprocfs\leechcore.dll` + device drivers |

**Architecture**: MemProcFS represents a memory dump as a virtual filesystem. Instead of running individual plugins like Volatility, it mounts the memory image and exposes processes, DLLs, network connections, and other artifacts as files and directories.

**Key components**:

| DLL | Purpose |
|---|---|
| `vmm.dll` | Virtual Memory Manager -- core parsing engine |
| `vmmyara.dll` | YARA integration for scanning process memory regions |
| `leechcore.dll` | Memory acquisition/reading abstraction layer |
| `leechcore_device_hvsavedstate.dll` | Hyper-V saved state file support |
| `leechcore_device_rawtcp.dll` | Raw TCP memory acquisition (live) |
| `leechcore_driver.dll` | Kernel driver-based acquisition |
| `FTD3XX.dll`, `FTD3XXWU.dll` | FTDI FPGA-based hardware memory acquisition |
| `dbghelp.dll`, `symsrv.dll` | Microsoft debugging symbols resolution |
| `info.db` | Pre-built database for OS structure identification |

**MemProcFS packager workflow**:

1. `memprocfs_packager.exe` receives a memory image path
2. Mounts the image via MemProcFS virtual filesystem
3. Extracts processes, DLLs, network state, loaded modules
4. Runs `vmmyara.dll` for in-memory YARA scanning
5. Runs FinDevil analysis (detecting evil through memory anomalies)
6. Packages results into CT json.gz format

**Result types generated**: `MEMPROCFS_FINDEVIL` (from FinDevil anomaly detection in memory).

### 3.3 LibNotOnDisk CloudRules (post-processing)

After memory forensics data is ingested, the `LibNotOnDiskCloudRulePlugin` (16 rules) compares loaded DLL lists against disk-backed files:

| Detection | Pattern | Purpose |
|---|---|---|
| Typosquat DLLs | `msc0ree.dll`, `kern3l32.dll`, `ntd1l.dll` | .NET CLR / kernel32 / NTDLL impersonation |
| Suspicious DLLs | `scriptcontrol*.dll`, `umppc*.dll` in system32 | Script host injection, print driver injection |
| False-positive exclusions | SentinelOne agent DLLs, Office 16 shared DLLs, Sophos AV DLLs | Known legitimate in-memory-only DLLs |
| Catch-all | Empty pattern (2 rules) | Flag any unrecognized in-memory-only DLL |

---

## 4. YARA Integration

### 4.1 YARA Engine

| Property | Value |
|---|---|
| Binary | `yara\CyberTriageYara.exe` (2.3 MB) |
| Compiler | `yara\yarac64.exe` |
| Library | `yara\zlib.dll` (compression support for rules) |

`CyberTriageYara.exe` is a custom wrapper around the YARA library (not the standard `yara64.exe`). It integrates with CT's file scanning pipeline, accepting files from the ingest process and returning match results as `YARA_HIT` analysis results.

### 4.2 Precompiled Rule Sets

Four targeted detection rule sets ship in `yara_precompiled_rules\`:

| Rule set | Directory | Target |
|---|---|---|
| **Suspicious OneNote** | `onenote\Suspicious_OneNote\` | OneNote-based phishing payloads (.one files with embedded scripts/executables) |
| **ScreenConnect** | `screenconnect\screenconnect\` | ScreenConnect remote access exploitation artifacts |
| **Sliver C2** | `sliver_binary\sliver\` | Sliver adversary framework binary detection |
| **NSA Webshells** | `webshells\NSA_Core_Webshell\` | NSA-published core webshell signatures (ASPX, JSP, PHP) |

These rules are **precompiled** (binary format), meaning the source `.yar` files have been processed by `yarac64.exe` into optimized matching structures. The precompiled rules are not human-readable but execute faster than source rules.

### 4.3 YARA Scanning Flow

1. During Phase 2 ingest, file content is decoded from base64 and saved to the file store
2. `CyberTriageYara.exe` scans files against all precompiled rule sets
3. Matches generate `YARA_HIT` analysis results with the rule name and matched strings
4. MemProcFS also performs in-memory YARA scanning via `vmmyara.dll` (separate from file-based scanning)

### 4.4 In-Memory YARA (via MemProcFS)

The `vmmyara.dll` library extends MemProcFS with YARA scanning capabilities directly within process memory spaces. This enables detection of:

- Unpacked malware in process memory (not visible on disk)
- Injected code regions containing known signatures
- Fileless malware residing only in memory

---

## 5. Hayabusa / Sigma Integration

### 5.1 Hayabusa Engine

| Property | Value |
|---|---|
| Binary | `hayabusa\hayabusa.exe` (11.5 MB) |
| Rules | `hayabusa\encoded_rules.yml` (9.1 MB, ~3000 encoded Sigma/Hayabusa rules) |
| Config | `hayabusa\config\profiles.yaml` |
| Exclusions | `hayabusa\exclude_rules.txt` (32 excluded rule GUIDs) |
| Rule config | `hayabusa\rules_config_files.txt` |

### 5.2 Custom Output Profile

CyberTriage defines a custom Hayabusa output profile (`cyber-triage-custom`) that captures all fields needed for CT integration:

```yaml
cyber-triage-custom:
    Timestamp: "%Timestamp%"
    RuleTitle: "%RuleTitle%"
    Level: "%Level%"
    Computer: "%Computer%"
    Channel: "%Channel%"
    EventID: "%EventID%"
    RuleAuthor: "%RuleAuthor%"
    MitreTactics: "%MitreTactics%"
    MitreTags: "%MitreTags%"
    OtherTags: "%OtherTags%"
    RecordID: "%RecordID%"
    AllFieldInfo: "%AllFieldInfo%"
    RuleFile: "%RuleFile%"
    EvtxFile: "%EvtxFile%"
    RuleID: "%RuleID%"
```

This profile captures MITRE ATT&CK mappings, full event field info, and rule metadata for enrichment into CT's analysis results.

### 5.3 Excluded Sigma Rules (32 rules)

CyberTriage excludes 32 Sigma/Hayabusa rules from processing, organized by reason:

**Replaced by Hayabusa-native rules** (6 rules):

| GUID | Original rule | Replacement |
|---|---|---|
| `6695d6a2-...` | User Added to Local Administrators | Hayabusa native |
| `5ecd226b-...` | Local User Creation | Hayabusa native |
| `23013005-...` | Hidden Local User Creation | Hayabusa native |
| `cb7a40d5-...` | PsExec Tool Execution | Hayabusa native (original rule non-functional) |
| `c063426c-...` | Execution Of Other File Type Than .exe | Hayabusa rule `8d1487f1` |
| `3ce7b51a-...` | Execution Of Other File Type Than .exe (alt) | Hayabusa rule `8d1487f1` |

**Replaced by Sigma correlation rules** (3 rules):

| GUID | Original rule | Replacement mechanism |
|---|---|---|
| `35e8a0fc-...` | PW Guessing | Sigma correlation |
| `4574194d-...` | User Guessing | Sigma correlation |
| `ffd622af-...` | PW Spray | Sigma correlation |

**Replaced by CT-native detection** (7 rules):

| GUID | Original rule | CT replacement |
|---|---|---|
| `c70d7033-...` | Windows Defender Threat Detected | CloudRules EventsMatching |
| `23f0b75b-...` | Security Event Log Cleared | CT rule `c2f690ac` |
| `9b14c9d8-...` | Security Eventlog Cleared (alt) | CT rule `c2f690ac` |
| `30966a3a-...` | Important Eventlog Cleared | CT rule `f481a1f3` |
| `8617b59c-...` | Eventlog Cleared | CT rule `ed90ed4f` |
| `73f64ce7-...` | User Logoff Event | Not needed for triage |
| `de5d0dd7-...` | Admin User Remote Logon | Covered by "Logon (Type 10 RemoteInteractive)" |

**Sysmon-specific exclusions** (5 rules):

| GUID | Rule | Reason |
|---|---|---|
| `f508ff7b-...` | Sysmon 4,16: Configuration Modification | Sysmon internal |
| `0f88cce2-...` | Sysmon 16: Configuration Change | Sysmon internal |
| `17d51ceb-...` | Sysmon 25: Process Hollowing | (excluded) |
| `5dd9120c-...` | Sysmon 27: Blocked Executable | Replaced by `bb35ca48` |
| `8a5ee8f3-...` | Sysmon 255: Configuration Error | Sysmon internal |

**Disabled due to placeholder requirements** (3 rules):

| GUID | Rule | Missing placeholder |
|---|---|---|
| `f8d98d6c-...` | Pass the Hash Activity | `%Workstations%` |
| `dd7876d8-...` | Possible Zerologon (CVE-2020-1472) | `%DC-MACHINE-NAME%` |
| `68fcba0d-...` | Remote Registry Management | `%Admins_Workstations%` |

**Disabled due to missing fields** (2 rules):

| GUID | Rule | Missing field |
|---|---|---|
| `d85240fc-...` | Windows Kernel Token Stealing | `ParentIntegrityLevel` |
| `ab0d6f07-...` | Windows Kernel Token Stealing (alt) | `ParentIntegrityLevel` |

**False positive suppressions** (3 rules):

| GUID | Rule |
|---|---|
| `a4504cb2-...` | Suspicious Multiple File Rename Or Delete |
| `9f8b3bda-...` | Quick Execution of Suspicious Commands (Sysmon 1) |
| `53facd0f-...` | Quick Execution of Suspicious Commands (Sec 4688) |

### 5.4 Additional CloudRules Suppressions

The `HayabusaCloudRulePlugin` (1 CloudRules rule, 3 entries) adds further suppressions for correlation rules that produce excessive false positives in enterprise environments:

| GUID | Suppressed rule |
|---|---|
| `49d15187-...` | `Sec_4648_Med_ExplicitLogon_PW-Spray_Correlation.yml` |
| `0ae09af3-...` | `Sec_4625_Med_LogonFail_UserGuessing_Correlation.yml` |
| `23179f25-...` | `Sec_4625_Med_LogonFail_WrongPW_PW-Guessing_Correlation.yml` |

### 5.5 Hayabusa Processing Flow

1. EVTX files are extracted from the target system during collection
2. `evtx_dump-v0.9.0.exe` parses `.evtx` files into structured event data
3. `hayabusa.exe` runs against the EVTX files using `encoded_rules.yml`
4. Output uses the `cyber-triage-custom` profile, producing one JSON line per detection
5. CT server ingests Hayabusa output, creating analysis results with MITRE ATT&CK tags
6. CloudRules `EventsMatchingCloudRulePlugin` provides additional Defender-specific detection (38 rules)

---

## 6. EVTX Processing Pipeline

### 6.1 Tools

| Tool | Purpose | Format support |
|---|---|---|
| `evtexport.exe` | Legacy event log export (libevt-based) | `.evt` (Windows XP/2003) |
| `evtinfo.exe` | Event log metadata and information | `.evt` metadata |
| `evtx_dump-v0.9.0.exe` | Modern event log parsing | `.evtx` (Vista+) |

The three-tool chain covers the full range of Windows event log formats:

- **Legacy** (`.evt`): Windows XP, 2003 -- handled by `evtexport.exe`/`evtinfo.exe` using libevt
- **Modern** (`.evtx`): Windows Vista through current -- handled by `evtx_dump-v0.9.0.exe`

### 6.2 Processing Chain

```
Target System                   CyberTriage Server
=============                   ==================

  .evtx files  --collected-->   evtx_dump-v0.9.0.exe
  (Security, System,                |
   Application, Defender,           +--> Structured event data (XML -> JSON)
   Sysmon, PowerShell, etc.)        |
                                    +--> Hayabusa (Sigma rule matching)
                                    |       |
                                    |       +--> Sigma/Hayabusa detections
                                    |
                                    +--> CloudRules EventsMatching
                                    |       |
                                    |       +--> 38 rules targeting Defender events
                                    |
                                    +--> CT WindowsEvent data model
                                            |
                                            +--> eventID, logName, payload, time
                                            +--> Stored in PostgreSQL
```

### 6.3 WindowsEvent Data Model

From the decompiled `WindowsEvent.java`:

```java
public record WindowsEvent(
    String logName,          // Channel name (e.g., "Security")
    String logPathName,      // EVTX file path
    long eventID,            // Windows event ID
    String path,             // Executable path (if applicable)
    Map<String, Object> payload,  // Event XML data fields
    long recordID,           // Event record ID
    long time,               // Epoch milliseconds
    String userDomain,       // Account domain
    String userID,           // Account name
    String userSID,          // Security identifier
    String extractor         // "SystemAPI" for live, parser for offline
)
```

The `payload` map preserves all event-specific fields (e.g., `LogonType`, `TargetLogonId`, `Threat Name`, `New Value`), which are critical for CloudRules `EventsMatchingCloudRulePlugin` regex matching.

---

## 7. Specialized Parsers

### 7.1 BITS Parser

| Property | Value |
|---|---|
| Binary | `bitsparser\BitsParser_0a2b51e.exe` (8.4 MB) |
| Dependencies | `libcrypto-1_1.dll`, `libssl-1_1.dll`, `libffi-7.dll` |
| Purpose | Extract BITS (Background Intelligent Transfer Service) transfer jobs |

BITS is a Windows service for asynchronous file transfers. Attackers abuse it for:
- Data exfiltration (transferring files to external servers)
- Malware download (pulling payloads via BITS to evade detection)
- Persistence (BITS jobs survive reboots)

The parser extracts job metadata including source URLs, destination paths, and timestamps. CloudRules `CommonBitsJobDomainCloudRulePlugin` (2 rules, 4 domain patterns) then filters known-benign BITS domains (Adobe, Microsoft, Google, Live.com) to surface suspicious BITS activity.

### 7.2 WMI Persistence Detector

| Property | Value |
|---|---|
| Binary | `wmi\collectWMIPersistence.exe` (7.9 MB) |
| Purpose | Detect WMI event subscriptions used for persistence |

WMI event subscriptions are a stealthy persistence mechanism. The collector identifies:
- `__EventFilter` instances (trigger conditions)
- `CommandLineEventConsumer` instances (actions executed)
- `__FilterToConsumerBinding` instances (filter-to-action links)

Results map to analysis result types:
- `WMI_EVENTSUB_CONS_UNEXPECT` -- unexpected consumer action
- `WMI_EVENTSUB_NAMESPACE_UNEXPECT` -- unexpected WMI namespace
- `WMI_EVENTSUB_PERS` -- persistent WMI subscription detected

### 7.3 ESE Database Extraction

| Property | Value |
|---|---|
| Binaries | `lib_esedb\esedbexport_16d65f0.exe`, `esedbinfo_16d65f0.exe` (543 KB) |
| Purpose | Extract Extensible Storage Engine databases |

ESE databases are used by multiple Windows components:
- **Internet Explorer/Edge**: Browsing history, cache, cookies
- **Windows Search**: Index database (`Windows.edb`)
- **SRUM**: System Resource Usage Monitor (network, power, app usage)
- **Exchange**: Mailbox databases

The export tool extracts table contents into CSV/text format for CT ingestion.

### 7.4 Pasco2 (IE History)

| Property | Value |
|---|---|
| Binary | `pasco2\pasco2-1.0.0.jar` (Java) |
| Dependencies | `commons-cli-1.10.0.jar`, `commons-collections-3.2.2.jar`, `trove4j-3.0.3.jar` |
| Purpose | Parse Internet Explorer cache/history files (`index.dat`) |

Pasco2 handles the legacy `index.dat` binary format used by Internet Explorer for cache and history storage. This is essential for forensic analysis of older Windows systems where IE was the default browser.

### 7.5 Search Engine URL Query Extraction

| Property | Value |
|---|---|
| Config | `search_engine\SEUQAMappings.xml` |
| Purpose | Extract search queries from browser history URLs |
| Origin | Autopsy SEUQA (Search Engine URL Query Analyzer) module |

Supported search engines:

| Engine | Domain pattern | Query parameter |
|---|---|---|
| Google | `.google.` | `?q=`, `&q=` |
| Yahoo | `.yahoo.` | `?p=` |
| Bing | `.bing` | `?q=`, `&q=` |
| Twitter | `twitter.` | `?q=`, `&q=` |
| LinkedIn | `.linkedin.` | `&keywords=` |
| Facebook | `.facebook.` | `?value=` |

This enables CT to extract what the user searched for during the investigation timeframe -- valuable for establishing user intent or attacker reconnaissance activity.

### 7.6 GeoIP Lookup

| Property | Value |
|---|---|
| Database | `geolite2\GeoLite2-Country.mmdb` |
| Library | MaxMind GeoIP2 (Java, in core JAR) |
| Purpose | Map IP addresses to countries |

Used for enriching network connections (`nwConnectionDescriptor`) and DNS cache entries (`dnsCacheEntry`) with geographic context. Connections to unexpected countries can indicate C2 communication or data exfiltration.

---

## 8. Autopsy Integration

| Property | Value |
|---|---|
| Module | `integrations\autopsy\cybertriage_importer_1.0.5.nbm` (18 MB) |
| Format | NetBeans Module (NBM) |
| Purpose | Import CyberTriage results into Autopsy forensics platform |

The Autopsy importer enables CT findings to be viewed alongside traditional disk forensics in the Autopsy platform (an open-source digital forensics environment also developed by Basis Technology). This provides:

- Unified timeline view combining CT's rapid triage with full disk analysis
- Cross-referencing CT malware findings with file system artifacts
- Access to Autopsy's keyword search, hash filtering, and reporting on CT data
- Collaborative review workflow between triage and deep forensics teams

The module is installed by copying the `.nbm` file into Autopsy's plugin directory.

---

## 9. Scope Beyond Traditional Windows Collection

### 9.1 Collection Types

The collector agent's `typesCollected` field (from `CollectionInfo`) indicates which data categories were gathered. From the evaldata sample:

```
ENUM_FS, PROCESSES, STARTUP_ITEMS, SCHEDULED_TASKS, NETWORK,
NETWORK_CACHES, USERS, PROGRAM_RUN, WEB, SYSTEM_CONFIG,
USER_LOGINS, NETWORK_SHARES, DATA_ACCESSED, ALL_FILES
```

### 9.2 Comparison with Traditional DFIR Tools

| Capability | Traditional DFIR (Kroll, X-Ways, etc.) | CyberTriage | Notes |
|---|---|---|---|
| Disk forensics | Full disk image analysis | Selective file extraction + metadata | CT trades completeness for speed |
| Memory forensics | Separate tool (Volatility standalone) | **Integrated** (Volatility + MemProcFS) | CT auto-processes RAM dumps |
| EVTX analysis | Manual or separate tool | **Integrated** (Hayabusa + CloudRules) | Automated Sigma + custom rules |
| Malware scanning | Separate AV/YARA | **Integrated** (YARA + cloud reputation) | Multi-tier: hash, upload, YARA, imphash |
| Threat intelligence | Manual IOC matching | **Integrated** (CloudRules, 386 rules) | Auto-updated per CT release |
| BITS forensics | Manual extraction | **Integrated** (BitsParser) | Automatic with domain filtering |
| WMI persistence | Manual registry analysis | **Integrated** (collectWMIPersistence) | Dedicated WMI extractor |
| ESE database parsing | Separate tool (ESEDatabaseView, etc.) | **Integrated** (esedbexport) | IE history, SRUM, Windows Search |
| GeoIP enrichment | Manual lookup | **Integrated** (GeoLite2) | Automatic for all network artifacts |
| Browser forensics | Separate tools per browser | **Integrated** (Pasco2 + SEUQA) | IE/Edge history + search queries |
| Timeline generation | Manual assembly | **Integrated** (json.gz + Timesketch) | Via ct-to-timesketch pipeline |
| EDR telemetry import | Not applicable | **Integrated** (MDE via Graph API + CSV) | License-gated; see Section 10 |

### 9.3 What CT Captures That Others Typically Don't

1. **Real-time process and network state**: Live system API queries for running processes, open connections, DNS cache, and listening ports (not available from dead-box forensics)
2. **Integrated YARA + memory scanning**: YARA runs against both disk files and process memory (via vmmyara.dll) in a single pipeline
3. **Cloud reputation scoring**: File hashes are checked against Basis Technology's cloud malware database with import hash correlation
4. **Automated Sigma correlation**: Hayabusa processes all EVTX files with ~3000 detection rules, producing MITRE-tagged findings
5. **CloudRules intelligence layer**: 386 rules covering Impacket, RMM tools, exfil domains, Defender tampering, PowerShell abuse -- evaluated automatically against all artifacts
6. **Multi-collector coverage**: Five collector variants ensure data collection from Windows XP through current Windows, including UAC-elevated and minimal-dependency modes
7. **MDE telemetry import** (license-gated): Direct Microsoft Graph API integration pulls 30 days of endpoint telemetry, security alerts, and process/file/network history from MDE without deploying an agent to the target

### 9.4 Implications for ct-to-timesketch

Each data source requires awareness in the Go parsers:

| Data source | Extractor value | How to identify | Notes for parsing |
|---|---|---|---|
| Disk collection | `TSK`, `CollectionTool`, `CyberTriage` | Standard json.gz sections | Primary data flow |
| Live system queries | `SystemAPI` | `sourceType: "Memory"` on DNS/network | Real-time state, not historical |
| Volatility output | `Volatility` | `extractor: "Volatility"` | Same json.gz format, different source |
| MemProcFS output | (embedded in json.gz) | `MEMPROCFS_FINDEVIL` result type | Memory-only findings |
| YARA matches | (analysis result) | `YARA_HIT` result type | File or memory match |
| Hayabusa findings | (analysis result) | Hayabusa-tagged events | Already handled by ct-to-timesketch |
| CloudRules findings | (analysis result) | `cloudrules_*` enrichment fields | Pending ct-to-timesketch implementation |
| BITS jobs | `CollectionTool` | BITS-specific artifact types | May need dedicated parser |
| WMI persistence | `CollectionTool` | WMI event subscription artifacts | Maps to `WMI_EVENTSUB_*` |
| GeoIP data | (enrichment) | Country fields on network artifacts | Already in network event fields |
| MDE API output | `ONLINE_API` | `DefenderSubType.DEFENDER_HUNT_*` source tags | See Section 10 |
| MDE CSV output | `ONLINE_API` | `DefenderSubType.DEFENDER_TIMELINE_*` source tags | See Section 10 |

---

## 10. Microsoft Defender for Endpoint Integration

CyberTriage includes a **license-gated** integration with Microsoft Defender for Endpoint (MDE) that imports endpoint telemetry via two parallel paths: the Microsoft Graph API (Advanced Hunting) and MDE Timeline CSV export. This is entirely separate from the EVTX-based Defender log analysis described in Section 2.

> **Note**: The screenshot in the CT options UI shows "This integration is not included in your license." The feature requires a separate license tier from Sleuth Kit Labs. Configuration fields: Client Id, Client Secret, Tenant Id, Endpoint (Public Cloud or US Government), Scopes.

### 10.1 Authentication

| Property | Value |
|---|---|
| Library | MSAL4J (`msal4j.jar`, 393 KB) + Azure Identity (`azure-identity.jar`, 257 KB) |
| Credential type | `ClientSecretCredential` (Azure AD app registration) |
| Required fields | `clientId`, `clientSecret`, `tenantId` |
| Default scopes | `https://graph.microsoft.com/.default` |
| SDK | Microsoft Graph SDK for Java (`microsoft-graph.jar`, 56 MB) via Kiota client generation |
| HTTP client | OkHttp3 with configurable proxy (system, manual, or none) |

**Supported endpoints**:

| Endpoint | Graph URL | Authority | 
|---|---|---|
| Public Cloud | `https://graph.microsoft.com/v1.0` | `https://login.microsoftonline.com/` |
| US Government (GCC High) | `https://graph.microsoft.us/v1.0` | `https://login.microsoftonline.us/` |

The `DefenderAPIEndpointConfig` record stores the full configuration:

```java
public record DefenderAPIEndpointConfig(
    boolean licensed,        // license check
    boolean enabled,         // user toggle
    String clientId,         // Azure AD app client ID
    String clientSecret,     // Azure AD app client secret
    String tenantId,         // Azure AD tenant ID
    DefenderRootEndpoint endpoint,  // PUBLIC_CLOUD or US_GOVERMENT
    String[] scopes          // defaults to {"https://graph.microsoft.com/.default"}
)
```

### 10.2 Connection Management

`DefenderConnection` manages the `GraphServiceClient` lifecycle:

- Creates a `ClientSecretCredential` via `ClientSecretCredentialBuilder`
- Wraps it in `AzureIdentityAuthenticationProvider` for Graph SDK
- Configures OkHttp3 with proxy settings, custom SSL trust store, and 60-second timeouts
- Connection test performs two queries:
  1. `DeviceProcessEvents | limit 1` (Advanced Hunting)
  2. `security/alertsV2?$top=1` (Security Alerts v2)
- Implements retry logic (3 attempts, 1-second delay) with credential error detection

### 10.3 Path 1: Graph API Advanced Hunting (HuntingQueryProcessor)

The `HuntingQueryProcessor` executes KQL queries against MDE's Advanced Hunting API for a specific device (identified by `DeviceId`). It collects data in 8 steps with 20+ queries:

**Step 1 -- Host Information**:

```kql
DeviceInfo | where DeviceId == "<deviceId>" | limit 1
```

Fields extracted: `DeviceName`, `OSVersion`, `OSBuild`, `OSDistribution`, `OSPlatform`, `PublicIP`

```kql
DeviceNetworkInfo | where IPAddresses != "[]"
  | where DeviceId == "<deviceId>"
  | summarize arg_max(Timestamp, *) by NetworkAdapterName
```

Fields extracted: Private IP addresses from `IPAddresses` JSON array.

**Step 2 -- Users**:

```kql
DeviceEvents | where ActionType == "UserAccountCreated" and DeviceId == "<deviceId>"
```

**Step 3 -- Logons**:

```kql
DeviceLogonEvents | where DeviceId == "<deviceId>"
```

Post-processed via `DefenderArtifactUtils.processLogonSessionEntries()` using the `DefenderLogonSessionsScratchTable`.

**Step 4 -- Scheduled Tasks / Services / WMI**:

```kql
DeviceEvents | where ActionType == "ServiceInstalled" and DeviceId == "<deviceId>"
DeviceEvents | where ActionType == "ScheduledTaskCreated" and DeviceId == "<deviceId>"
DeviceEvents | where ActionType == "ScheduledTaskUpdated" and DeviceId == "<deviceId>"
DeviceEvents | where ActionType == "ScheduledTaskDeleted" and DeviceId == "<deviceId>"
DeviceEvents | where ActionType == "WmiBindEventFilterToConsumer" and DeviceId == "<deviceId>"
```

**Step 5 -- Network Activity**:

```kql
DeviceNetworkEvents | where ActionType == "ConnectionSuccess" and DeviceId == "<deviceId>"
DeviceNetworkEvents | where ActionType == "InboundConnectionAccepted" and DeviceId == "<deviceId>"
DeviceNetworkEvents | where ActionType == "ListeningConnectionCreated" and DeviceId == "<deviceId>"
```

**Step 6 -- Processes and Security Events**:

Security events (Defender antivirus + log clearing):

```kql
DeviceEvents | where (
    ActionType == "SecurityLogCleared" or
    ActionType == "AntivirusDetection" or
    ActionType == "AntivirusDetectionActionType" or
    ActionType == "AntivirusMalwareBlocked" or
    ActionType == "AntivirusError" or
    ActionType == "AntivirusMalwareActionFailed"
) and DeviceId == "<deviceId>"
```

Process creation:

```kql
DeviceProcessEvents | where ActionType == "ProcessCreated" and DeviceId == "<deviceId>"
```

PowerShell commands:

```kql
DeviceEvents | where ActionType == "PowerShellCommand" and DeviceId == "<deviceId>"
```

**Step 7 -- Web Artifacts**:

```kql
DeviceEvents | where ActionType == "BrowserLaunchedToOpenUrl"
    and not (RemoteUrl !startswith "http" and RemoteUrl endswith ".lnk")
    and DeviceId == "<deviceId>"
```

**Step 8 -- File Events**:

```kql
DeviceFileEvents | where DeviceId == "<deviceId>"
```

**Step 9 -- Security Alerts** (separate API, not KQL):

```
GET /security/alertsV2
  ?$filter=status ne 'resolved'
    and (severity eq 'medium' or severity eq 'high')
    and classification ne 'falsePositive'
    and createdDateTime gt <30 days ago>
```

Processed by `DefenderAlertsProcessor.processAlerts()` which extracts alert evidence, associated processes, files, and network indicators.

### 10.4 Path 2: CSV Timeline Import (TimelineCSVProcessor)

The `TimelineCSVProcessor` ingests MDE Timeline export files (CSV or ZIP containing multiple CSVs) via `MultiCsvReader`:

**Supported column names** (handles both legacy and modern MDE export formats):

| Modern column | Legacy column | Purpose |
|---|---|---|
| `DeviceName` | `Computer Name` | Hostname |
| `DeviceId` | `Machine Id` | MDE device identifier |
| `ActionType` | `Action Type` | Event classification |
| `Timestamp` | `Timestamp` | Event time |

**Processing flow**:

1. `CSVReferenceDateFinder` scans CSV data to find the reference timestamp
2. Each CSV row is converted to a Map via `DefenderArtifactUtils.convertCSVToHuntMap()`
3. `DefenderArtifactProcessor.convertToCTArtifact()` normalizes to CT artifact format
4. Post-processing stages assemble process trees, logon sessions, file metadata, and scheduled tasks from scratch tables

**Logon type mapping** (CSV `LogonType` string to CT logon type):

| MDE LogonType | CT Logon Type |
|---|---|
| `System` | System |
| `Interactive` | Local Interactive |
| `Network` | Network |
| `NetworkCleartext` | Network |
| `NewCredentials` | New Credentials |
| `RemoteInteractive` | Remote Interactive |
| `CachedInteractive` | Local Interactive |
| `CachedRemoteInteractive` | Remote Interactive |
| `Batch`, `Service`, `Unlock`, `CachedUnlock` | (empty -- skipped) |

### 10.5 Data Normalization (DefenderArtifactProcessor)

`DefenderArtifactProcessor.convertToCTArtifact()` is the central conversion function for both API and CSV paths. It maps MDE data to standard CT artifact types based on `ActionType`:

| MDE ActionType | CT Data Type | Notes |
|---|---|---|
| `ProcessCreated` | Process | Full process tree with parent PID, command line, SHA1/SHA256 |
| `LogonSuccess` | LogonSession | Mapped via logon type; deduped in scratch table |
| `LogonFailed` | LogonSession | Failed logon with failure reason |
| `LogonAttempted` | LogonSession | Logon attempt |
| `ConnectionSuccess` | NetworkConnection | Remote IP, port, protocol |
| `InboundConnectionAccepted` | NetworkConnection | Inbound connection with local/remote details |
| `ListeningConnectionCreated` | NetworkConnection | Listening socket (local port) |
| `FileCreated` | File | File path, SHA1, SHA256 |
| `FileModified` | File | Modified file metadata |
| `FileDeleted` | File | Deleted file record |
| `ServiceInstalled` | ScheduledTask/Service | Service installation with binary path |
| `ScheduledTaskCreated` | ScheduledTask | Task with action/trigger |
| `ScheduledTaskUpdated` | ScheduledTask | Task modification |
| `ScheduledTaskDeleted` | ScheduledTask | Task removal |
| `UserAccountCreated` | User | New user account |
| `WmiBindEventFilterToConsumer` | WMI Persistence | WMI event subscription |
| `SecurityLogCleared` | WindowsEvent | Security log cleared event |
| `AntivirusDetection` | WindowsEvent | Defender malware detection |
| `AntivirusMalwareBlocked` | WindowsEvent | Defender blocked malware |
| `AntivirusError` | WindowsEvent | Defender error |
| `AntivirusMalwareActionFailed` | WindowsEvent | Defender remediation failure |
| `PowerShellCommand` | Process | PowerShell command execution |
| `BrowserLaunchedToOpenUrl` | WebArtifact | URL opened via browser |

### 10.6 Scratch Table Staging

MDE data uses PostgreSQL scratch tables for deduplication and assembly before final ingest:

| Scratch table | Purpose | Key fields |
|---|---|---|
| `DefenderFilesScratchTable` | Deduplicates file entries (same file may appear in multiple events) | SHA1, SHA256, path, file name, size |
| `DefenderProcessesScratchTable` | Assembles process tree (parent-child relationships from separate events) | PID, process name, command line, parent PID, SHA1 |
| `DefenderLogonSessionsScratchTable` | Correlates logon sessions (success/fail from separate events) | Logon ID, account name, logon type, domain |
| `DefenderTasksScratchTable` | Aggregates scheduled task lifecycle events (create/update/delete) | Task name, action, trigger, path |

Each scratch table extends `DefenderScratchItem` and implements collection-scoped temporary storage that is cleaned up after ingest completes.

### 10.7 Source Type Tagging

All MDE-sourced artifacts are tagged with `sourceInfo.sourceType: "ONLINE_API"` and a specific `DefenderSubType` to distinguish their origin:

**API-sourced subtypes** (prefix `DEFENDER_HUNT_`):

| Enum value | Display string |
|---|---|
| `DEFENDER_HUNT` | Windows Defender Hunt |
| `DEFENDER_HUNT_PROCESS_CREATED` | Windows Defender Hunt - ProcessCreated |
| `DEFENDER_HUNT_LOGON_SUCCESS` | Windows Defender Hunt - LogonSuccess |
| `DEFENDER_HUNT_LOGON_FAILED` | Windows Defender Hunt - LogonFailed |
| `DEFENDER_HUNT_LOGON_ATTEMPTED` | Windows Defender Hunt - LogonAttempted |
| `DEFENDER_HUNT_SERVICE_INSTALLED` | Windows Defender Hunt - ServiceInstalled |
| `DEFENDER_HUNT_CONNECTION_SUCCESS` | Windows Defender Hunt - ConnectionSuccess |
| `DEFENDER_HUNT_INBOUND_CONNECTION_ACCEPTED` | Windows Defender Hunt - InboundConnectionAccepted |
| `DEFENDER_HUNT_LISTENING_CONNECTION_ACCEPTED` | Windows Defender Hunt - ListeningConnectionCreated |
| `DEFENDER_HUNT_LISTENING_SOCKET_CREATED` | Windows Defender Hunt - ListeningSocketCreated |
| `DEFENDER_HUNT_FILE_CREATED` | Windows Defender Hunt - FileCreated |
| `DEFENDER_HUNT_FILE_MODIFIED` | Windows Defender Hunt - FileModified |
| `DEFENDER_HUNT_FILE_DELETED` | Windows Defender Hunt - FileDeleted |
| `DEFENDER_HUNT_TASK_CREATED` | Windows Defender Hunt - ScheduledTaskCreated |

**CSV-sourced subtypes** (prefix `DEFENDER_TIMELINE_`):

| Enum value | Display string |
|---|---|
| `DEFENDER_TIMELINE_PROCESS_CREATED` | Windows Defender Timeline - ProcessCreated |
| `DEFENDER_TIMELINE_LOGON_SUCCESS` | Windows Defender Timeline - LogonSuccess |
| `DEFENDER_TIMELINE_LOGON_FAILED` | Windows Defender Timeline - LogonFailed |
| `DEFENDER_TIMELINE_LOGON_ATTEMPTED` | Windows Defender Timeline - LogonAttempted |
| `DEFENDER_TIMELINE_SERVICE_INSTALLED` | Windows Defender Timeline - ServiceInstalled |
| `DEFENDER_TIMELINE_CONNECTION_SUCCESS` | Windows Defender Timeline - ConnectionSuccess |
| `DEFENDER_TIMELINE_INBOUND_CONNECTION_ACCEPTED` | Windows Defender Timeline - InboundConnectionAccepted |
| `DEFENDER_TIMELINE_LISTENING_CONNECTION_CREATED` | Windows Defender Timeline - ListeningConnectionCreated |
| `DEFENDER_TIMELINE_LISTENING_SOCKET_CREATED` | Windows Defender Timeline - ListeningSocketCreated |
| `DEFENDER_TIMELINE_FILE_CREATED` | Windows Defender Timeline - FileCreated |
| `DEFENDER_TIMELINE_FILE_MODIFIED` | Windows Defender Timeline - FileModified |
| `DEFENDER_TIMELINE_FILE_DELETED` | Windows Defender Timeline - FileDeleted |
| `DEFENDER_TIMELINE_TASK_CREATED` | Windows Defender Timeline - ScheduledTaskCreated |

### 10.8 Rate Limiting and Query Engine

`DefenderQueryEngine` manages query execution via `SlidingWindowRequestSubmitter`:

| Property | Value |
|---|---|
| Query timeout | 420 seconds (7 minutes) per query |
| Priority levels | `HIGH`, `LOW` (alerts use separate path) |
| Max row limit | Configurable; throws `MaxRowsExceededException` when exceeded |
| Retry behavior | Query partitioning when row limits are hit |
| Concurrency | Thread-safe singleton with `CompletableFuture`-based async execution |
| Rate window | Sliding window to respect MDE API throttling limits |

### 10.9 Alert Processing Pipeline

`DefenderAlertsProcessor.processAlerts()` handles Security Alerts v2 responses:

- Filters alerts by device: matches `deviceId` against alert evidence
- Extracts medium/high severity, unresolved, non-false-positive alerts from the last 30 days
- Creates CT `WindowsEvent` artifacts from alert metadata (title, severity, category, MITRE techniques)
- `DefenderAlertsBatchProcessor` handles batch post-processing: extracts hash data and process data from alert evidence for malware scanning correlation

### 10.10 MDE Integration vs. EVTX-Based Defender Analysis

| Aspect | EVTX-based (Section 2) | MDE API/CSV (Section 10) |
|---|---|---|
| Data source | Local `.evtx` files from target system | Microsoft Graph API or exported CSV |
| Scope | Defender event logs only | Full endpoint telemetry (processes, files, network, logons, tasks, alerts) |
| Historical depth | Limited to EVTX retention on target | Up to 30 days via MDE retention |
| License | All CT licenses | Separate license tier required |
| Agent deployment | Requires CT collector on target | No agent needed -- queries MDE cloud data |
| Defender coverage | Service state, config changes, detections | Same plus antivirus actions, PowerShell, browser URLs |
| Analysis pipeline | EVTX -> Hayabusa/CloudRules -> CT results | MDE -> DefenderArtifactProcessor -> scratch tables -> CT results |
| `sourceType` | `"CollectionTool"` or `"SystemAPI"` | `"ONLINE_API"` |

### 10.11 Azure AD App Registration Requirements

To configure the integration, an Azure AD app registration needs the following Microsoft Graph API permissions:

| Permission | Type | Purpose |
|---|---|---|
| `ThreatHunting.Read.All` | Application | Advanced Hunting KQL queries |
| `SecurityAlert.Read.All` | Application | Security Alerts v2 |
| `Device.Read.All` | Application | Device information lookup |
| `Machine.Read.All` | Application (legacy) | Device search by name |

### 10.12 Dependencies Bundled in CT Install

| Library | JAR | Size |
|---|---|---|
| Microsoft Graph SDK | `microsoft-graph.jar` | 56.2 MB |
| Microsoft Graph Core | `microsoft-graph-core.jar` | 82.5 KB |
| MSAL4J | `msal4j.jar` | 392.8 KB |
| MSAL4J Persistence | `msal4j-persistence-extension.jar` | 27.0 KB |
| Azure Identity | `azure-identity.jar` | 256.7 KB |
| Azure Core | `azure-core.jar` | 872.8 KB |
| Azure Core HTTP (Netty) | `azure-core-http-netty.jar` | 86.3 KB |
| Azure JSON | `azure-json.jar` | 326.0 KB |
| Azure XML | `azure-xml.jar` | 240.8 KB |
| Azure Storage Blob | `azure-storage-blob.jar` | 863.7 KB |
| Azure Storage Common | `azure-storage-common.jar` | 129.2 KB |
| Kiota Abstractions | `microsoft-kiota-abstractions.jar` | 82.8 KB |
| Kiota Auth Azure | `microsoft-kiota-authentication-azure.jar` | 6.1 KB |
| Kiota HTTP OkHttp | `microsoft-kiota-http-okHttp.jar` | 59.9 KB |
| Kiota Serialization (JSON/form/text/multipart) | 4 JARs | ~52 KB |
| OpenTelemetry API | `opentelemetry-api.jar` | 159.0 KB |
| OpenTelemetry Common | `opentelemetry-common.jar` | 2.1 KB |
| OpenTelemetry Context | `opentelemetry-context.jar` | 49.4 KB |

---

## Appendix A: Collector Agent Variants

| Variant | Binary | Size | Target OS |
|---|---|---|---|
| Full (with libraries) | `collector\CyberTriageCollector_Libs.exe` | 7.9 MB | Windows 7+ (bundles all DLLs) |
| No external libraries | `collector_nolibs\CyberTriageCollector.exe` | 9.4 MB | Windows 7+ (static linked) |
| UAC-elevated | `collector_uac\CyberTriageCollector_Libs_UAC.exe` | - | Windows 7+ (requests admin elevation) |
| Vista compatible | `collector_vistanolibs\CyberTriageCollector_Vista.exe` | - | Windows Vista (legacy API support) |
| XP compatible | `collector_xpnolibs\CyberTriageCollector_XP.exe` | - | Windows XP (minimal API surface) |

Each variant also includes `CyberTriageCollectorGUI.exe` (~1.3 MB) for interactive use.

---

## Appendix B: Full Directory Layout

```
C:\Program Files\Cyber Triage\cybertriage\
  bitsparser\             BitsParser_0a2b51e.exe + OpenSSL
  cloudrules\             CloudRules_rv3160001.json.gz
  collector\              CyberTriageCollector_Libs.exe + GUI
  collector_nolibs\       CyberTriageCollector.exe + GUI
  collector_uac\          CyberTriageCollector_Libs_UAC.exe + GUI
  collector_vistanolibs\  CyberTriageCollector_Vista.exe + GUI
  collector_xpnolibs\     CyberTriageCollector_XP.exe + GUI
  config\                 settings.yml, module configs
  core\                   locale\core_cybertriage.jar
  cred_manager\           CredentialUpdateManager.exe
  demo_data\              cybertriage_evaldata_2025-11-12.json.gz
  EULA\                   License agreements
  evtexport\              evtexport.exe, evtinfo.exe, libevt.dll
  evtx_dump\              evtx_dump-v0.9.0.exe
  geolite2\               GeoLite2-Country.mmdb
  hayabusa\               hayabusa.exe, encoded_rules.yml, config/, exclude_rules.txt
  integrations\autopsy\   cybertriage_importer_1.0.5.nbm
  keytool\                keytool.exe (Java keystore management)
  lib_esedb\              esedbexport_16d65f0.exe, esedbinfo_16d65f0.exe
  memprocfs_packager\     memprocfs_packager.exe, memprocfs\ (vmm.dll, vmmyara.dll, ...)
  modules\                com-basistech-df-cyberTriage-core.jar + ext\ libraries
                            ext\com-azure\  (azure-core, azure-identity, azure-storage-*)
                            ext\com-microsoft-azure\  (msal4j, msal4j-persistence-extension)
                            ext\com-microsoft-graph\  (microsoft-graph.jar 56MB, microsoft-graph-core)
                            ext\com-microsoft-kiota\  (kiota abstractions, auth, http, serialization)
  pasco2\                 pasco2-1.0.0.jar + dependencies
  search_engine\          SEUQAMappings.xml
  service\                CyberTriageService.exe
  update_tracking\        (version tracking)
  volatility\             volatility-a438e76.exe, plugins.zip
  wmi\                    collectWMIPersistence.exe
  yara\                   CyberTriageYara.exe, yarac64.exe
  yara_precompiled_rules\ onenote\, screenconnect\, sliver_binary\, webshells\
```
