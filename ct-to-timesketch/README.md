# CyberTriage to Timesketch

A pure Go binary that converts [CyberTriage](https://www.cybertriage.com/) forensic capture files to [Timesketch](https://timesketch.org/) JSONL format, with optional [Hayabusa](https://github.com/Yamato-Security/hayabusa) Sigma-based and [CyberTriage CloudRules](https://www.cybertriage.com/) threat detection.

## Overview

CyberTriage exports forensic data in compressed JSON format (`.json.gz`). This tool:

- **Streams** the capture in a single pass, extracting timeline events and exporting collected files as native artifacts to disk
- **Parses** all supported artifact types automatically -- no flags needed
- **Detects** threats via Hayabusa Sigma rules on exported EVTX files (optional)
- **Analyzes** with CyberTriage CloudRules -- 386 Go-native threat detection rules across 12 plugin types (optional)
- **Generates** comprehensive forensic timelines ready for Timesketch import

## Performance

The entire pipeline is a single Go binary with a custom byte-level streaming JSON parser. All forensic extractors run unconditionally on every capture.

| Capture Size | Total Time | Events     | Throughput |
|--------------|------------|------------|------------|
| 1.9 GB       | ~59s       | 3,276,116  | ~32 MB/s   |

## Quick Start

```bash
# Build the binary (requires Go 1.21+)
go build -o ct-to-timesketch ./cmd/ct-to-timesketch/

# Convert a CyberTriage capture -- all extractors run automatically
./ct-to-timesketch capture.json.gz

# With Hayabusa threat detection
./ct-to-timesketch capture.json.gz --hayabusa

# With CyberTriage CloudRules threat detection
./ct-to-timesketch capture.json.gz --cloudrules

# With both threat detection engines
./ct-to-timesketch capture.json.gz --hayabusa --cloudrules

# Re-run extractors against previously exported artifacts (skip streaming scan)
./ct-to-timesketch capture.json.gz --skip-base

# Cloud log inputs
./ct-to-timesketch sign_in_logs.json --entra
./ct-to-timesketch url_clicks.csv --mdo
```

## CLI Options

| Option | Description |
|--------|-------------|
| `--output FILE` / `-o FILE` | Output JSONL path (default: `reports/<hostname>_timeline.jsonl`) |
| `--artifacts-dir DIR` | Artifacts directory (default: `artifacts/<hostname>/`) |
| `--skip-base` | Skip streaming scan; re-run extractors against existing artifacts |
| `--hayabusa` | Run Hayabusa Sigma threat detection on exported EVTX files |
| `--hayabusa-path PATH` | Explicit path to Hayabusa binary (auto-detected if omitted) |
| `--cloudrules` | Run CyberTriage CloudRules threat detection on all timeline events |
| `--cloudrules-path PATH` | Explicit path to CloudRules json.gz (auto-detected if omitted) |
| `--entra` | Input is Entra ID / Azure AD sign-in JSON |
| `--mdo` | Input is Microsoft Defender for Office 365 CSV |
| `--list-extractors` | Show all extractors and exit |
| `--version` | Print version and exit |

No `--parse-*` flags exist. Every registered extractor runs on every capture. At under 60 seconds for multi-GB captures, selective parsing is unnecessary and risks missing forensic artifacts.

## Built-in Help System

The tool includes a hierarchical help system modeled after the Azure CLI, designed for both human operators and agentic AI discovery:

```bash
# Show topic index
./ct-to-timesketch help

# Deep dive into a specific topic
./ct-to-timesketch help pipeline      # End-to-end processing stages
./ct-to-timesketch help extractors    # All 14 extractors with event types and fields
./ct-to-timesketch help cloudrules    # 12 plugin types, scoring model, enrichment
./ct-to-timesketch help hayabusa      # Sigma detection, severity levels, binary discovery
./ct-to-timesketch help output        # Complete JSONL field reference and tag structure
./ct-to-timesketch help cloud         # Entra ID and MDO modes with export instructions
./ct-to-timesketch help examples      # Usage patterns, automation, and AI integration
```

Every help page is pure structured text with no ANSI colors or paging, making it fully parseable by LLM agents via simple pipe/capture. The extractor list is dynamically generated from the registry at runtime.

## Extractors

All extractors run automatically on every CyberTriage capture:

| Category | Extractor | Description |
|----------|-----------|-------------|
| **Streaming** | Base Artifacts | Processes, logons, events, network, DNS, services, tasks |
| **Streaming** | MFT | NTFS file system timeline (MACB timestamps) |
| **Event Logs** | EVTX | Raw Windows Event Logs with full EventData extraction |
| **Registry** | Registry | ShellBags, UserAssist, BAM, USB, Services, ShimCache |
| **Execution** | Prefetch | Program execution artifacts |
| **Execution** | SRUM | System Resource Usage (app usage, network data) |
| **Execution** | Scheduled Tasks | Task XML files (persistence) |
| **User Activity** | Browser | Chrome, Edge, Firefox history |
| **User Activity** | LNK | Windows shortcut files |
| **User Activity** | PowerShell | Command history |
| **User Activity** | Timeline | Windows Timeline (ActivitiesCache.db) |
| **User Activity** | Recycle Bin | Deleted file metadata |
| **Server** | DHCP | DHCP Server logs |
| **Persistence** | WMI | WMI persistence detection |
| **Cloud** | Entra ID | Azure AD sign-in and audit logs (requires `--entra`) |
| **Cloud** | MDO | Defender for Office 365 events (requires `--mdo`) |

## Native Artifacts

The streaming scan exports all collected files to `artifacts/<hostname>/` in their native format:

```
artifacts/HOST.domain.com/
├── Windows/System32/winevt/Logs/
│   ├── Security.evtx
│   ├── System.evtx
│   └── ...
├── Windows/System32/config/
│   ├── SOFTWARE
│   ├── SYSTEM
│   └── ...
├── Users/jsmith/NTUSER.DAT
└── ...
```

These native files are parsed directly by the binary extractors (EVTX, Registry, SRUM, etc.) and are also available for independent post-processing with external tools.

## Hayabusa Threat Detection

When `--hayabusa` is specified and the [Hayabusa](https://github.com/Yamato-Security/hayabusa) binary is available, Sigma detection rules are applied to the exported EVTX files. Matching events receive:

- Tags: `hayabusa`, `sigma`, `hayabusa:<level>`
- Attributes: `hayabusa_rule`, `hayabusa_level`, `hayabusa_rule_id`, `mitre_attack`
- Detection summary printed to console

Install Hayabusa on your PATH or specify the location with `--hayabusa-path`.

## CloudRules Threat Detection

When `--cloudrules` is specified, the tool loads CyberTriage CloudRules (a `json.gz` rule set) and evaluates them **natively in Go** against all timeline events. Unlike Hayabusa (which shells out to an external binary), CloudRules is a built-in analysis engine covering 12 plugin types:

| Plugin | Rules | What it detects |
|--------|-------|-----------------|
| FileCorrelated | 122 | Suspicious executables by name, path, and arguments |
| PowershellArgs | 78 | Malicious PowerShell command patterns |
| Domain | 64 | Known exfiltration, C2, and suspicious domains |
| RemoteManagement | 45 | Remote management/access software (RMM tools) |
| EventsMatching | 38 | Specific Windows event log patterns (Defender, firewall) |
| ExecutableType | 18 | Data transfer and exfiltration tools |
| LibNotOnDisk | 16 | DLL injection indicators |
| + 5 supporting | 28 | Impact mapping, malware downgrade, exclusions |

Matching events receive:

- Tags: `cloudrules`, `cloudrules:<score>` (notable, likely_notable, unknown)
- Attributes: `cloudrules_rule`, `cloudrules_score`, `cloudrules_analysis_type`, `cloudrules_justification`, `cloudrules_impact`, `mitre_attack`

Place the CloudRules file in `cloudrules/` beside the binary, or specify with `--cloudrules-path`. A bundled rule set is included in the repository.

## Architecture

```
capture.json.gz
    │
    ▼
Decompress to .json.cache
    │
    ▼
Streaming Scan (single-pass byte-level JSON parser)
    ├── Creates timeline events (MFT, processes, logons, DNS, etc.)
    └── Exports collected files to artifacts/<hostname>/
            │
            ▼
    File-Based Extractors (all run automatically)
    ├── EVTX parser (pure Go)
    ├── Registry parser (pure Go)
    ├── SRUM / ESE parser (pure Go)
    ├── Browser history (SQLite)
    ├── LNK / Prefetch / Timeline
    └── PowerShell / Recycle Bin / WMI / DHCP / Scheduled Tasks
            │
            ▼ (optional)
    Hayabusa Sigma Detection
    ├── Runs against native EVTX files
    └── Tags matching events with detection metadata
            │
            ▼ (optional)
    CloudRules Threat Detection (Go-native)
    ├── Evaluates 386 rules across 12 plugin types
    └── Tags matching events with threat scores and MITRE mapping
            │
            ▼
Write JSONL timeline
```

## Output Format

The tool generates Timesketch-compatible JSONL:

```json
{
  "datetime": "2023-01-15T14:30:00.000Z",
  "timestamp_desc": "Windows Event Log Entry",
  "message": "RDP session logon: DOMAIN\\jsmith from 10.0.1.50",
  "data_type": "windows:evtx:record",
  "event_type": "windows_rdp",
  "source_short": "CT-EventLog",
  "host_name": "WORKSTATION-01"
}
```

## Requirements

- Go 1.21+ (build time only)
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) (optional, for `--hayabusa`)
- CloudRules `json.gz` (bundled in `cloudrules/`, for `--cloudrules`)

No Python, no pip, no external dependencies at runtime. The binary is self-contained.

## Project Structure

```
ct-to-timesketch/
├── cmd/ct-to-timesketch/     # CLI entry point
│   └── main.go
├── internal/
│   ├── cache/                # Decompression and artifact indexing
│   ├── converter/            # Timesketch event builder and JSONL writer
│   ├── extractors/           # File-based artifact extractors
│   │   ├── all/              # Auto-registration of all extractors
│   │   ├── evtx/             # Windows Event Log parser
│   │   ├── registry/         # Registry hive parser
│   │   ├── srum/             # SRUM ESE database parser
│   │   ├── browser/          # Chrome/Edge/Firefox history
│   │   ├── lnk/              # Windows shortcut parser
│   │   ├── prefetch/         # Prefetch file parser
│   │   ├── timeline/         # Windows Timeline (ActivitiesCache.db)
│   │   ├── powershell/       # PowerShell history
│   │   ├── recyclebin/       # Recycle Bin metadata
│   │   ├── wmi/              # WMI persistence
│   │   ├── dhcp/             # DHCP server logs
│   │   ├── scheduled_tasks/  # Task XML files
│   │   ├── entra/            # Entra ID / Azure AD logs
│   │   └── mdo/              # Microsoft Defender for Office 365
│   ├── help/                 # Hierarchical help system (az-style topic pages)
│   ├── postprocess/          # Post-extraction analysis (Hayabusa, CloudRules)
│   ├── scanner/              # Streaming JSON parser + artifact export
│   └── progress/             # Console output and progress reporting
├── schemas/                  # Data type schemas and field definitions
├── cloudrules/               # Bundled CyberTriage CloudRules rule set
├── docs/analysis/            # CyberTriage format specs and CloudRules reference
├── captures/                 # Input files (gitignored)
├── artifacts/                # Exported native artifacts (gitignored)
└── reports/                  # Generated JSONL timelines (gitignored)
```

## Timesketch Integration

After generating a JSONL timeline:

1. Access your Timesketch instance
2. Create or open a sketch
3. Upload the generated `.jsonl` file
4. Analyze the timeline with Timesketch's search and visualization tools

## Reference Documentation

The `docs/analysis/` directory contains detailed specifications and analysis that informed this tool's design:

| Document | Description |
|----------|-------------|
| [CYBERTRIAGE_JSON_GZ_SPEC.md](docs/analysis/CYBERTRIAGE_JSON_GZ_SPEC.md) | CyberTriage `.json.gz` capture file format specification |
| [CLOUDRULES_SPEC.md](docs/analysis/CLOUDRULES_SPEC.md) | CloudRules engine specification -- plugin types, matching logic, event field mapping |
| [CLOUDRULES_ANALYSIS.md](docs/analysis/CLOUDRULES_ANALYSIS.md) | CloudRules rule inventory -- 386 rules across 12 plugin types with detection categories |
| [CT_PROCESSING_PIPELINE.md](docs/analysis/CT_PROCESSING_PIPELINE.md) | End-to-end processing pipeline architecture and data flow |
| [CT_TO_TIMESKETCH_GAP_REPORT.md](docs/analysis/CT_TO_TIMESKETCH_GAP_REPORT.md) | Coverage analysis -- what CyberTriage artifacts map to Timesketch events |
| [STEALTH_EXTRACTION_RUNBOOK.md](docs/analysis/STEALTH_EXTRACTION_RUNBOOK.md) | Operational runbook for forensic data extraction workflows |

## See Also

- [Timesketch](https://timesketch.org/) - Collaborative forensic timeline analysis
- [CyberTriage](https://www.cybertriage.com/) - Incident response triage tool
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Sigma-based Windows Event Log threat detection
- [Plaso](https://plaso.readthedocs.io/) - Log2timeline super timeline tool
