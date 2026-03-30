# Windows Data Types Reference

This document provides a comprehensive reference of all Windows-related data types supported by ct-to-timesketch, following Plaso/Timesketch naming conventions.

**Last Updated:** 2026-01-03  
**Version:** 2.3.0

---

## Table of Contents

1. [Overview](#overview)
2. [Implemented Data Types](#implemented-data-types)
   - [Windows Event Logs](#windows-event-logs-evtx)
   - [Registry - User Activity](#registry---user-activity)
   - [Registry - System](#registry---system)
   - [Registry - Startup/Autorun](#registry---startupautorun)
   - [Registry - RDP/MSTSC](#registry---rdpmstsc)
   - [Registry - Network Shares](#registry---network-shares)
   - [Amcache](#amcache)
   - [Task Scheduler](#task-scheduler)
   - [File System (NTFS)](#file-system-ntfs)
   - [LNK Files](#lnk-files)
   - [Prefetch](#prefetch)
   - [Browser History](#browser-history)
   - [WebCache](#webcache-ieedge)
   - [PowerShell](#powershell)
   - [Network Connections](#network-connections)
   - [SRUM](#srum-system-resource-usage-monitor)
   - [Windows Timeline](#windows-timeline-activitiescachedb)
   - [User Access Logging](#user-access-logging-ual)
   - [DHCP Server Logs](#dhcp-server-logs)
3. [Roadmap - Not Yet Implemented](#roadmap---not-yet-implemented)
4. [CSV Reference File](#csv-reference-file)
5. [Timesketch Query Examples](#timesketch-query-examples)

---

## Overview

ct-to-timesketch converts CyberTriage forensic captures to Timesketch JSONL format using Plaso-compatible data types. This ensures compatibility with:

- Timesketch's built-in analyzers
- Sigma rules
- Plaso timeline tools
- Standard DFIR workflows

### Data Type Naming Convention

Data types follow the Plaso naming scheme:
```
{category}:{subcategory}:{artifact}
```

Examples:
- `windows:evtx:record` - Windows Event Log record
- `windows:registry:sam_users` - SAM user account
- `fs:stat:ntfs:$standard_information` - NTFS $SI timestamps

---

## Implemented Data Types

### Windows Event Logs (EVTX)

**Data Type:** `windows:evtx:record`

**Source:** EVTX Extractor, SystemAPI Converter

| Field | Type | Description |
|-------|------|-------------|
| `source_name` | str | Event provider name (e.g., Microsoft-Windows-Security-Auditing) |
| `channel` | str | Event log channel (Security, System, Application, etc.) |
| `event_identifier` | str | Windows Event ID |
| `computer_name` | str | Computer name from event record |
| `record_number` | str | Event record number |
| `user_sid` | str | User SID from event record |

**Example Event:**
```json
{
  "data_type": "windows:evtx:record",
  "source_name": "Microsoft-Windows-Security-Auditing",
  "channel": "Security",
  "event_identifier": "4624",
  "computer_name": "DC01.domain.local"
}
```

**Timesketch Query:**
```
data_type:"windows:evtx:record" AND event_identifier:4624
```

---

### Registry - User Activity

#### UserAssist

**Data Type:** `windows:registry:userassist`

| Field | Type | Description |
|-------|------|-------------|
| `value_name` | str | Decoded UserAssist entry (program path) |
| `key_path` | str | Registry key path |

#### RecentDocs

**Data Type:** `windows:registry:recentdocs`

| Field | Type | Description |
|-------|------|-------------|
| `key_path` | str | Registry key path |

#### TypedURLs/TypedPaths

**Data Type:** `windows:registry:typedurls`

| Field | Type | Description |
|-------|------|-------------|
| `typed_paths` | str | Comma-separated list of typed URLs/paths |
| `key_path` | str | Registry key path |

#### MRU List (Run Dialog)

**Data Type:** `windows:registry:mrulist`

| Field | Type | Description |
|-------|------|-------------|
| `commands` | str | Comma-separated list of MRU commands |
| `key_path` | str | Registry key path |

#### ShellBags

**Data Type:** `windows:registry:bagmru`

| Field | Type | Description |
|-------|------|-------------|
| `key_path` | str | ShellBag registry key path |

---

### Registry - System

#### SAM Users

**Data Type:** `windows:registry:sam_users`

| Field | Type | Description |
|-------|------|-------------|
| `username` | str | User account name |
| `account_rid` | int | Account Relative Identifier |
| `key_path` | str | Registry key path |
| `last_written_time` | datetime | Entry last modified |
| `login_count` | int | Number of logins |
| `last_login_time` | datetime | Last login timestamp |
| `last_password_set_time` | datetime | Last password change |
| `user_domain` | str | User domain |
| `user_sid` | str | User SID |
| `account_type` | str | Account type (Regular, Service) |
| `account_status` | str | Status (Active, Disabled) |
| `admin_priv` | str | Admin privilege level |
| `home_dir` | str | Home directory path |
| `expiration_date` | datetime | Account expiration date |

#### Services

**Data Type:** `windows:registry:services`

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | str | Windows service name |
| `image_path` | str | Service executable path |

#### USB Storage

**Data Type:** `windows:registry:usbstor`

| Field | Type | Description |
|-------|------|-------------|
| `device_description` | str | USB device description |
| `serial_number` | str | Device serial number |

#### Installed Software

**Data Type:** `windows:registry:uninstall`

| Field | Type | Description |
|-------|------|-------------|
| `software_name` | str | Display name |
| `publisher` | str | Publisher name |

---

### Registry - Startup/Autorun

**Data Type:** `windows:registry:run`

| Field | Type | Description |
|-------|------|-------------|
| `configType` | str | Configuration item type |
| `description` | str | Startup item description |
| `details` | str | Startup item details/path |
| `arguments` | str | Command line arguments |
| `userID` | str | Associated user ID |
| `registryKey` | str | Registry key path |
| `registryValue` | str | Registry value name |

---

### Registry - RDP/MSTSC

**Data Type:** `windows:registry:mstsc:connection`

| Field | Type | Description |
|-------|------|-------------|
| `entries` | str | Remote host/server name |
| `username` | str | Username hint |
| `key_path` | str | Registry key path |
| `last_written_time` | datetime | Entry last modified |
| `remote_domain` | str | Remote domain |
| `local_user` | str | Local user who connected |
| `user_sid` | str | User SID |

---

### Registry - Network Shares

**Data Type:** `windows:registry:mountpoints2`

| Field | Type | Description |
|-------|------|-------------|
| `remoteHostName` | str | Remote host name |
| `remoteShareName` | str | Share name |
| `userID` | str | User ID |
| `userSID` | str | User SID |

---

### Amcache

#### Application Execution Evidence

**Data Type:** `windows:registry:amcache`

| Field | Type | Description |
|-------|------|-------------|
| `sha1_hash` | str | SHA1 hash of executable |
| `file_path` | str | Full executable path |
| `file_name` | str | Executable filename |
| `publisher` | str | Software publisher |
| `product_name` | str | Product name |
| `product_version` | str | Product version |
| `file_version` | str | File version (PE header) |
| `binary_type` | str | Binary type (32/64-bit) |
| `file_size` | int | File size in bytes |
| `language` | str | Language code |
| `program_id` | str | Program identifier |
| `file_id` | str | File identifier |
| `sha256_hash` | str | SHA256 hash |

#### Installed Programs (Add/Remove Programs)

**Data Type:** `windows:registry:amcache:inventory_application`

| Field | Type | Description |
|-------|------|-------------|
| `program_name` | str | Program name (Add/Remove Programs) |
| `publisher` | str | Software publisher |
| `version` | str | Installed version |
| `language` | int | Language code |
| `install_date` | str | Installation date |
| `install_source` | str | Installation method (MSI, AppxPackage) |
| `install_path` | str | Installation directory |
| `uninstall_string` | str | Uninstall command |
| `registry_key_path` | str | Uninstall registry key |
| `msi_product_code` | str | MSI product code GUID |
| `msi_package_code` | str | MSI package code GUID |
| `hidden_from_arp` | bool | Hidden from Add/Remove Programs |
| `is_inbox_app` | bool | Windows built-in app |
| `store_app_type` | str | Windows Store app type |
| `package_full_name` | str | Full package name |

---

### Task Scheduler

#### TaskCache Registry

**Data Type:** `task_scheduler:task_cache:entry`

| Field | Type | Description |
|-------|------|-------------|
| `task_name` | str | Task name/path |
| `task_identifier` | str | Task GUID |
| `key_path` | str | Registry key path |
| `last_written_time` | datetime | Entry last modified |
| `last_registered_time` | datetime | Task registration time |
| `launch_time` | datetime | Last launch time |
| `unknown_time` | datetime | Unknown time from DynamicInfo |

#### Running Tasks/Processes

**Data Type:** `windows:tasks:job`

| Field | Type | Description |
|-------|------|-------------|
| `processName` | str | Process name |
| `processPath` | str | Executable path |
| `pid` | int | Process ID |
| `commandLine` | str | Command line |
| `userID` | str | User ID |

---

### File System (NTFS)

#### $STANDARD_INFORMATION Timestamps

**Data Type:** `fs:stat:ntfs:$standard_information`

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | str | Full file path |
| `file_size` | int | File size in bytes |
| `meta_type` | str | Metadata type (File, Dir) |
| `md5` | str | MD5 hash |
| `sha256` | str | SHA256 hash |
| `is_source_file` | bool | Forensic source file |

#### $FILE_NAME Timestamps

**Data Type:** `fs:stat:ntfs:$file_name`

| Field | Type | Description |
|-------|------|-------------|
| `file_path` | str | Full file path |

**Note:** $FILE_NAME timestamps are useful for detecting timestomping - compare with $SI timestamps.

---

### LNK Files

**Data Type:** `windows:lnk:link`

| Field | Type | Description |
|-------|------|-------------|
| `lnk_file` | str | LNK filename |
| `lnk_path` | str | LNK file path |
| `link_target` | str | Target path |

---

### Prefetch

**Data Type:** `windows:prefetch:execution`

| Field | Type | Description |
|-------|------|-------------|
| `executable` | str | Executed program name |
| `prefetch_file` | str | Prefetch filename |
| `prefetch_path` | str | Prefetch file path |
| `run_count` | int | Execution count |

---

### Browser History

#### Chrome/Edge/Brave

**Data Type:** `chrome:history:page_visited`

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Visited URL |
| `title` | str | Page title |
| `visit_count` | int | Visit count |
| `browser_type` | str | Browser type (Chrome, Edge, Brave) |

#### Firefox

**Data Type:** `firefox:places:page_visited`

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Visited URL |
| `title` | str | Page title |
| `visit_count` | int | Visit count |
| `browser_type` | str | Browser type (Firefox) |

---

### WebCache (IE/Edge)

**Data Type:** `msiecf:url`

| Field | Type | Description |
|-------|------|-------------|
| `url` | str | Cached URL |
| `container` | str | Container name |
| `access_count` | int | Access count |
| `username` | str | Associated username |
| `webcache_file` | str | WebCache file path |

---

### PowerShell

**Data Type:** `windows:powershell:console_history`

| Field | Type | Description |
|-------|------|-------------|
| `command` | str | Executed command |
| `command_index` | int | Command index in history |
| `total_commands` | int | Total commands in file |
| `username` | str | Username |
| `history_file` | str | History file path |
| `suspicious` | bool | Matches suspicious patterns |

---

### Network Connections

**Data Type:** `windows:network:connection`

| Field | Type | Description |
|-------|------|-------------|
| `localIP` | str | Local IP address |
| `localPort` | int | Local port |
| `remoteIP` | str | Remote IP address |
| `remotePort` | int | Remote port |
| `connectionType` | str | Connection type (TCP, UDP) |
| `pid` | int | Process ID |

---

### SRUM (System Resource Usage Monitor)

SRUM provides ~30 days of historical application execution and network usage data, even if other artifacts have been deleted.

#### Application Resource Usage

**Data Type:** `windows:srum:application_usage`

| Field | Type | Description |
|-------|------|-------------|
| `application` | str | Application path or name |
| `identifier` | int | SRUM entry ID |
| `user_identifier` | str | User SID |
| `foreground_cycle_time` | int | CPU cycles in foreground (100-ns intervals) |
| `background_cycle_time` | int | CPU cycles in background |
| `face_time` | int | User interaction time |
| `foreground_context_switches` | int | Context switch count (foreground) |
| `foreground_bytes_read` | int | Disk bytes read (foreground) |
| `foreground_bytes_written` | int | Disk bytes written (foreground) |
| `foreground_read_operations` | int | Read operation count |
| `foreground_write_operations` | int | Write operation count |
| `background_bytes_read` | int | Disk bytes read (background) |
| `background_bytes_written` | int | Disk bytes written (background) |

**Forensic Value:**
- Proves program execution even if Prefetch/Amcache deleted
- ~30 days of historical execution data
- CPU time indicates active usage vs. idle processes

**Timesketch Query:**
```
data_type:"windows:srum:application_usage" AND application:*powershell*
```

#### Network Connectivity

**Data Type:** `windows:srum:network_connectivity`

| Field | Type | Description |
|-------|------|-------------|
| `application` | str | Application path or name |
| `identifier` | int | SRUM entry ID |
| `user_identifier` | str | User SID |
| `interface_luid` | int | Network interface LUID |
| `interface_type` | str | Interface type (Ethernet, WiFi, etc.) |
| `connected_time` | int | Connection duration (seconds) |
| `connect_start_time` | datetime | Connection start time |

**Forensic Value:**
- Network connection history per application
- Identifies WiFi vs Ethernet vs VPN usage
- Useful for lateral movement/C2 detection

**Timesketch Query:**
```
data_type:"windows:srum:network_connectivity" AND interface_type:WiFi
```

#### Network Data Usage

**Data Type:** `windows:srum:network_usage`

| Field | Type | Description |
|-------|------|-------------|
| `application` | str | Application or network interface name |
| `identifier` | int | SRUM entry ID |
| `user_identifier` | str | User SID |
| `bytes_received` | int | Bytes received (inbound) |
| `bytes_sent` | int | Bytes sent (outbound) |
| `bytes_total` | int | Total bytes transferred |
| `interface_luid` | int | Network interface LUID |

**Forensic Value:**
- Network data usage per application/interface
- Identifies high-bandwidth applications
- Useful for data exfiltration detection

**Timesketch Query:**
```
data_type:"windows:srum:network_usage" AND bytes_sent:>1000000000
```

---

### Windows Timeline (ActivitiesCache.db)

The Windows Timeline feature (introduced in Windows 10) records user activities such as
opened documents, visited websites, and executed applications. Data is stored in the
`ActivitiesCache.db` SQLite database.

**Database Location:** `%LocalAppData%\ConnectedDevicesPlatform\<user>\ActivitiesCache.db`

**CLI Flag:** `--parse-timeline`

#### Generic Activities

**Data Type:** `windows:timeline:generic`

| Field | Type | Description |
|-------|------|-------------|
| `application` | str | Application name or identifier |
| `package_identifier` | str | Application package name |
| `activity_identifier` | str | Unique activity ID (GUID) |
| `activity_type` | int | Activity type (5=Open, 10=Clipboard, 11=Settings, 16=Launch) |
| `activity_status` | int | Activity status code |
| `start_time` | str | Activity start timestamp |
| `end_time` | str | Activity end timestamp |
| `duration` | int | Activity duration in seconds |
| `tag` | str | Activity tag or description |
| `group` | str | Activity group identifier |
| `platform` | str | Platform (windows/android/ios) |
| `is_local_only` | bool | Whether activity is local-only |
| `device_id` | str | Device identifier |

**Activity Types:**
- Type 5: Open File/Document
- Type 6: App in Focus (User Engaged)
- Type 10: Clipboard
- Type 11: System Settings
- Type 16: App Launch

**Forensic Value:**
- Application launch history
- File/document access patterns
- User activity timeline reconstruction
- Cross-device activity sync

**Timesketch Query:**
```
data_type:"windows:timeline:generic" AND activity_type:16
```

#### User Engagement

**Data Type:** `windows:timeline:user_engaged`

| Field | Type | Description |
|-------|------|-------------|
| `application` | str | Application name |
| `package_identifier` | str | Application package name |
| `active_duration_seconds` | int | Time user was actively engaged |
| `start_time` | str | Engagement start timestamp |
| `end_time` | str | Engagement end timestamp |
| `activity_identifier` | str | Unique activity ID (GUID) |
| `platform` | str | Platform identifier |
| `device_id` | str | Device identifier |

**Forensic Value:**
- User attention/focus patterns
- Application foreground time
- Productivity analysis
- Identify which apps user actively used vs background processes

**Timesketch Query:**
```
data_type:"windows:timeline:user_engaged" AND active_duration_seconds:>3600
```

---

### User Access Logging (UAL)

Windows Server User Access Logging tracks all client connections to server roles.
**Critical for detecting unauthorized remote access and lateral movement.**

**Database Location:** `%SystemRoot%\System32\LogFiles\Sum\Current.mdb`

**CLI Flag:** `--parse-ual`

#### Client Access Records

**Data Type:** `windows:user_access_logging:clients`

| Field | Type | Description |
|-------|------|-------------|
| `source_address` | str | Client IP address |
| `username` | str | Authenticated username (domain\user) |
| `client_name` | str | Client computer name |
| `role_identifier` | str | Service role GUID |
| `role_name` | str | Service role name (AD, File Server, etc.) |
| `access_count` | int | Total number of accesses |
| `first_seen_time` | str | First access timestamp |
| `last_seen_time` | str | Last access timestamp |

**Server Roles Tracked:**
- Active Directory Domain Services
- Active Directory Certificate Services
- DHCP Server
- DNS Server
- File Server
- Web Server
- Remote Access
- Print Services
- And more...

**Forensic Value:**
- **Unauthorized Access Detection**: See who connected from where
- **Lateral Movement**: Track threat actor movement across network
- **Service Abuse**: Identify excessive access to specific services
- **Timeline Reconstruction**: Correlate with other artifacts

**Timesketch Query:**
```
data_type:"windows:user_access_logging:clients" AND role_name:"Remote Access"
```

#### DNS Query Records

**Data Type:** `windows:user_access_logging:dns`

| Field | Type | Description |
|-------|------|-------------|
| `client_address` | str | DNS client IP address |
| `hostname` | str | Queried hostname |

**Forensic Value:**
- DNS query history per client
- C2 domain detection
- Internal resource enumeration

**Timesketch Query:**
```
data_type:"windows:user_access_logging:dns" AND hostname:*malicious*
```

---

### DHCP Server Logs

Windows DHCP Server maintains audit logs that record all DHCP lease operations.
**Critical for client infrastructure mapping, device inventory, and lateral movement tracking.**

**Log Location:** `%SystemRoot%\System32\Dhcp\DhcpSrvLog-{Day}.log`

**CLI Flag:** `--parse-dhcp`

#### DHCP Server Log Events

**Data Type:** `windows:dhcp:server_log`

| Field | Type | Description |
|-------|------|-------------|
| `dhcp_event_id` | str | DHCP event ID (10=New Lease, 11=Renew, 12=Release, etc.) |
| `dhcp_description` | str | Human-readable event description |
| `ip_address` | str | Assigned/requested IP address |
| `hostname` | str | Client hostname |
| `mac_address` | str | Client MAC address (formatted XX:XX:XX:XX:XX:XX) |
| `username` | str | Associated username (if available) |
| `transaction_id` | str | DHCP transaction identifier |
| `q_result` | str | Query result code |
| `correlation_id` | str | Correlation ID for related events |
| `vendor_class` | str | Client vendor class (e.g., "MSFT 5.0") |
| `user_class` | str | Client user class |
| `log_file` | str | Source log file name |
| `forensic_priority` | str | High-priority forensic event indicator |

**Key Event IDs:**

| ID | Event Type | Description |
|----|-----------|-------------|
| 10 | `dhcp_lease_new` | New IP lease assigned to client |
| 11 | `dhcp_lease_renew` | Existing lease renewed |
| 12 | `dhcp_lease_release` | Client released the lease |
| 13 | `dhcp_ip_conflict` | IP address conflict detected |
| 14 | `dhcp_lease_denied` | Lease request denied |
| 15 | `dhcp_lease_expired` | Lease expired |
| 16 | `dhcp_lease_deleted` | Lease deleted from server |
| 17 | `dhcp_auth_failed` | DHCP server authorization failed |
| 18 | `dhcp_auth_success` | DHCP server authorization succeeded |
| 24-25 | `dhcp_dns_update/failed` | Dynamic DNS update events |
| 30-34 | `dhcp_dns_*` | DNS registration events |
| 60-64 | `dhcp_rogue_*` | Rogue DHCP server detection events |

**Forensic Value:**
- **Complete Client Inventory**: Every device that requested an IP is logged
- **Network Topology**: Map which subnets have which devices
- **Device Identification**: MAC addresses for physical device tracking
- **Historical Presence**: When devices were on the network
- **Rogue Device Detection**: Unknown MAC addresses
- **Lateral Movement Tracking**: IP changes over time

---

#### Network Administrator Guide

This section provides practical guidance for network administrators to use DHCP data for infrastructure mapping, device inventory, and troubleshooting.

##### Network Infrastructure Mapping

DHCP logs enable comprehensive network infrastructure analysis:

| Analysis Type | Method | Use Case |
|--------------|--------|----------|
| **Subnet Inventory** | Group events by IP /24 prefix | Identify active subnets and their utilization |
| **Device Density** | Count unique MACs per subnet | Find overcrowded or underutilized subnets |
| **Network Topology** | Map IP ranges to hostnames | Understand network segmentation |
| **Growth Tracking** | Compare unique IPs over time | Capacity planning |

**Subnet Analysis Query:**
```
data_type:"windows:dhcp:server_log" AND ip_address:10.1.100.*
```

##### Device Type Identification via Vendor Class

The `vendor_class` field provides device fingerprinting capabilities. Common values observed in enterprise environments:

| Vendor Class | Device Type | Notes |
|--------------|-------------|-------|
| `MSFT 5.0` | Windows clients | Standard Windows DHCP fingerprint (XP through 11) |
| `chromeos` | Chromebooks | Google Chrome OS devices (common in K-12) |
| `android-dhcp-*` | Android devices | Mobile phones/tablets (version in suffix) |
| `yealink` | VoIP phones | Yealink IP phones |
| `Verkada` | Security cameras | Verkada surveillance systems |
| `Cisco AP c*` | Access points | Cisco wireless access points (model in suffix) |
| `udhcp*` | Embedded Linux | IoT devices, embedded systems |
| `dhcpcd-*` | Linux clients | Linux DHCP client daemon |
| `PXEClient:Arch:*` | PXE boot clients | Network boot devices, imaging systems |
| `HP Printer` | HP printers | HP network printers |
| `RicohPrinter` | Ricoh printers | Ricoh network printers |
| `Mfg=Hewlett Packard*` | HP devices | Detailed HP device identification |
| `ubnt` | Ubiquiti | Ubiquiti network devices |
| `ciscopnp` | Cisco PnP | Cisco Plug and Play devices |
| `CISCO SPA*` | Cisco phones | Cisco SPA IP phones |
| `MP202` | Audiocodes | Audiocodes media gateways |
| `Mediatrix*` | Media5 | Media5 VoIP adapters |

**Device Inventory Queries:**

All Windows clients:
```
data_type:"windows:dhcp:server_log" AND vendor_class:"MSFT 5.0"
```

All Chromebooks (common in education):
```
data_type:"windows:dhcp:server_log" AND vendor_class:chromeos
```

All mobile devices:
```
data_type:"windows:dhcp:server_log" AND vendor_class:android*
```

All IoT/embedded devices (non-standard clients):
```
data_type:"windows:dhcp:server_log" AND vendor_class:udhcp*
```

All VoIP phones:
```
data_type:"windows:dhcp:server_log" AND (vendor_class:yealink OR vendor_class:*SPA* OR vendor_class:*phone*)
```

##### Troubleshooting Use Cases

| Issue | Event Type | Query | Action |
|-------|-----------|-------|--------|
| **IP Conflicts** | `dhcp_ip_conflict` | `event_type:"dhcp_ip_conflict"` | Check for static IP conflicts or duplicate MACs |
| **Rogue DHCP Servers** | `dhcp_rogue_*` | `event_type:dhcp_rogue*` | Investigate unauthorized DHCP servers |
| **Authorization Failures** | `dhcp_auth_failed` | `event_type:"dhcp_auth_failed"` | Check AD authorization for DHCP server |
| **DNS Update Failures** | `dhcp_dns_failed` | `event_type:"dhcp_dns_failed"` | Review DNS permissions, scavenging settings |
| **Roaming Devices** | Multiple IPs per MAC | Group by `mac_address` | Normal for mobile devices, investigate if unexpected |
| **Lease Denials** | `dhcp_lease_denied` | `event_type:"dhcp_lease_denied"` | Check scope exhaustion, reservations, or filters |

**High-Priority Security Events:**
```
data_type:"windows:dhcp:server_log" AND forensic_priority:True
```

This returns: IP conflicts, lease denials, authorization failures, and rogue server detections.

##### Field Reference for Network Administrators

| Field | Network Admin Use | Example Query |
|-------|------------------|---------------|
| `ip_address` | Subnet mapping, IP inventory | `ip_address:10.1.100.*` |
| `mac_address` | Physical device tracking, rogue detection | `mac_address:"AA:BB:CC:DD:EE:FF"` |
| `hostname` | Asset inventory correlation, naming compliance | `hostname:*-laptop*` |
| `vendor_class` | Device type categorization, IoT inventory | `vendor_class:chromeos` |
| `dhcp_event_id` | Event filtering (10=new, 11=renew, etc.) | `dhcp_event_id:10` |
| `forensic_priority` | Quick filter for security-relevant events | `forensic_priority:True` |
| `log_file` | Identify which day's log contains events | `log_file:DhcpSrvLog-Mon.log` |

##### Complete Timesketch Query Reference

**Basic Queries:**

All DHCP events:
```
data_type:"windows:dhcp:server_log"
```

All new leases:
```
data_type:"windows:dhcp:server_log" AND event_type:"dhcp_lease_new"
```

Events for specific MAC address:
```
data_type:"windows:dhcp:server_log" AND mac_address:"AA:BB:CC:DD:EE:FF"
```

Events for specific subnet:
```
data_type:"windows:dhcp:server_log" AND ip_address:10.1.100.*
```

**Security-Focused Queries:**

IP conflicts and denied leases:
```
data_type:"windows:dhcp:server_log" AND (event_type:"dhcp_ip_conflict" OR event_type:"dhcp_lease_denied")
```

Rogue DHCP server activity:
```
data_type:"windows:dhcp:server_log" AND event_type:dhcp_rogue*
```

Authorization issues:
```
data_type:"windows:dhcp:server_log" AND (event_type:"dhcp_auth_failed" OR event_type:"dhcp_auth_success")
```

All high-priority forensic events:
```
data_type:"windows:dhcp:server_log" AND forensic_priority:True
```

**Device Inventory Queries:**

Non-Windows devices (IoT/embedded):
```
data_type:"windows:dhcp:server_log" AND vendor_class:* AND NOT vendor_class:"MSFT 5.0"
```

Devices without hostnames (potential rogue):
```
data_type:"windows:dhcp:server_log" AND event_type:"dhcp_lease_new" AND hostname:""
```

Devices by naming pattern:
```
data_type:"windows:dhcp:server_log" AND hostname:*-workstation*
```

**Operational Queries:**

DNS update failures (common issue):
```
data_type:"windows:dhcp:server_log" AND event_type:"dhcp_dns_failed"
```

Lease activity for specific host:
```
data_type:"windows:dhcp:server_log" AND hostname:"workstation01.domain.local"
```

---

## Roadmap - Not Yet Implemented

The following Windows data types from Plaso are relevant for forensics but not yet implemented:

| Data Type | Priority | Description | Requirement |
|-----------|----------|-------------|-------------|
| `windows:recycler` | LOW | Deleted file metadata | $Recycle.Bin parsing |
| `windows:restore_point` | LOW | Restore point metadata | Restore point parsing |

---

## CSV Reference File

A Timesketch-compatible CSV file is available at:
```
schemas/data_types.csv
```

This file follows the same format as the official [Timesketch data_types.csv](https://github.com/google/timesketch/blob/master/data/nl2q/data_types.csv).

---

## Timesketch Query Examples

### Find Failed Logons
```
data_type:"windows:evtx:record" AND event_identifier:4625
```

### Find RDP Connections
```
data_type:"windows:registry:mstsc:connection"
```

### Find Program Executions (Prefetch)
```
data_type:"windows:prefetch:execution"
```

### Find USB Device Connections
```
data_type:"windows:registry:usbstor"
```

### Find Scheduled Tasks
```
data_type:"task_scheduler:task_cache:entry"
```

### Find PowerShell Commands
```
data_type:"windows:powershell:console_history" AND suspicious:True
```

### Find Browser History
```
data_type:"chrome:history:page_visited" OR data_type:"firefox:places:page_visited"
```

### Find Installed Programs
```
data_type:"windows:registry:amcache:inventory_application"
```

---

## References

- [Timesketch data_types.csv](https://github.com/google/timesketch/blob/master/data/nl2q/data_types.csv)
- [Plaso Documentation](https://plaso.readthedocs.io/)
- [SANS Windows Forensics Poster](https://www.sans.org/posters/windows-forensic-analysis/)

