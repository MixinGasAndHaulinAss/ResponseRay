# CyberTriage to Timesketch - Data Types & Field Changelog

This document tracks all changes made to align our data extraction output with the official [Timesketch/Plaso data_types.csv](https://github.com/google/timesketch/blob/master/data/nl2q/data_types.csv) specification.

**Date:** 2026-01-09  
**Version:** 2.6.0

---

## Version 2.6.0 - Microsoft Defender for Office 365 (MDO) Support (2026-01-09)

### Major Changes

**Added Microsoft Defender for Office 365 Support:**
- New data type: `mdo:url_click` for URL click tracking from email links
- New data type: `mdo:email_event` for email metadata with threat detection
- Enables end-to-end phishing investigation: email → click → authentication

**Correlation Fields Documentation:**
- Added comprehensive correlation field documentation to `field_standards.md`
- Documents `networkMessageId` as the key correlation field between MDO data types
- Documents `userId`, `senderObjectId`, `recipientObjectId` for Entra correlation
- Added attack chain correlation examples

### New Data Types

#### `mdo:url_click` - URL Click Tracking

Tracks when users click URLs from emails. Export from: security.microsoft.com > Explorer > URL clicks

| Field | Type | Description |
|-------|------|-------------|
| `recipient` | str | User who clicked the URL |
| `url` | str | The clicked URL (refanged) |
| `urlDomain` | str | Extracted domain for searching |
| `urlClickAction` | str | Action: Allowed or Blocked |
| `isClickedThrough` | bool | User proceeded through warning |
| **`networkMessageId`** | str | **CORRELATION KEY** - links to source email |
| `clickId` | str | Unique click event ID |
| `clientIp` | str | User's IP when clicking |
| `urlChain` | str | JSON redirect chain |
| `threatType` | str | Detected threat type |
| `appName` | str | Client app (Outlook, OWA, Mail) |
| `tags` | str | User tags (Priority account, etc.) |

#### `mdo:email_event` - Email Events with Threat Detection

Full email metadata with threat verdicts. Export from: security.microsoft.com > Explorer > All email

| Field | Type | Description |
|-------|------|-------------|
| **`networkMessageId`** | str | **CORRELATION KEY** - links to URL clicks |
| `internetMessageId` | str | Email Message-ID header |
| `senderAddress` | str | Sender email |
| `senderDisplayName` | str | Sender display name |
| `senderDomain` | str | Sender domain |
| `senderIp` | str | Sender mail server IP |
| **`senderObjectId`** | str | **CORRELATION KEY** - links to Entra identity |
| `recipients` | str | Recipient email(s) |
| **`recipientObjectId`** | str | **CORRELATION KEY** - links to Entra identity |
| `subject` | str | Email subject |
| `deliveryAction` | str | Delivered, Blocked, Quarantined |
| `directionality` | str | Inbound, Outbound, Intra-org |
| `threats` | str | Detected threats |
| `threatClassification` | str | Threat classification |
| `fileThreats` | str | JSON: attachment threats with SHA256 |
| `urls` | str | JSON: URLs in email |
| `firstContact` | bool | First contact from sender (spear phishing indicator) |
| `recipientTags` | str | User tags (Priority account, VIP) |

### Correlation Capabilities

The `networkMessageId` field enables correlation across the attack chain:

```
Phishing Email (mdo:email_event)
        │
        │ networkMessageId: "abc-123"
        ▼
User Clicks URL (mdo:url_click)
        │
        │ recipient → recipientObjectId
        ▼
Compromised Sign-in (entra:signin)
        │
        │ userId (matches recipientObjectId)
        ▼
Attacker Actions (entra:audit)
```

**Example Correlation Query:**
```
# Find the phishing email and all clicks on its URLs
networkMessageId:"add040c0-5e8a-4fdd-7588-08de4f883bd7"

# Then correlate with user's Entra activity
userId:"9280f0f2-77e4-4709-8308-022767dbd8c0" AND datetime:[2026-01-08 TO 2026-01-09]
```

### CLI Changes

- Added `--parse-mdo` flag to parse MDO CSV exports
- Added to `--parse-all` flag
- Supports directory input for processing multiple MDO/Entra files together

**Usage:**
```bash
# Parse MDO CSV directly
python -m ct_to_timesketch exports/UrlClicks.csv --parse-mdo

# Parse all cloud logs in a directory
python -m ct_to_timesketch "captures/Rowan County/" --parse-mdo --parse-entra
```

---

## Version 2.5.0 - Entra ID Full Fidelity & camelCase Fields (2026-01-09)

### Major Changes

**Field Naming: camelCase for Entra Fields**
- Changed Entra field names from snake_case to camelCase to match Microsoft Graph API
- Enables direct copy/paste of queries from Azure portal
- Reduces friction for analysts familiar with Entra ID field names
- Example: `user_id` → `userId`, `ip_address` → `ipAddress`

**Expanded Field Coverage:**
- `entra:signin`: Expanded from 43 to 66 fields
- `entra:audit`: Expanded from 24 to 31 fields
- Added critical fields for incident response: status, risk, geolocation, device, MFA

**Forensic Fidelity:**
- Removed JSON truncation for complex arrays
- Full `appliedConditionalAccessPolicies`, `authenticationDetails`, etc. now preserved
- No data loss for forensic analysis

### Breaking Changes - Field Name Migration

Entra fields now use camelCase to match the Microsoft Graph API:

| Old Field (v2.4.0) | New Field (v2.5.0) | Notes |
|--------------------|-------------------|-------|
| `user_id` | `userId` | Azure AD user GUID |
| `username` | `userPrincipalName` | User principal name |
| `user_display_name` | `userDisplayName` | Display name |
| `ip_address` | `ipAddress` | Sign-in IP |
| `app_id` | `appId` | Application GUID |
| `app_name` | `appDisplayName` | Application name |
| `correlation_id` | `correlationId` | Correlation ID |
| `conditional_access_status` | `conditionalAccessStatus` | CA result |
| `risk_level_during_signin` | `riskLevelDuringSignIn` | Risk level |
| `risk_state` | `riskState` | Risk state |
| `created_time` | `createdDateTime` | Timestamp |

### New Fields Added

**Sign-in Status Fields** (critical for blocked login detection):
- `statusErrorCode` - Error code (0=success, 50126=bad password, 53003=CA blocked)
- `statusFailureReason` - Human-readable failure reason
- `statusAdditionalDetails` - Additional context

**Risk Fields** (critical for AitM/phishing detection):
- `riskEventTypes_v2` - Comma-separated risk event types (unlikelyTravel, maliciousIPAddress, etc.)

**Geolocation Fields** (critical for impossible travel analysis):
- `locationCity`, `locationState`, `locationCountry`
- `locationLatitude`, `locationLongitude`

**Device Fields** (useful for conditional access analysis):
- `deviceId`, `deviceDisplayName`, `deviceOS`, `deviceBrowser`
- `deviceIsCompliant`, `deviceIsManaged`, `deviceTrustType`

**MFA Fields:**
- `mfaAuthMethod`, `mfaAuthDetail`

**Complex Arrays** (full JSON, no truncation):
- `appliedConditionalAccessPolicies` - Full CA policy details
- `authenticationDetails` - Auth step details
- `networkLocationDetails` - Named location info
- `authenticationProcessingDetails` - Processing context
- `authenticationRequirementPolicies` - Requirement policies

**Searchable Summary Fields** (for fast queries without JSON parsing):
- `appliedCaPolicyNames` - Comma-separated CA policy names
- `authMethodsUsed` - Comma-separated auth methods
- `modifiedPropertyNames` - Comma-separated modified properties (audit logs)

### Rationale for camelCase

While the rest of the codebase uses snake_case (Plaso convention), Entra fields use camelCase because:

1. **Query compatibility**: Azure portal and Microsoft documentation use camelCase
2. **Copy/paste workflows**: Analysts can copy field names directly from Azure
3. **Microsoft Graph API alignment**: Field names match the API exactly
4. **Reference links**: Added Microsoft documentation URLs in data_types.csv

### Migration Notes

**Query Updates Required:**
```
# Old queries (v2.4.0)
user_id:"abc-123" AND ip_address:"1.2.3.4"
risk_state:"atRisk"

# New queries (v2.5.0)
userId:"abc-123" AND ipAddress:"1.2.3.4"
riskState:"atRisk"

# New capability: Search by error code
statusErrorCode:53003  # Find CA-blocked sign-ins
statusErrorCode:50126  # Find bad password attempts

# New capability: Search by risk events
riskEventTypes_v2:*unlikelyTravel*  # Impossible travel
riskEventTypes_v2:*maliciousIPAddress*  # Known bad IP

# New capability: Search by location
locationCountry:"CN" OR locationCountry:"RU"  # Foreign sign-ins
```

---

## Version 2.4.0 - Entra Sign-Ins & Field Consistency (2025-12-27)

### Major Changes

**Added Entra ID / Azure AD Sign-Ins Support:**
- New data type: `entra:signin` for Azure AD interactive sign-in events
- 43 standardized fields for comprehensive sign-in analysis
- Enables correlation between cloud and on-premises events

**Field Name Standardization for Cross-Referencing:**
- Standardized IP address fields: `client_ip` (was `source_address`, `client_address`)
- Created field name standards document for consistent cross-referencing
- All new data types use standardized field names

### New Data Type: Entra Sign-Ins

**data_type:** `entra:signin`

Azure AD interactive sign-in events with full authentication context.

**Key Fields for Cross-Referencing:**
- `user_id` - Azure AD user GUID (enables correlation with local events)
- `username` - User principal name (e.g., `user@domain.com`)
- `user_display_name` - Human-readable user name
- `ip_address` - Sign-in IP address
- `app_id` - Application GUID
- `app_name` - Application display name
- `created_time` - Sign-in timestamp

**Example Cross-Reference Query:**
```
# Find all events for a user across Entra and Windows
username:"elizabeth.anderson@rowancountync.gov" OR user_id:"c44aa32a-6699-43f0-bd15-58644481ac94"

# Correlate Entra sign-ins with local Windows logon events
username:"elizabeth.anderson@rowancountync.gov" AND (data_type:"entra:signin" OR data_type:"windows:evtx:record")
```

**Complete Field List:**
See `schemas/data_types.csv` for all 43 fields including:
- Authentication details (methods, protocols, requirements)
- Risk assessment (risk levels, risk state)
- Conditional access (status, policies)
- Network information (IP address, ASN, location)
- Session information (session ID, token details)
- Resource access (resource ID, tenant information)

### Field Name Standardization

**IP Address Fields:**
- `windows:user_access_logging:clients`: `source_address` → `client_ip`
- `windows:user_access_logging:dns`: `client_address` → `client_ip`

This enables consistent cross-referencing:
```
# Find all events from a specific IP
ip_address:"24.123.188.14" OR client_ip:"24.123.188.14" OR source_ip:"24.123.188.14"
```

### Documentation

- **Field Name Standards**: See `docs/FIELD_NAME_STANDARDS.md` for complete field naming conventions
- Defines standard field names for user identity, IP addresses, timestamps, and more
- Enables consistent cross-referencing queries across all data types

---

## Version 2.3.0 - Field Name Standardization (2025-12-27)

### Major Changes

**All field names standardized to snake_case:**
- Migrated all camelCase field names to snake_case for consistency
- `schemas/data_types.csv` is now the single source of truth for field definitions
- Created `ct_to_timesketch/core/data_types.py` module to load and validate CSV definitions
- All output fields now validated against CSV definitions

### Field Name Changes

| Old Field | New Field | Data Type(s) | Notes |
|-----------|-----------|--------------|-------|
| `hostName` | `host_name` | All events | Standard Timesketch field |
| `configType` | `config_type` | `windows:registry:run` | Startup items |
| `userID` | `user_id` | Multiple | Context-dependent (some use `username`) |
| `userSID` | `user_sid` | Multiple | User security identifier |
| `registryKey` | `registry_key` | `windows:registry:run` | Registry key path |
| `registryValue` | `registry_value` | `windows:registry:run` | Registry value name |
| `remoteHostName` | `remote_host_name` | `windows:registry:mountpoints2` | Network shares |
| `remoteShareName` | `remote_share_name` | `windows:registry:mountpoints2` | Network shares |
| `processName` | `process_name` | `windows:tasks:job` | Process name |
| `processPath` | `process_path` | `windows:tasks:job` | Process path |
| `commandLine` | `command_line` | `windows:tasks:job` | Command line |
| `localIP` | `local_ip` | `windows:network:connection` | Network connections |
| `localPort` | `local_port` | `windows:network:connection` | Network connections |
| `remoteIP` | `remote_ip` | `windows:network:connection` | Network connections |
| `remotePort` | `remote_port` | `windows:network:connection` | Network connections |
| `connectionType` | `connection_type` | `windows:network:connection` | Network connections |
| `filePath` | `file_path` | `fs:stat:ntfs:*` | File system metadata |
| `fileName` | `file_name` | `fs:stat:ntfs:*` | File system metadata |
| `fileSize` | `file_size` | `fs:stat:ntfs:*` | File system metadata |
| `metaType` | `meta_type` | `fs:stat:ntfs:*` | File system metadata |
| `md5hash` | `md5` | `fs:stat:ntfs:$standard_information` | Hash fields |
| `sha1hash` | `sha1` | `fs:stat:ntfs:$standard_information` | Hash fields |
| `sha256hash` | `sha256` | `fs:stat:ntfs:$standard_information` | Hash fields |

### New Features

1. **Data Types Loader Module** (`ct_to_timesketch/core/data_types.py`)
   - Loads field definitions from `schemas/data_types.csv`
   - Validates field names are snake_case
   - Provides helper functions for field lookup and validation
   - Caches loaded data for performance

2. **Field Validation**
   - `add_event()` now validates output fields against CSV definitions
   - Ensures consistency across all extractors
   - Prevents typos and naming inconsistencies

### Migration Notes

**Breaking Changes:**
- All output JSONL files now use snake_case field names
- Existing queries using camelCase field names will need to be updated
- `hostName` → `host_name` affects all events

**For Query Updates:**
```
# Old queries
hostName:DC01  →  host_name:DC01
userID:admin  →  user_id:admin
localIP:192.168.1.1  →  local_ip:192.168.1.1

# Network connections
localIP:* AND remotePort:443  →  local_ip:* AND remote_port:443
```

**For Data Processing:**
- All field names in output JSONL are now snake_case
- CSV definitions are enforced programmatically
- Field validation occurs at event creation time

---

**Date:** 2025-12-27  
**Version:** 2.2.0

---

## Summary of Changes

### Data Type Changes

| File | Old `data_type` | New `data_type` | Reason |
|------|-----------------|-----------------|--------|
| `extractors/registry.py` | `windows:registry:typedpaths` | `windows:registry:typedurls` | Match Plaso naming |
| `extractors/registry.py` | `windows:registry:service` | `windows:registry:services` | Match Plaso naming (plural) |
| `extractors/webcache.py` | `msiecf:url_record` | `msiecf:url` | Match Plaso naming |
| `core/converter.py` | `windows:tasks:task_scheduler` | `windows:tasks:job` | Match Plaso naming |

### Field Name Changes

| File | Old Field | New Field | data_type | Reason |
|------|-----------|-----------|-----------|--------|
| `extractors/evtx.py` | `EventID` | `event_identifier` | `windows:evtx:record` | Plaso snake_case convention |
| `extractors/evtx.py` | `Channel` | `channel` | `windows:evtx:record` | Plaso snake_case convention |
| `core/converter.py` | `EventID` | `event_identifier` | `windows:evtx:record` | Plaso snake_case convention (SystemAPI events) |
| `core/converter.py` | `Channel` | `channel` | `windows:evtx:record` | Plaso snake_case convention (SystemAPI events) |
| `extractors/browser.py` | `visitCount` | `visit_count` | `chrome:history:page_visited` | Plaso snake_case convention |
| `extractors/browser.py` | `browserType` | `browser_type` | `chrome:history:page_visited` | Plaso snake_case convention |
| `extractors/browser.py` | `visitCount` | `visit_count` | `firefox:places:page_visited` | Plaso snake_case convention |
| `extractors/browser.py` | `browserType` | `browser_type` | `firefox:places:page_visited` | Plaso snake_case convention |
| `extractors/lnk.py` | `target_path` | `link_target` | `windows:lnk:link` | Match Plaso field name |
| `extractors/registry.py` | `program_path` | `value_name` | `windows:registry:userassist` | Match Plaso field name |
| `extractors/registry.py` | `registry_key` | `key_path` | Multiple registry types | Match Plaso field name |
| `core/converter.py` | `userID` | `username` | `windows:registry:sam_users` | Match Plaso field name |
| `core/converter.py` | `loginCount` | `login_count` | `windows:registry:sam_users` | Match Plaso field name |
| `extractors/registry.py` | `user_rid` | `account_rid` | `windows:registry:sam_users` | Match Plaso field name |
| `core/converter.py` | `remoteHostName` | `entries` | `windows:registry:mstsc:connection` | Match Plaso field name |
| `core/converter.py` | `remoteUser` | `username` | `windows:registry:mstsc:connection` | Match Plaso field name |

---

## Detailed Changes by Extractor

### EVTX Extractor (`extractors/evtx.py`)

**data_type:** `windows:evtx:record`

| Field | Before | After | Notes |
|-------|--------|-------|-------|
| Event ID | `EventID` | `event_identifier` | Matches Plaso convention |
| Channel | `Channel` | `channel` | Lowercase for consistency |
| Source Name | `source_name` | `source_name` | No change (already correct) |
| Computer Name | `computer_name` | `computer_name` | No change (already correct) |
| Record Number | `record_number` | `record_number` | No change (already correct) |
| User SID | `user_sid` | `user_sid` | No change (already correct) |

### SystemAPI Windows Events (`core/converter.py`)

**data_type:** `windows:evtx:record`

CyberTriage pre-parsed Windows Events (from SystemAPI) now use the same field names as raw EVTX parsing:

| Field | Before | After | Notes |
|-------|--------|-------|-------|
| Event ID | `EventID` | `event_identifier` | Matches Plaso convention |
| Channel | `Channel` | `channel` | Lowercase for consistency |
| Source Name | `source_name` | `source_name` | No change (already correct) |
| Computer Name | `computer_name` | `computer_name` | No change (already correct) |

**Event data fields:** Dynamic event fields (e.g., `LogonType`, `TargetUserName`, `IpAddress`) are now exported without a prefix for direct Timesketch query compatibility. Query example: `event_identifier:4624 AND LogonType:3`

### Browser Extractor (`extractors/browser.py`)

**data_types:** `chrome:history:page_visited`, `firefox:places:page_visited`

| Field | Before | After | Notes |
|-------|--------|-------|-------|
| URL | `url` | `url` | No change |
| Title | `title` | `title` | No change |
| Visit Count | `visitCount` | `visit_count` | Snake_case convention |
| Browser Type | `browserType` | `browser_type` | Snake_case convention |

### LNK Extractor (`extractors/lnk.py`)

**data_type:** `windows:lnk:link`

| Field | Before | After | Notes |
|-------|--------|-------|-------|
| LNK File | `lnk_file` | `lnk_file` | No change |
| LNK Path | `lnk_path` | `lnk_path` | No change |
| Target Path | `target_path` | `link_target` | Match Plaso field name |

### Registry Extractor (`extractors/registry.py`)

**data_types affected:**
- `windows:registry:userassist`
- `windows:registry:recentdocs`
- `windows:registry:typedurls` (was `typedpaths`)
- `windows:registry:mrulist`
- `windows:registry:bagmru`
- `windows:registry:sam_users`
- `windows:registry:services` (was `service`)
- `windows:registry:amcache`

| Field | Before | After | Notes |
|-------|--------|-------|-------|
| Program Path | `program_path` | `value_name` | UserAssist - match Plaso |
| Registry Key | `registry_key` | `key_path` | All registry types - match Plaso |

### WebCache Extractor (`extractors/webcache.py`)

**data_type:** `msiecf:url` (was `msiecf:url_record`)

No field name changes. Only the data_type was updated.

### Converter (`core/converter.py`)

**data_type:** `windows:tasks:job` (was `windows:tasks:task_scheduler`)

No field name changes. Only the data_type was updated.

---

## Field Updates (v2.2.0 - 2025-12-27)

### SAM Users (`windows:registry:sam_users`)

Updated field names to align with Plaso schema for `windows:registry:sam_users`.

**Files affected:** `core/converter.py`, `extractors/registry.py`

| Old Field | New Field | Type | Notes |
|-----------|-----------|------|-------|
| `userID` | `username` | str | Plaso field name |
| `user_rid` | `account_rid` | int | Plaso field name, now parsed as integer |
| `userSID` | `user_sid` | str | Snake_case convention |
| `userDomain` | `user_domain` | str | Snake_case convention |
| `loginCount` | `login_count` | int | Plaso field name, now parsed as integer |
| (new) | `last_login_time` | datetime | Added from CyberTriage `lastLoginDate` |
| (new) | `last_password_set_time` | datetime | Added from CyberTriage `lastPasswordChangeDate` |
| (new) | `last_written_time` | datetime | SAM key modification time |
| `accountType` | `account_type` | str | Snake_case convention |
| `accountStatus` | `account_status` | str | Snake_case convention |
| `isAdmin` | `admin_priv` | str | More descriptive name |
| `homeDir` | `home_dir` | str | Snake_case convention |
| (new) | `expiration_date` | datetime | Added from CyberTriage `expirationDate` |

**Registry Parser Improvements:**
- RID now extracted from hex key name and converted to integer
- Username now resolved from SAM Names subkey mapping
- Key path included for all entries

### MSTSC/RDP Connections (`windows:registry:mstsc:connection`)

Updated field names to align with Plaso schema for `windows:registry:mstsc:connection`.

**Files affected:** `core/converter.py`

| Old Field | New Field | Type | Notes |
|-----------|-----------|------|-------|
| `remoteHostName` | `entries` | str | Plaso field name (MRU entries) |
| `remoteUser` | `username` | str | Plaso field name (UsernameHint) |
| (new) | `key_path` | str | Added from sourceInfo.keyName |
| (new) | `last_written_time` | datetime | Added to attributes (was only used as timestamp) |
| `remoteDomain` | `remote_domain` | str | Snake_case convention |
| `localUser` | `local_user` | str | Snake_case convention |
| `userSID` | `user_sid` | str | Snake_case convention |

---

## New Data Types Added (v2.1.0 - 2025-12-27)

### Amcache Installed Programs (`extractors/amcache.py`)

**data_type:** `windows:registry:amcache:inventory_application`

Added extraction of `InventoryApplication` registry key from Amcache.hve, providing the equivalent of Add/Remove Programs for Windows Administrator review.

| Field | Description | Example |
|-------|-------------|---------|
| `program_name` | Program name (Add/Remove Programs) | "Microsoft Azure AD Connect" |
| `publisher` | Software vendor | "Microsoft Corporation" |
| `version` | Installed version | "2.3.20.0" |
| `install_date` | Installation date | "09/05/2024 00:00:00" |
| `install_source` | Installation method | "MSI Installer", "Windows Store App" |
| `install_path` | Installation directory | "C:\Program Files\..." |
| `uninstall_string` | Uninstall command | "MsiExec.exe /X{...}" |
| `msi_product_code` | MSI GUID (for SCCM/Intune) | "{D51B2CD3-5016-...}" |
| `msi_package_code` | MSI package GUID | "{3EE95640-7C6B-...}" |
| `hidden_from_arp` | Hidden from Add/Remove Programs | true/false |
| `is_inbox_app` | Windows built-in app | true/false |
| `store_app_type` | Windows Store app type | "Win10StoreApp" |
| `package_full_name` | Store app package name | "Microsoft.Windows..." |

**Use Case:** Windows Administrator software inventory review, compliance verification, identifying hidden software.

### Task Scheduler TaskCache (`extractors/registry.py`)

**data_type:** `task_scheduler:task_cache:entry`

Added extraction of TaskCache registry key for scheduled task definitions.

| Field | Type | Description |
|-------|------|-------------|
| `task_name` | str | Name/path of the scheduled task (e.g., `\Microsoft\Windows\UpdateOrchestrator\Refresh Settings`) |
| `task_identifier` | str | GUID identifier of the task |
| `key_path` | str | Windows Registry key path |
| `last_written_time` | datetime | Entry last written date and time |
| `last_registered_time` | datetime | Date and time the task was last registered |
| `launch_time` | datetime | Date and time the task was last launched |
| `unknown_time` | datetime | Unknown time from DynamicInfo binary value |

**DynamicInfo Binary Structure:**
- Offset 0x04: Last registered time (FILETIME)
- Offset 0x0C: Launch time (FILETIME)
- Offset 0x14: Unknown time (FILETIME) - purpose undocumented by Microsoft

**Use Case:** Scheduled task inventory, identifying malicious persistence via scheduled tasks, correlating with EVTX task events.

---

## Custom Data Types (Unchanged)

The following custom data types are not in the official Plaso spec but follow naming conventions and provide valuable forensic context:

| data_type | Description | Reason for Custom Type |
|-----------|-------------|------------------------|
| `windows:registry:amcache:inventory_application` | Installed programs (Add/Remove Programs) | Custom extension of amcache for admin review |
| `windows:powershell:console_history` | PowerShell command history | Not in Plaso (unique artifact) |
| `windows:registry:recentdocs` | RecentDocs registry key | Not in Plaso (Windows-specific) |
| `windows:network:connection` | Network connection artifacts | Custom CyberTriage artifact |
| `ct:generic:event` | Fallback for unmapped events | CyberTriage-specific |

---

## Migration Notes

### For Query Updates

If you have existing Timesketch queries or Sigma rules, update the following field references:

```
# EVTX Events
EventID:4624  →  event_identifier:4624
Channel:Security  →  channel:Security
payload_LogonType:3  →  LogonType:3  (prefix removed)
payload_TargetUserName:*  →  TargetUserName:*  (prefix removed)

# Browser History
visitCount:*  →  visit_count:*
browserType:Chrome  →  browser_type:Chrome

# LNK Files
target_path:*  →  link_target:*

# Registry
program_path:*  →  value_name:*
registry_key:*  →  key_path:*

# SAM Users
userID:administrator  →  username:administrator
loginCount:*  →  login_count:*
user_rid:500  →  account_rid:500

# MSTSC/RDP Connections
remoteHostName:*  →  entries:*
remoteUser:*  →  username:*
remoteDomain:*  →  remote_domain:*
localUser:*  →  local_user:*
```

### For Data Processing Tools

If integrating with other tools that consume our JSONL output:

1. **EVTX records** now use `event_identifier` (int) instead of `EventID`
2. **Browser history** fields use snake_case: `visit_count`, `browser_type`
3. **LNK files** use `link_target` instead of `target_path`
4. **Registry artifacts** use `value_name` and `key_path`

---

## Reference

- [Timesketch data_types.csv](https://github.com/google/timesketch/blob/master/data/nl2q/data_types.csv)
- [Plaso Parser Documentation](https://plaso.readthedocs.io/)
- [Timesketch GitHub Repository](https://github.com/google/timesketch)

