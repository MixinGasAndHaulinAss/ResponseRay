# Field Name Standards for Cross-Referencing

This document defines standard field names for common concepts across all data types to enable cross-referencing queries in Timesketch.

## Core Principles

1. **Same concept = Same field name**: Fields representing the same concept must use identical names across all data types
2. **snake_case**: All field names use snake_case
3. **Descriptive**: Field names should be clear and unambiguous

## Standard Field Mappings

### User Identity Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| User GUID/UUID | `user_id` | Unique user identifier (GUID, UUID, or local ID) | Entra `userId`, local user IDs |
| Username/Principal | `username` | User principal name or account name | `userPrincipalName`, `userID` (when it's a name) |
| User Display Name | `user_display_name` | Human-readable user name | `userDisplayName`, `userDisplayName` |
| User SID | `user_sid` | Windows Security Identifier | `S-1-5-21-...` |
| User Domain | `user_domain` | Domain name for user | `DOMAIN`, `rowancountync.gov` |

**Usage Rules:**
- Use `user_id` for unique identifiers (GUIDs, UUIDs, numeric IDs)
- Use `username` for account names/principal names
- Use `user_sid` specifically for Windows SIDs
- Use `user_identifier` only when the type is ambiguous (legacy SRUM)

### IP Address Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| Single IP | `ip_address` | Single IP address (source or destination) | `24.123.188.14` |
| Source IP | `source_ip` | Source IP in a connection | Network connections |
| Destination IP | `destination_ip` | Destination IP in a connection | Network connections |
| Client IP | `client_ip` | Client IP address | UAL, DNS queries |

**Usage Rules:**
- Use `ip_address` when there's only one IP (e.g., sign-in events)
- Use `source_ip`/`destination_ip` for bidirectional connections
- Use `client_ip` when specifically referring to a client in a client-server context

### Timestamp Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| Creation Time | `created_time` | When the record/entity was created | Account creation, file creation |
| Modification Time | `modified_time` | When the record was last modified | Registry key modified |
| Access Time | `access_time` | When the resource was accessed | File access, login time |
| Start Time | `start_time` | When an activity started | Process start, session start |
| End Time | `end_time` | When an activity ended | Session end, activity end |
| Last Written | `last_written_time` | Registry-specific: last write time | Registry keys |

**Usage Rules:**
- Use `created_time` for entity creation
- Use `modified_time` for updates/changes
- Use `access_time` for read/access operations
- Use `start_time`/`end_time` for time-bounded activities
- Use `last_written_time` specifically for registry keys (Plaso convention)

### Application/Process Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| Application ID | `app_id` | Application identifier (GUID) | Entra `appId` |
| Application Name | `app_name` | Application display name | `appDisplayName` |
| Process Name | `process_name` | Executable name | `cmd.exe`, `powershell.exe` |
| Process Path | `process_path` | Full path to executable | `C:\Windows\System32\cmd.exe` |
| Command Line | `command_line` | Full command line | `cmd.exe /c dir` |

### Network Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| Local IP | `local_ip` | Local IP address | Network connections |
| Local Port | `local_port` | Local port number | Network connections |
| Remote IP | `remote_ip` | Remote IP address | Network connections |
| Remote Port | `remote_port` | Remote port number | Network connections |
| Connection Type | `connection_type` | Protocol type | `TCP`, `UDP` |

### File System Fields

| Concept | Standard Field Name | Description | Examples |
|---------|---------------------|-------------|----------|
| File Path | `file_path` | Full file path | `/windows/system32/config/SOFTWARE` |
| File Name | `file_name` | File name only | `SOFTWARE` |
| File Size | `file_size` | File size in bytes | `134742016` |
| Hash (MD5) | `md5` | MD5 hash | `6978121de2e9d23fb56f5a3ce532c373` |
| Hash (SHA1) | `sha1` | SHA1 hash | `014507ca746a4ba1c6d24d0594adaf7c7f54af98` |
| Hash (SHA256) | `sha256` | SHA256 hash | `303edfd44bc62a723ca8c3e3d3dfae9af9a82d7a01124696a6f371278ad5d57c` |

## Migration Plan

### Phase 1: Standardize Common Fields
- [x] User identity: `user_id`, `username`, `user_sid`
- [ ] IP addresses: `ip_address`, `source_ip`, `destination_ip`, `client_ip`
- [ ] Timestamps: `created_time`, `modified_time`, `access_time`

### Phase 2: Update Existing Data Types
- Update all data types to use standard field names
- Maintain backward compatibility where possible

### Phase 3: Add New Data Types
- All new data types must use standard field names
- Entra sign-ins will be the first new data type

## Cross-Reference Query Examples

With standardized field names, you can perform queries like:

```
# Find all events for a specific user across all data types
user_id:"c44aa32a-6699-43f0-bd15-58644481ac94" OR username:"elizabeth.anderson@rowancountync.gov"

# Find all events from a specific IP address
ip_address:"24.123.188.14" OR source_ip:"24.123.188.14" OR client_ip:"24.123.188.14"

# Find all file access events for a user
username:"elizabeth.anderson" AND (event_type:"file_access" OR data_type:"fs:stat:ntfs:*")

# Correlate Entra sign-ins with local Windows events
username:"elizabeth.anderson@rowancountync.gov" AND (data_type:"entra:signin" OR data_type:"windows:evtx:record")
```

