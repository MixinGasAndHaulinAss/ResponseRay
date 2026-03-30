# Data Type Schemas

This directory contains the complete data type definitions and documentation for Timesketch-compatible forensic event schemas.

## Contents

- **`data_types.csv`** - Master CSV file defining all data types and their fields
  - Format compatible with Timesketch/Plaso data_types.csv
  - Single source of truth for field definitions
  - All field names use snake_case for consistency

- **`changelog.md`** - Complete changelog of all data type and field name changes
  - Tracks version history
  - Documents breaking changes
  - Migration notes for field name updates

- **`field_standards.md`** - Field naming standards for cross-referencing
  - Standard field names for common concepts (user identity, IP addresses, timestamps)
  - Enables consistent cross-referencing queries across data types
  - Guidelines for adding new data types

- **`windows_data_types.md`** - Comprehensive reference for Windows data types
  - Detailed documentation of all Windows-related data types
  - Field descriptions and examples
  - Query examples

## Usage

The `data_types.csv` file is a standard CSV that can be consumed by any language or tool. The Go pipeline (`internal/converter/`) uses these data type strings directly when emitting Timesketch events.

## Data Types

Currently defined data types include:

- **Windows Event Logs**: `windows:evtx:record`
- **Windows Registry**: Various registry artifact types
- **File System**: `fs:stat:ntfs:*`
- **Browser History**: `chrome:history:page_visited`, `firefox:places:page_visited`
- **Network**: `windows:network:connection`
- **SRUM**: Application and network usage
- **Windows Timeline**: User activity tracking
- **User Access Logging**: Server access logs
- **Entra ID / Azure AD**: `entra:signin`, `entra:audit`
- **Microsoft Defender for Office 365**: `mdo:url_click`, `mdo:email_event`
- And more...

See `data_types.csv` for the complete list.

## Correlation Fields

Key fields for cross-data-type correlation:

| Field | Links | Use Case |
|-------|-------|----------|
| `networkMessageId` | `mdo:email_event` ↔ `mdo:url_click` | Track phishing email → user clicks |
| `userId` | `entra:signin` ↔ `entra:audit` | User activity across Entra |
| `senderObjectId` / `recipientObjectId` | `mdo:email_event` ↔ `entra:signin` | Email users → authentication |
| `sha256` / `fileHash` | `mdo:email_event` ↔ `fs:stat:ntfs:*` | Email attachments → endpoint files |

See `field_standards.md` for detailed correlation documentation.

## Field Naming Convention

All fields use **snake_case** for consistency:
- ✅ `user_id`, `ip_address`, `created_time`
- ❌ `userId`, `ipAddress`, `createdTime`

See `field_standards.md` for detailed naming standards.

## Version

Current version: **2.6.0**

See `changelog.md` for version history and migration notes.

