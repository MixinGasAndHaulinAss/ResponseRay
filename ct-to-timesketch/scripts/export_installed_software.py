#!/usr/bin/env python3
"""
Export installed software information from CyberTriage timeline JSONL files.

Extracts software installation data from:
- Registry Uninstall keys (windows:registry:uninstall)
- Amcache InventoryApplication (windows:registry:amcache:inventory_application)

Exports to CSV with comprehensive metadata including:
- Program name, publisher, version
- Installation date and source
- MSI product/package codes
- Installation path and uninstall strings
"""

import json
import csv
import sys
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def parse_install_date(date_str):
    """
    Parse InstallDate string to ISO format.
    
    Handles multiple formats:
    - YYYYMMDD (common in Registry)
    - MM/DD/YYYY HH:MM:SS
    - YYYY-MM-DD HH:MM:SS
    - ISO timestamps
    """
    if not date_str:
        return None
    
    date_str = str(date_str).strip()
    
    # Try ISO format first
    if 'T' in date_str or date_str.endswith('Z'):
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.isoformat()
        except:
            pass
    
    # Try various date formats
    formats = [
        '%Y%m%d',                    # YYYYMMDD
        '%m/%d/%Y %H:%M:%S',        # MM/DD/YYYY HH:MM:SS
        '%m/%d/%Y %I:%M:%S %p',     # MM/DD/YYYY HH:MM:SS AM/PM
        '%Y-%m-%d %H:%M:%S',        # YYYY-MM-DD HH:MM:SS
        '%m/%d/%Y',                  # MM/DD/YYYY
        '%Y-%m-%d',                  # YYYY-MM-DD
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.isoformat()
        except ValueError:
            continue
    
    return None


def normalize_program_name(name):
    """Normalize program name for comparison."""
    if not name:
        return ''
    return name.strip().lower()


def get_program_key(entry):
    """
    Generate a unique key for a program entry for deduplication.
    
    Uses MSI product code if available, otherwise name + publisher.
    """
    # Prefer MSI product code (most unique)
    msi_code = entry.get('msi_product_code') or entry.get('msiProductCode')
    if msi_code:
        return f'msi:{msi_code.lower()}'
    
    # Fall back to name + publisher
    name = normalize_program_name(
        entry.get('program_name') or 
        entry.get('software_name') or 
        entry.get('name') or 
        ''
    )
    publisher = normalize_program_name(
        entry.get('publisher') or ''
    )
    
    return f'name:{name}|publisher:{publisher}'


def extract_software_data(jsonl_path, output_path=None):
    """
    Extract installed software from timeline JSONL file.
    
    Args:
        jsonl_path: Path to input JSONL file (relative to project root or absolute)
        output_path: Path to output CSV file (optional)
    
    Returns:
        Dictionary with extraction statistics
    """
    # Resolve path relative to project root if needed
    jsonl_path = Path(jsonl_path)
    if not jsonl_path.is_absolute():
        project_root = Path(__file__).parent.parent
        jsonl_path = project_root / jsonl_path
    
    if not jsonl_path.exists():
        print(f"Error: File not found: {jsonl_path}")
        return None
    
    print(f"Reading {jsonl_path}...")
    
    # Store software entries by unique key
    software_dict = {}
    registry_count = 0
    amcache_count = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                
                # Check for Registry Uninstall entries
                if (entry.get('data_type') == 'windows:registry:uninstall' or 
                    entry.get('event_type') == 'registry_software'):
                    
                    registry_count += 1
                    program_key = get_program_key(entry)
                    
                    # Create or update software entry
                    if program_key not in software_dict:
                        software_dict[program_key] = {
                            'data_source': 'Registry',
                            'program_name': entry.get('software_name') or entry.get('program_name') or '',
                            'publisher': entry.get('publisher') or '',
                            'version': entry.get('version') or '',
                            'install_date': None,
                            'install_source': 'Registry',
                            'install_path': entry.get('install_path') or entry.get('rootDirPath') or '',
                            'uninstall_string': entry.get('uninstall_string') or entry.get('uninstallString') or '',
                            'registry_key_path': entry.get('registry_key_path') or entry.get('registryKeyPath') or '',
                            'msi_product_code': entry.get('msi_product_code') or entry.get('msiProductCode') or '',
                            'msi_package_code': entry.get('msi_package_code') or entry.get('msiPackageCode') or '',
                            'hidden_from_arp': entry.get('hidden_from_arp') or entry.get('hiddenArp') or False,
                            'is_inbox_app': entry.get('is_inbox_app') or entry.get('isInboxApp') or False,
                            'store_app_type': entry.get('store_app_type') or entry.get('storeAppType') or '',
                            'package_full_name': entry.get('package_full_name') or entry.get('packageFullName') or '',
                            'timestamp': entry.get('datetime') or '',
                            'hostname': entry.get('hostName') or entry.get('host_name') or '',
                        }
                    
                    # Update with Registry data (fill gaps)
                    sw_entry = software_dict[program_key]
                    
                    # Use Registry timestamp if no install date
                    if not sw_entry['install_date'] and entry.get('datetime'):
                        sw_entry['install_date'] = entry.get('datetime')
                    
                    # Update name/publisher if missing
                    if not sw_entry['program_name']:
                        sw_entry['program_name'] = entry.get('software_name') or entry.get('program_name') or ''
                    if not sw_entry['publisher']:
                        sw_entry['publisher'] = entry.get('publisher') or ''
                
                # Check for Amcache InventoryApplication entries
                elif (entry.get('data_type') == 'windows:registry:amcache:inventory_application' or
                      entry.get('event_type') == 'installed_program'):
                    
                    amcache_count += 1
                    program_key = get_program_key(entry)
                    
                    # Extract install date
                    install_date_str = (entry.get('install_date') or 
                                      entry.get('installDate') or 
                                      entry.get('msiInstallDate') or '')
                    install_date_iso = None
                    if install_date_str:
                        install_date_iso = parse_install_date(install_date_str)
                    elif entry.get('datetime'):
                        install_date_iso = entry.get('datetime')
                    
                    # If entry exists, prefer Amcache data (more complete)
                    if program_key in software_dict:
                        sw_entry = software_dict[program_key]
                        # Update data source
                        if sw_entry['data_source'] == 'Registry':
                            sw_entry['data_source'] = 'Both'
                        # Prefer Amcache data for all fields
                        sw_entry['program_name'] = entry.get('program_name') or sw_entry['program_name']
                        sw_entry['publisher'] = entry.get('publisher') or sw_entry['publisher']
                        sw_entry['version'] = entry.get('version') or sw_entry['version']
                        sw_entry['install_date'] = install_date_iso or sw_entry['install_date']
                        sw_entry['install_source'] = entry.get('install_source') or sw_entry['install_source']
                        sw_entry['install_path'] = entry.get('install_path') or entry.get('rootDirPath') or sw_entry['install_path']
                        sw_entry['uninstall_string'] = entry.get('uninstall_string') or entry.get('uninstallString') or sw_entry['uninstall_string']
                        sw_entry['registry_key_path'] = entry.get('registry_key_path') or entry.get('registryKeyPath') or sw_entry['registry_key_path']
                        sw_entry['msi_product_code'] = entry.get('msi_product_code') or entry.get('msiProductCode') or sw_entry['msi_product_code']
                        sw_entry['msi_package_code'] = entry.get('msi_package_code') or entry.get('msiPackageCode') or sw_entry['msi_package_code']
                        sw_entry['hidden_from_arp'] = entry.get('hidden_from_arp') or entry.get('hiddenArp') or sw_entry['hidden_from_arp']
                        sw_entry['is_inbox_app'] = entry.get('is_inbox_app') or entry.get('isInboxApp') or sw_entry['is_inbox_app']
                        sw_entry['store_app_type'] = entry.get('store_app_type') or entry.get('storeAppType') or sw_entry['store_app_type']
                        sw_entry['package_full_name'] = entry.get('package_full_name') or entry.get('packageFullName') or sw_entry['package_full_name']
                        sw_entry['timestamp'] = entry.get('datetime') or sw_entry['timestamp']
                        sw_entry['hostname'] = entry.get('hostName') or entry.get('host_name') or sw_entry['hostname']
                    else:
                        # Create new entry from Amcache
                        software_dict[program_key] = {
                            'data_source': 'Amcache',
                            'program_name': entry.get('program_name') or '',
                            'publisher': entry.get('publisher') or '',
                            'version': entry.get('version') or '',
                            'install_date': install_date_iso,
                            'install_source': entry.get('install_source') or '',
                            'install_path': entry.get('install_path') or entry.get('rootDirPath') or '',
                            'uninstall_string': entry.get('uninstall_string') or entry.get('uninstallString') or '',
                            'registry_key_path': entry.get('registry_key_path') or entry.get('registryKeyPath') or '',
                            'msi_product_code': entry.get('msi_product_code') or entry.get('msiProductCode') or '',
                            'msi_package_code': entry.get('msi_package_code') or entry.get('msiPackageCode') or '',
                            'hidden_from_arp': entry.get('hidden_from_arp') or entry.get('hiddenArp') or False,
                            'is_inbox_app': entry.get('is_inbox_app') or entry.get('isInboxApp') or False,
                            'store_app_type': entry.get('store_app_type') or entry.get('storeAppType') or '',
                            'package_full_name': entry.get('package_full_name') or entry.get('packageFullName') or '',
                            'timestamp': entry.get('datetime') or '',
                            'hostname': entry.get('hostName') or entry.get('host_name') or '',
                        }
                        
            except json.JSONDecodeError:
                continue
            except Exception as e:
                if line_num <= 10:
                    print(f"Warning: Error on line {line_num}: {e}")
                continue
    
    print(f"\nProcessed timeline entries")
    print(f"  Registry Uninstall entries: {registry_count}")
    print(f"  Amcache InventoryApplication entries: {amcache_count}")
    print(f"  Unique software programs: {len(software_dict)}")
    
    if not software_dict:
        print("\nNo installed software entries found in timeline.")
        return {'total': 0, 'registry': 0, 'amcache': 0}
    
    # Determine output path
    if not output_path:
        input_path = Path(jsonl_path)
        output_path = input_path.parent / f"{input_path.stem}_installed_software.csv"
    else:
        output_path = Path(output_path)
        if not output_path.is_absolute():
            output_path = Path(jsonl_path).parent / output_path
    
    # Write to CSV
    print(f"\nWriting to {output_path}...")
    
    fieldnames = [
        'program_name',
        'publisher',
        'version',
        'install_date',
        'install_source',
        'install_path',
        'uninstall_string',
        'registry_key_path',
        'msi_product_code',
        'msi_package_code',
        'data_source',
        'hidden_from_arp',
        'is_inbox_app',
        'store_app_type',
        'package_full_name',
        'timestamp',
        'hostname',
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Sort by program name
        for program_key in sorted(software_dict.keys(), 
                                  key=lambda k: software_dict[k]['program_name'].lower()):
            sw_entry = software_dict[program_key]
            
            # Convert boolean values
            row = {}
            for field in fieldnames:
                value = sw_entry.get(field, '')
                if isinstance(value, bool):
                    row[field] = 'True' if value else 'False'
                elif value is None:
                    row[field] = ''
                else:
                    row[field] = str(value)
            
            writer.writerow(row)
    
    print(f"✓ Exported {len(software_dict)} software programs to {output_path}")
    
    # Print summary statistics
    print(f"\nSummary:")
    print(f"  Programs with version: {sum(1 for s in software_dict.values() if s['version']):,}")
    print(f"  Programs with install date: {sum(1 for s in software_dict.values() if s['install_date']):,}")
    print(f"  Programs with publisher: {sum(1 for s in software_dict.values() if s['publisher']):,}")
    print(f"  Programs with MSI codes: {sum(1 for s in software_dict.values() if s['msi_product_code']):,}")
    print(f"  Data sources:")
    sources = defaultdict(int)
    for s in software_dict.values():
        sources[s['data_source']] += 1
    for src, count in sorted(sources.items()):
        print(f"    {src}: {count}")
    
    return {
        'total': len(software_dict),
        'registry': registry_count,
        'amcache': amcache_count
    }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python export_installed_software.py <timeline.jsonl> [output.csv]")
        print("\nExample:")
        print("  python export_installed_software.py ../reports/DC00_timeline.jsonl")
        print("  python export_installed_software.py ../reports/KAN-GW2_timeline.jsonl output.csv")
        sys.exit(1)
    
    jsonl_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    extract_software_data(jsonl_path, output_path)

