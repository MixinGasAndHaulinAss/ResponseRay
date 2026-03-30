#!/usr/bin/env python3
"""
Export list of collected files from a timeline JSONL file.

Extracts files where fileContentStatus == "Collected" and exports:
- Full file path
- File name
- File size
- Date created
- Date modified
- Hashes (MD5, SHA1, SHA256)
- MFT entry number
"""

import json
import csv
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def parse_timeline(jsonl_path, output_path=None):
    """
    Parse timeline JSONL and extract collected files.
    
    Args:
        jsonl_path: Path to input JSONL file (relative to project root or absolute)
        output_path: Path to output CSV file (optional, defaults to <input>_collected_files.csv)
    """
    
    # Resolve path relative to project root if needed
    jsonl_path = Path(jsonl_path)
    if not jsonl_path.is_absolute():
        # Try relative to project root (parent of scripts directory)
        project_root = Path(__file__).parent.parent
        jsonl_path = project_root / jsonl_path
    
    if not jsonl_path.exists():
        print(f"Error: File not found: {jsonl_path}")
        return
    
    # Group entries by file path to consolidate timestamps
    files = defaultdict(lambda: {
        'filePath': '',
        'fileName': '',
        'fileSize': None,
        'created': None,
        'modified': None,
        'accessed': None,
        'changed': None,
        'md5': None,
        'sha1': None,
        'sha256': None,
        'metaDataAddr': None,
        'fileContentStatus': None,
        'metaType': None,
        'userSID': None
    })
    
    print(f"Reading {jsonl_path}...")
    total_entries = 0
    collected_count = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                total_entries += 1
                
                # Only process MFT entries
                data_type = entry.get('data_type', '')
                if not data_type.startswith('fs:stat:ntfs:'):
                    continue
                
                # Only process collected files
                content_status = (entry.get('fileContentStatus') or 
                                entry.get('file_content_status'))
                
                if content_status != 'Collected':
                    continue
                
                collected_count += 1
                
                # Get file path (try different field names)
                file_path = (entry.get('filePath') or 
                           entry.get('file_path') or 
                           entry.get('path') or '')
                
                if not file_path:
                    continue
                
                # Initialize or update file entry
                file_info = files[file_path]
                
                # Set basic info (only once)
                if not file_info['filePath']:
                    file_info['filePath'] = file_path
                    file_info['fileName'] = (entry.get('fileName') or 
                                           entry.get('file_name') or 
                                           entry.get('name') or '')
                    file_info['fileSize'] = entry.get('fileSize') or entry.get('file_size')
                    file_info['metaDataAddr'] = entry.get('metaDataAddr') or entry.get('meta_data_addr')
                    file_info['fileContentStatus'] = content_status
                    file_info['metaType'] = entry.get('metaType') or entry.get('meta_type')
                    file_info['userSID'] = entry.get('userSID') or entry.get('user_sid')
                    
                    # Hashes
                    file_info['md5'] = entry.get('md5hash') or entry.get('md5')
                    file_info['sha1'] = entry.get('sha1hash') or entry.get('sha1')
                    file_info['sha256'] = entry.get('sha256hash') or entry.get('sha256')
                
                # Update timestamps based on timestamp_desc
                dt_str = entry.get('datetime', '')
                if dt_str:
                    try:
                        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                        ts_desc = entry.get('timestamp_desc', '')
                        
                        if 'Created' in ts_desc and not ts_desc.endswith('($FN)'):
                            if file_info['created'] is None or dt < file_info['created']:
                                file_info['created'] = dt
                        elif 'Modified' in ts_desc and not ts_desc.endswith('($FN)'):
                            if file_info['modified'] is None or dt > file_info['modified']:
                                file_info['modified'] = dt
                        elif 'Accessed' in ts_desc and not ts_desc.endswith('($FN)'):
                            if file_info['accessed'] is None or dt > file_info['accessed']:
                                file_info['accessed'] = dt
                        elif 'Changed' in ts_desc and not ts_desc.endswith('($FN)'):
                            if file_info['changed'] is None or dt > file_info['changed']:
                                file_info['changed'] = dt
                    except Exception as e:
                        pass
                        
            except json.JSONDecodeError:
                continue
            except Exception as e:
                if line_num <= 10:
                    print(f"Warning: Error on line {line_num}: {e}")
                continue
    
    print(f"\nProcessed {total_entries:,} total entries")
    print(f"Found {collected_count:,} collected file entries")
    print(f"Unique collected files: {len(files):,}")
    
    if not files:
        print("\nNo collected files found in timeline.")
        return
    
    # Determine output path
    if not output_path:
        input_path = Path(jsonl_path)
        # Output to same directory as input file
        output_path = input_path.parent / f"{input_path.stem}_collected_files.csv"
    else:
        output_path = Path(output_path)
        if not output_path.is_absolute():
            # If relative, make it relative to input file's directory
            output_path = Path(jsonl_path).parent / output_path
    
    # Write to CSV
    print(f"\nWriting to {output_path}...")
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = [
            'file_path',
            'file_name',
            'file_size',
            'date_created',
            'date_modified',
            'date_accessed',
            'date_changed',
            'md5',
            'sha1',
            'sha256',
            'mft_entry',
            'content_status',
            'meta_type',
            'user_sid'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Sort by file path
        for file_path in sorted(files.keys()):
            file_info = files[file_path]
            
            writer.writerow({
                'file_path': file_info['filePath'],
                'file_name': file_info['fileName'],
                'file_size': file_info['fileSize'] or '',
                'date_created': file_info['created'].isoformat() if file_info['created'] else '',
                'date_modified': file_info['modified'].isoformat() if file_info['modified'] else '',
                'date_accessed': file_info['accessed'].isoformat() if file_info['accessed'] else '',
                'date_changed': file_info['changed'].isoformat() if file_info['changed'] else '',
                'md5': file_info['md5'] or '',
                'sha1': file_info['sha1'] or '',
                'sha256': file_info['sha256'] or '',
                'mft_entry': file_info['metaDataAddr'] or '',
                'content_status': file_info['fileContentStatus'] or '',
                'meta_type': file_info['metaType'] or '',
                'user_sid': file_info['userSID'] or ''
            })
    
    print(f"✓ Exported {len(files):,} collected files to {output_path}")
    
    # Print summary
    print(f"\nSummary:")
    print(f"  Files with creation date: {sum(1 for f in files.values() if f['created']):,}")
    print(f"  Files with modification date: {sum(1 for f in files.values() if f['modified']):,}")
    print(f"  Total file size: {sum(f['fileSize'] or 0 for f in files.values()):,} bytes")
    print(f"  Files with hashes: {sum(1 for f in files.values() if f['md5'] or f['sha1'] or f['sha256']):,}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python export_collected_files.py <timeline.jsonl> [output.csv]")
        print("\nExample:")
        print("  python export_collected_files.py reports/KAN-GW2_timeline.jsonl")
        sys.exit(1)
    
    jsonl_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    parse_timeline(jsonl_path, output_path)

