#!/usr/bin/env python3
"""
Quick analysis of SYSVOL structure from DC00_timeline.jsonl
Shows what data is available before building full reconstruction tool.
"""

import json
import re
from collections import defaultdict
from pathlib import Path
from datetime import datetime

def analyze_sysvol(jsonl_path):
    """Analyze SYSVOL entries in the JSONL timeline file."""
    
    # Resolve path relative to project root if needed
    jsonl_path = Path(jsonl_path)
    if not jsonl_path.is_absolute():
        # Try relative to project root (parent of scripts directory)
        project_root = Path(__file__).parent.parent
        jsonl_path = project_root / jsonl_path
    
    if not jsonl_path.exists():
        print(f"Error: File not found: {jsonl_path}")
        return None
    
    sysvol_entries = []
    paths_seen = set()
    gpos = defaultdict(lambda: {'files': [], 'created': None, 'modified': None})
    directory_structure = defaultdict(set)
    timestamp_types = defaultdict(int)
    
    print(f"Analyzing {jsonl_path}...")
    print("=" * 80)
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                
                # Check if this is a SYSVOL-related entry
                file_path = entry.get('filePath', '')
                if not file_path or 'SYSVOL' not in file_path.upper():
                    continue
                
                # Only process MFT entries (not event log entries)
                data_type = entry.get('data_type', '')
                if not data_type.startswith('fs:stat:ntfs:'):
                    continue
                
                sysvol_entries.append(entry)
                paths_seen.add(file_path)
                
                # Extract directory structure
                path_parts = file_path.split('/')
                for i in range(1, len(path_parts)):
                    dir_path = '/'.join(path_parts[:i])
                    if dir_path:
                        directory_structure[dir_path].add('/'.join(path_parts[:i+1]))
                
                # Track timestamp types
                ts_desc = entry.get('timestamp_desc', '')
                timestamp_types[ts_desc] += 1
                
                # Identify GPOs (paths with GUID pattern)
                gpo_match = re.search(r'/Policies/(\{[A-F0-9-]+\})/', file_path, re.IGNORECASE)
                if gpo_match:
                    gpo_guid = gpo_match.group(1)
                    gpos[gpo_guid]['files'].append({
                        'path': file_path,
                        'filename': entry.get('fileName', ''),
                        'size': entry.get('fileSize'),
                        'timestamp': entry.get('datetime'),
                        'timestamp_desc': ts_desc,
                        'mft_entry': entry.get('meta_data_addr')
                    })
                    
                    # Track earliest creation and latest modification
                    dt_str = entry.get('datetime')
                    if dt_str:
                        try:
                            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
                            if 'Created' in ts_desc:
                                if gpos[gpo_guid]['created'] is None or dt < gpos[gpo_guid]['created']:
                                    gpos[gpo_guid]['created'] = dt
                            if 'Modified' in ts_desc or 'Changed' in ts_desc:
                                if gpos[gpo_guid]['modified'] is None or dt > gpos[gpo_guid]['modified']:
                                    gpos[gpo_guid]['modified'] = dt
                        except:
                            pass
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error on line {line_num}: {e}")
                continue
    
    # Print summary statistics
    print(f"\nSUMMARY STATISTICS")
    print("-" * 80)
    print(f"Total SYSVOL MFT entries found: {len(sysvol_entries):,}")
    print(f"Unique file paths: {len(paths_seen):,}")
    print(f"Unique directories inferred: {len(directory_structure):,}")
    print(f"Group Policy Objects (GPOs) identified: {len(gpos):,}")
    
    print(f"\nTIMESTAMP TYPES FOUND")
    print("-" * 80)
    for ts_type, count in sorted(timestamp_types.items(), key=lambda x: -x[1]):
        print(f"  {ts_type}: {count:,}")
    
    # Show directory structure sample
    print(f"\nDIRECTORY STRUCTURE SAMPLE (first 20 directories)")
    print("-" * 80)
    sorted_dirs = sorted(directory_structure.keys())
    for dir_path in sorted_dirs[:20]:
        children = sorted(directory_structure[dir_path])
        print(f"  {dir_path}/")
        for child in children[:3]:  # Show first 3 children
            child_name = child.replace(dir_path + '/', '')
            print(f"    └─ {child_name}")
        if len(children) > 3:
            print(f"    └─ ... ({len(children) - 3} more)")
    
    # Show GPOs found
    print(f"\nGROUP POLICY OBJECTS (GPOs) FOUND")
    print("-" * 80)
    for gpo_guid, gpo_data in sorted(gpos.items())[:10]:  # Show first 10 GPOs
        print(f"\n  GPO: {gpo_guid}")
        print(f"    Files: {len(gpo_data['files'])}")
        if gpo_data['created']:
            print(f"    Created: {gpo_data['created']}")
        if gpo_data['modified']:
            print(f"    Modified: {gpo_data['modified']}")
        
        # Show key files
        key_files = [f for f in gpo_data['files'] if any(x in f['filename'].lower() 
                    for x in ['gpt.ini', 'registry.pol', 'machine', 'user'])]
        if key_files:
            print(f"    Key files:")
            for f in key_files[:5]:
                print(f"      - {f['filename']} ({f['timestamp']})")
    
    if len(gpos) > 10:
        print(f"\n  ... ({len(gpos) - 10} more GPOs)")
    
    # Show file type breakdown
    print(f"\nFILE TYPE BREAKDOWN")
    print("-" * 80)
    file_types = defaultdict(int)
    for entry in sysvol_entries:
        filename = entry.get('fileName', '')
        if filename:
            ext = Path(filename).suffix.lower()
            if not ext:
                ext = '(no extension)'
            file_types[ext] += 1
    
    for ext, count in sorted(file_types.items(), key=lambda x: -x[1])[:15]:
        print(f"  {ext}: {count:,}")
    
    # Show sample entries
    print(f"\nSAMPLE ENTRIES (first 5)")
    print("-" * 80)
    for entry in sysvol_entries[:5]:
        print(f"\n  Path: {entry.get('filePath', 'N/A')}")
        print(f"    Timestamp: {entry.get('datetime', 'N/A')}")
        print(f"    Type: {entry.get('timestamp_desc', 'N/A')}")
        print(f"    Size: {entry.get('fileSize', 'N/A')} bytes")
        print(f"    MFT Entry: {entry.get('meta_data_addr', 'N/A')}")
        print(f"    Data Type: {entry.get('data_type', 'N/A')}")
    
    return {
        'total_entries': len(sysvol_entries),
        'unique_paths': len(paths_seen),
        'directories': len(directory_structure),
        'gpos': len(gpos),
        'gpo_details': dict(gpos)
    }

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        jsonl_path = sys.argv[1]
    else:
        # Default to DC00 timeline if in reports directory
        project_root = Path(__file__).parent.parent
        jsonl_path = project_root / 'reports' / 'DC00_timeline.jsonl'
        if not jsonl_path.exists():
            print("Usage: python analyze_sysvol_quick.py <timeline.jsonl>")
            print("\nExample:")
            print("  python analyze_sysvol_quick.py ../reports/DC00_timeline.jsonl")
            sys.exit(1)
    
    results = analyze_sysvol(jsonl_path)
    if results:
        print(f"\n{'=' * 80}")
        print("Analysis complete!")

