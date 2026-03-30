#!/usr/bin/env python3
"""
Export interactive console sessions and RDP sessions from CyberTriage timeline JSONL files.

Extracts session data from:
- Windows Security Event Logs (4624, 4625, 4634, 4647)
- Terminal Services Event Logs (21, 22, 23, 24, 25, 1149)
- Registry Terminal Server Client history
- SystemAPI current sessions

Exports to CSV with comprehensive session details including:
- Connection type (Interactive Console, RDP, Network)
- Start and end times
- Source IP addresses and hostnames
- Session duration
- Authentication details
"""

import json
import csv
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def parse_logon_type(logon_type):
    """
    Parse Windows logon type to human-readable format.
    
    Logon Types:
    2 = Interactive (console)
    3 = Network
    4 = Batch
    5 = Service
    7 = Unlock
    8 = NetworkCleartext
    9 = NewCredentials
    10 = RemoteInteractive (RDP)
    11 = CachedInteractive
    """
    logon_type_map = {
        '2': 'Interactive',
        '3': 'Network',
        '4': 'Batch',
        '5': 'Service',
        '7': 'Unlock',
        '8': 'NetworkCleartext',
        '9': 'NewCredentials',
        '10': 'RemoteInteractive',
        '11': 'CachedInteractive',
    }
    return logon_type_map.get(str(logon_type), f'Type {logon_type}')


def determine_connection_type(entry):
    """
    Determine connection type from entry data.
    
    Returns: 'Interactive Console', 'RDP', 'Network', or 'Unknown'
    """
    # Check Terminal Services events first
    if entry.get('event_type') == 'windows_rdp':
        address = entry.get('Address', '')
        if address == 'LOCAL':
            return 'Interactive Console'
        else:
            return 'RDP'
    
    # Check Registry RDP entries
    if entry.get('event_type') == 'rdp_connection':
        return 'RDP'
    
    # Check Security event log entries
    logon_type = entry.get('LogonType', '')
    address = entry.get('Address', '')
    ip_address = entry.get('IpAddress', '')
    
    # LogonType 10 = RemoteInteractive (RDP)
    if logon_type == '10':
        return 'RDP'
    
    # LogonType 2 = Interactive (console)
    if logon_type == '2':
        # Check if it's truly local
        if address == 'LOCAL' or ip_address in ['-', '', '127.0.0.1', '::1']:
            return 'Interactive Console'
        # Could still be RDP if IP is present
        if ip_address and ip_address not in ['-', '', '127.0.0.1', '::1']:
            return 'RDP'
        return 'Interactive Console'
    
    # LogonType 3 = Network
    if logon_type == '3':
        return 'Network'
    
    # Default based on event type
    if entry.get('event_type') == 'windows_rdp':
        return 'RDP'
    
    return 'Unknown'


def extract_sessions(jsonl_path, output_path=None):
    """
    Extract session and RDP connection data from timeline JSONL file.
    
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
    
    # Store sessions by logon ID (most reliable correlation)
    sessions_by_logon_id = defaultdict(lambda: {
        'logon_id': None,
        'session_id': None,
        'connection_type': None,
        'username': None,
        'domain': None,
        'source_ip': None,
        'source_hostname': None,
        'target_hostname': None,
        'logon_time': None,
        'logoff_time': None,
        'logon_type': None,
        'logon_type_desc': None,
        'authentication_method': None,
        'logon_process': None,
        'workstation_name': None,
        'event_ids': set(),
        'data_sources': set(),
        'hostname': None,
        'failed': False,
    })
    
    # Also track by session ID for RDP sessions
    sessions_by_session_id = defaultdict(lambda: {
        'session_id': None,
        'username': None,
        'logon_time': None,
        'logoff_time': None,
        'connection_type': None,
    })
    
    # Track failed logons separately
    failed_logons = []
    
    # Counters
    logon_count = 0
    logoff_count = 0
    rdp_terminal_count = 0
    rdp_registry_count = 0
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line.strip())
                
                # Process Windows Security Event Log entries
                if (entry.get('event_type') == 'windows_logon' and 
                    entry.get('event_identifier') in ['4624', '4625', '4634', '4647', '4672']):
                    
                    eid = entry.get('event_identifier', '')
                    logon_id = entry.get('TargetLogonId') or entry.get('LogonID') or entry.get('LogonId', '')
                    session_id = entry.get('SessionID', '')
                    username = entry.get('TargetUserName') or entry.get('SubjectUserName', '')
                    domain = entry.get('TargetDomainName') or entry.get('SubjectDomainName', '')
                    ip_address = entry.get('IpAddress', '') or entry.get('IpAddress', '-')
                    workstation = entry.get('WorkstationName', '')
                    logon_type = entry.get('LogonType', '')
                    auth_package = entry.get('AuthenticationPackageName', '')
                    logon_process = entry.get('LogonProcessName', '')
                    hostname = entry.get('hostName') or entry.get('host_name', '')
                    dt = entry.get('datetime', '')
                    
                    # Failed logon (4625)
                    if eid == '4625':
                        failed_logons.append({
                            'timestamp': dt,
                            'username': username,
                            'domain': domain,
                            'source_ip': ip_address if ip_address != '-' else '',
                            'source_hostname': workstation,
                            'logon_type': logon_type,
                            'logon_type_desc': parse_logon_type(logon_type),
                            'failure_reason': entry.get('SubStatus', ''),
                            'hostname': hostname,
                            'event_id': eid,
                            'data_source': 'EventLog',
                        })
                        continue
                    
                    # Successful logon (4624, 4672)
                    if eid in ['4624', '4672']:
                        logon_count += 1
                        if logon_id:
                            session = sessions_by_logon_id[logon_id]
                            session['logon_id'] = logon_id
                            session['session_id'] = session_id or session['session_id']
                            session['username'] = username or session['username']
                            session['domain'] = domain or session['domain']
                            session['source_ip'] = ip_address if ip_address != '-' else session.get('source_ip')
                            session['source_hostname'] = workstation or session.get('source_hostname')
                            session['target_hostname'] = hostname or session.get('target_hostname')
                            session['logon_time'] = dt or session.get('logon_time')
                            session['logon_type'] = logon_type or session.get('logon_type')
                            session['logon_type_desc'] = parse_logon_type(logon_type) or session.get('logon_type_desc')
                            session['authentication_method'] = auth_package or session.get('authentication_method')
                            session['logon_process'] = logon_process or session.get('logon_process')
                            session['workstation_name'] = workstation or session.get('workstation_name')
                            session['hostname'] = hostname or session.get('hostname')
                            session['event_ids'].add(eid)
                            session['data_sources'].add('EventLog')
                            
                            # Determine connection type
                            if not session['connection_type']:
                                session['connection_type'] = determine_connection_type(entry)
                    
                    # Logoff (4634, 4647)
                    elif eid in ['4634', '4647']:
                        logoff_count += 1
                        if logon_id:
                            session = sessions_by_logon_id[logon_id]
                            session['logoff_time'] = dt or session.get('logoff_time')
                            session['event_ids'].add(eid)
                            session['data_sources'].add('EventLog')
                
                # Process Terminal Services (RDP) events
                elif entry.get('event_type') == 'windows_rdp':
                    rdp_terminal_count += 1
                    eid = entry.get('event_identifier', '')
                    session_id = entry.get('SessionID', '')
                    username = entry.get('User', '')
                    address = entry.get('Address', '')
                    hostname = entry.get('hostName') or entry.get('host_name', '')
                    dt = entry.get('datetime', '')
                    
                    # Parse username/domain
                    if '\\' in username:
                        domain, user = username.split('\\', 1)
                    else:
                        domain = ''
                        user = username
                    
                    connection_type = determine_connection_type(entry)
                    
                    # RDP session logon (21)
                    if eid == '21':
                        if session_id:
                            session = sessions_by_session_id[session_id]
                            session['session_id'] = session_id
                            session['username'] = user or session.get('username')
                            session['logon_time'] = dt or session.get('logon_time')
                            session['connection_type'] = connection_type or session.get('connection_type')
                    
                    # RDP session logoff (23)
                    elif eid == '23':
                        if session_id:
                            session = sessions_by_session_id[session_id]
                            session['session_id'] = session_id
                            session['username'] = user or session.get('username')
                            session['logoff_time'] = dt or session.get('logoff_time')
                            session['connection_type'] = connection_type or session.get('connection_type')
                    
                    # Try to match with logon_id sessions
                    # For RDP, we can use session_id + username as correlation
                    for logon_id, session in sessions_by_logon_id.items():
                        if (session.get('session_id') == session_id and 
                            session.get('username') == user):
                            session['logoff_time'] = dt if eid == '23' else session.get('logoff_time')
                            session['event_ids'].add(eid)
                            session['data_sources'].add('EventLog')
                            if not session['connection_type']:
                                session['connection_type'] = connection_type
                
                # Process Registry RDP connections
                elif entry.get('event_type') == 'rdp_connection':
                    rdp_registry_count += 1
                    remote_host = entry.get('entries', '')
                    username = entry.get('username', '')
                    remote_domain = entry.get('remote_domain', '')
                    local_user = entry.get('local_user', '')
                    hostname = entry.get('hostName') or entry.get('host_name', '')
                    dt = entry.get('datetime', '') or entry.get('last_written_time', '')
                    
                    # Create a session entry for registry RDP
                    # Use a combination key since we don't have logon_id
                    session_key = f"{local_user}@{remote_host}@{dt}"
                    
                    sessions_by_logon_id[session_key] = {
                        'logon_id': None,
                        'session_id': None,
                        'connection_type': 'RDP',
                        'username': username or local_user,
                        'domain': remote_domain,
                        'source_ip': '',  # Not available in registry
                        'source_hostname': remote_host,
                        'target_hostname': hostname,
                        'logon_time': dt,
                        'logoff_time': None,
                        'logon_type': '10',  # RemoteInteractive
                        'logon_type_desc': 'RemoteInteractive',
                        'authentication_method': '',
                        'logon_process': '',
                        'workstation_name': remote_host,
                        'event_ids': {'registry'},
                        'data_sources': {'Registry'},
                        'hostname': hostname,
                        'failed': False,
                    }
                        
            except json.JSONDecodeError:
                continue
            except Exception as e:
                if line_num <= 10:
                    print(f"Warning: Error on line {line_num}: {e}")
                continue
    
    print(f"\nProcessed timeline entries")
    print(f"  Security logon events (4624/4672): {logon_count}")
    print(f"  Security logoff events (4634/4647): {logoff_count}")
    print(f"  Failed logon attempts (4625): {len(failed_logons)}")
    print(f"  Terminal Services RDP events: {rdp_terminal_count}")
    print(f"  Registry RDP connections: {rdp_registry_count}")
    print(f"  Total unique sessions found: {len(sessions_by_logon_id)}")
    print(f"  (Filtering to Interactive Console and RDP only)")
    
    # Merge session_id sessions into logon_id sessions
    for session_id, rdp_session in sessions_by_session_id.items():
        if rdp_session.get('username') and rdp_session.get('logon_time'):
            # Try to find matching logon_id session
            matched = False
            for logon_id, session in sessions_by_logon_id.items():
                if (session.get('session_id') == session_id and 
                    session.get('username') == rdp_session.get('username')):
                    # Merge data
                    if not session.get('logon_time'):
                        session['logon_time'] = rdp_session.get('logon_time')
                    if not session.get('logoff_time') and rdp_session.get('logoff_time'):
                        session['logoff_time'] = rdp_session.get('logoff_time')
                    if not session.get('connection_type'):
                        session['connection_type'] = rdp_session.get('connection_type')
                    matched = True
                    break
            
            # If no match, create new session
            if not matched:
                sessions_by_logon_id[f"rdp_{session_id}"] = {
                    'logon_id': None,
                    'session_id': session_id,
                    'connection_type': rdp_session.get('connection_type', 'RDP'),
                    'username': rdp_session.get('username'),
                    'domain': '',
                    'source_ip': '',
                    'source_hostname': '',
                    'target_hostname': '',
                    'logon_time': rdp_session.get('logon_time'),
                    'logoff_time': rdp_session.get('logoff_time'),
                    'logon_type': '10',
                    'logon_type_desc': 'RemoteInteractive',
                    'authentication_method': '',
                    'logon_process': '',
                    'workstation_name': '',
                    'event_ids': {'rdp_terminal'},
                    'data_sources': {'EventLog'},
                    'hostname': '',
                    'failed': False,
                }
    
    # Calculate durations and prepare for export
    # Filter to only Interactive Console and RDP sessions (hands-on-keyboard activity)
    sessions_list = []
    for logon_id, session in sessions_by_logon_id.items():
        # Skip Network logons (LogonType 3) and Unknown connection types
        connection_type = session.get('connection_type', '')
        logon_type = session.get('logon_type', '')
        
        # Only include Interactive Console (LogonType 2) and RDP (LogonType 10 or RDP connection type)
        if connection_type == 'Network' or (connection_type == 'Unknown' and logon_type not in ['2', '10']):
            continue
        
        # Also filter by logon type if connection type is not set
        if not connection_type or connection_type == 'Unknown':
            if logon_type not in ['2', '10']:
                continue
            # Set connection type based on logon type if not already set
            if logon_type == '2':
                connection_type = 'Interactive Console'
            elif logon_type == '10':
                connection_type = 'RDP'
        
        # Calculate duration if both times available
        duration_seconds = None
        if session['logon_time'] and session['logoff_time']:
            try:
                logon_dt = datetime.fromisoformat(session['logon_time'].replace('Z', '+00:00'))
                logoff_dt = datetime.fromisoformat(session['logoff_time'].replace('Z', '+00:00'))
                duration_seconds = int((logoff_dt - logon_dt).total_seconds())
            except:
                pass
        
        sessions_list.append({
            'session_id': session.get('session_id') or '',
            'logon_id': session.get('logon_id') or logon_id,
            'connection_type': connection_type or session.get('connection_type') or 'Unknown',
            'username': session.get('username') or '',
            'domain': session.get('domain') or '',
            'source_ip': session.get('source_ip') or '',
            'source_hostname': session.get('source_hostname') or session.get('workstation_name') or '',
            'target_hostname': session.get('target_hostname') or session.get('hostname') or '',
            'logon_time': session.get('logon_time') or '',
            'logoff_time': session.get('logoff_time') or '',
            'duration_seconds': duration_seconds if duration_seconds is not None else '',
            'logon_type': session.get('logon_type') or '',
            'logon_type_desc': session.get('logon_type_desc') or '',
            'authentication_method': session.get('authentication_method') or '',
            'logon_process': session.get('logon_process') or '',
            'workstation_name': session.get('workstation_name') or '',
            'event_ids': ','.join(sorted(session.get('event_ids', []))),
            'data_source': ','.join(sorted(session.get('data_sources', []))),
            'hostname': session.get('hostname') or '',
        })
    
    # Add failed logons (only for Interactive/RDP logon types)
    for failed in failed_logons:
        # Only include failed logons for Interactive (2) or RemoteInteractive (10) types
        failed_logon_type = failed.get('logon_type', '')
        if failed_logon_type not in ['2', '10']:
            continue
        
        sessions_list.append({
            'session_id': '',
            'logon_id': '',
            'connection_type': 'Failed Logon',
            'username': failed.get('username', ''),
            'domain': failed.get('domain', ''),
            'source_ip': failed.get('source_ip', ''),
            'source_hostname': failed.get('source_hostname', ''),
            'target_hostname': failed.get('hostname', ''),
            'logon_time': failed.get('timestamp', ''),
            'logoff_time': '',
            'duration_seconds': '',
            'logon_type': failed_logon_type,
            'logon_type_desc': failed.get('logon_type_desc', ''),
            'authentication_method': '',
            'logon_process': '',
            'workstation_name': failed.get('source_hostname', ''),
            'event_ids': failed.get('event_id', ''),
            'data_source': failed.get('data_source', ''),
            'hostname': failed.get('hostname', ''),
        })
    
    if not sessions_list:
        print("\nNo session entries found in timeline.")
        return {'total': 0, 'logons': 0, 'logoffs': 0, 'failed': 0, 'rdp': 0}
    
    # Determine output path
    if not output_path:
        input_path = Path(jsonl_path)
        output_path = input_path.parent / f"{input_path.stem}_sessions_rdp.csv"
    else:
        output_path = Path(output_path)
        if not output_path.is_absolute():
            output_path = Path(jsonl_path).parent / output_path
    
    # Write to CSV
    print(f"\nWriting to {output_path}...")
    
    fieldnames = [
        'session_id',
        'logon_id',
        'connection_type',
        'username',
        'domain',
        'source_ip',
        'source_hostname',
        'target_hostname',
        'logon_time',
        'logoff_time',
        'duration_seconds',
        'logon_type',
        'logon_type_desc',
        'authentication_method',
        'logon_process',
        'workstation_name',
        'event_ids',
        'data_source',
        'hostname',
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        # Sort by logon time
        sessions_list.sort(key=lambda x: x['logon_time'] or '')
        
        for session in sessions_list:
            writer.writerow(session)
    
    print(f"✓ Exported {len(sessions_list)} session entries to {output_path}")
    
    # Print summary statistics
    successful = [s for s in sessions_list if s['connection_type'] != 'Failed Logon']
    failed = [s for s in sessions_list if s['connection_type'] == 'Failed Logon']
    
    print(f"\nSummary:")
    print(f"  Successful sessions: {len(successful):,}")
    print(f"  Failed logon attempts: {len(failed):,}")
    print(f"  Sessions with duration: {sum(1 for s in successful if s['duration_seconds']):,}")
    
    # Connection type breakdown
    conn_types = defaultdict(int)
    for s in successful:
        conn_types[s['connection_type']] += 1
    print(f"  Connection types:")
    for conn_type, count in sorted(conn_types.items()):
        print(f"    {conn_type}: {count:,}")
    
    # Data source breakdown
    sources = defaultdict(int)
    for s in sessions_list:
        for src in s['data_source'].split(','):
            if src:
                sources[src] += 1
    print(f"  Data sources:")
    for src, count in sorted(sources.items()):
        print(f"    {src}: {count:,}")
    
    return {
        'total': len(sessions_list),
        'logons': logon_count,
        'logoffs': logoff_count,
        'failed': len(failed_logons),
        'rdp': rdp_terminal_count + rdp_registry_count
    }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python export_sessions_rdp.py <timeline.jsonl> [output.csv]")
        print("\nExample:")
        print("  python export_sessions_rdp.py ../reports/DC00_timeline.jsonl")
        print("  python export_sessions_rdp.py ../reports/KAN-GW2_timeline.jsonl output/sessions.csv")
        sys.exit(1)
    
    jsonl_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    extract_sessions(jsonl_path, output_path)

