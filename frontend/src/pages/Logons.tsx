import EventView from './EventView'

const logonColumns = [
  { id: 'user', header: 'User', cell: ({ row }: any) => row.original.data.TargetUserName || row.original.data.User || '-' },
  { id: 'logonType', header: 'Type', cell: ({ row }: any) => {
    const t = row.original.data.LogonType
    const labels: Record<string, string> = { '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock', '8': 'NetworkClear', '9': 'NewCreds', '10': 'RemoteInteractive', '11': 'CachedInteractive' }
    return t ? `${t} (${labels[t] || '?'})` : '-'
  }},
  { id: 'ip', header: 'Source IP', cell: ({ row }: any) => row.original.data.IpAddress || row.original.data.Address || '-' },
  { id: 'domain', header: 'Domain', cell: ({ row }: any) => row.original.data.TargetDomainName || '-' },
  { id: 'auth', header: 'Auth Package', cell: ({ row }: any) => row.original.data.AuthenticationPackageName || row.original.data.PackageName || '-' },
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => row.original.data.event_identifier || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All Logons', eventTypes: ['windows_logon', 'windows_authentication', 'windows_rdp'] },
  { key: 'success', label: 'Successful', eventTypes: ['windows_logon'], dataFilter: { event_identifier: '4624' } },
  { key: 'failed', label: 'Failed', eventTypes: ['windows_logon'], dataFilter: { event_identifier: '4625' } },
  { key: 'rdp', label: 'RDP', eventTypes: ['windows_rdp'] },
  { key: 'auth', label: 'Authentication', eventTypes: ['windows_authentication'] },
  { key: 'sessions', label: 'Session Processes', eventTypes: ['session_logon'] },
]

export default function Logons() {
  return <EventView title="Logons" eventTypes={['windows_logon', 'windows_authentication', 'windows_rdp', 'session_logon']} columns={logonColumns} tabs={tabs} />
}
