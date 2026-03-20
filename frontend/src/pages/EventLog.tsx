import EventView from './EventView'

const columns = [
  { id: 'channel', header: 'Channel', cell: ({ row }: any) => row.original.data.channel || '-' },
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => row.original.data.event_identifier || '-' },
  { id: 'source', header: 'Source', cell: ({ row }: any) => row.original.data.source_name || '-' },
  { id: 'computer', header: 'Computer', cell: ({ row }: any) => row.original.data.computer_name || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => (
    <span className="max-w-lg truncate block">{row.original.message || '-'}</span>
  )},
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['windows_event'] },
  { key: 'sysmon', label: 'Sysmon', eventTypes: ['windows_event'], channel: 'Microsoft-Windows-Sysmon/Operational' },
  { key: 'security', label: 'Security', eventTypes: ['windows_event'], channel: 'Security' },
  { key: 'application', label: 'Application', eventTypes: ['windows_event'], channel: 'Application' },
  { key: 'system', label: 'System', eventTypes: ['windows_event'], channel: 'System' },
  { key: 'firewall', label: 'Firewall', eventTypes: ['windows_event'], channel: 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' },
  { key: 'winrm', label: 'WinRM', eventTypes: ['windows_event'], channel: 'Microsoft-Windows-WinRM/Operational' },
]

export default function EventLog() {
  return <EventView title="Event Log Explorer" eventTypes={['windows_event']} columns={columns} tabs={tabs} />
}
