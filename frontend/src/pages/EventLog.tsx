import EventView from './EventView'
import FieldValue from '../components/FieldValue'

const columns = [
  { id: 'channel', header: 'Channel', cell: ({ row }: any) => {
    const v = String(row.original.data.channel || '')
    return v ? <FieldValue field="channel" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => {
    const v = String(row.original.data.event_identifier || '')
    return v ? <FieldValue field="event_identifier" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'source', header: 'Source', cell: ({ row }: any) => {
    const v = String(row.original.data.source_name || '')
    return v ? <FieldValue field="source_name" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'computer', header: 'Computer', cell: ({ row }: any) => {
    const v = String(row.original.data.computer_name || '')
    return v ? <FieldValue field="computer_name" value={v}>{v}</FieldValue> : '-'
  }},
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
