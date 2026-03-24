import EventView from './EventView'
import FieldValue from '../components/FieldValue'

const columns = [
  { id: 'type', header: 'Type', cell: ({ row }: any) => {
    const et = row.original.event_type
    const labels: Record<string, string> = {
      startup_item: 'Startup',
      wmi_persistence: 'WMI',
      registry_winlogon: 'Winlogon',
    }
    const display = labels[et] || et
    const raw = String(et || '')
    if (!raw) return '-'
    return <FieldValue field="event_type" value={raw}>{display}</FieldValue>
  }},
  { id: 'name', header: 'Name / Pattern', cell: ({ row }: any) => {
    const d = row.original.data
    if (d.description) {
      const v = String(d.description)
      return <FieldValue field="description" value={v}>{v}</FieldValue>
    }
    if (d.pattern) {
      const v = String(d.pattern)
      return <FieldValue field="pattern" value={v}>{v}</FieldValue>
    }
    if (d.value_name) {
      const v = String(d.value_name)
      return <FieldValue field="value_name" value={v}>{v}</FieldValue>
    }
    return '-'
  }},
  { id: 'details', header: 'Details', cell: ({ row }: any) => {
    const d = row.original.data
    const text = String(d.details || d.value_data || d.context || '')
    if (!text) return '-'
    const field = d.details ? 'details' : d.value_data ? 'value_data' : 'context'
    return (
      <span className="max-w-lg truncate block">
        <FieldValue field={field} value={text}>{text}</FieldValue>
      </span>
    )
  }},
  { id: 'config', header: 'Config Type', cell: ({ row }: any) => {
    const v = String(row.original.data.config_type || '')
    return v ? <FieldValue field="config_type" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'key', header: 'Registry Key', cell: ({ row }: any) => {
    const v = String(row.original.data.registry_key || '')
    if (!v) return '-'
    return (
      <span className="max-w-md truncate block font-mono text-xs">
        <FieldValue field="registry_key" value={v}>{v}</FieldValue>
      </span>
    )
  }},
  { id: 'user', header: 'User', cell: ({ row }: any) => {
    const v = String(row.original.data.user_id || '')
    return v ? <FieldValue field="user_id" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['startup_item', 'wmi_persistence', 'registry_winlogon'] },
  { key: 'startup', label: 'Startup Items', eventTypes: ['startup_item'] },
  { key: 'wmi', label: 'WMI', eventTypes: ['wmi_persistence'] },
  { key: 'winlogon', label: 'Winlogon', eventTypes: ['registry_winlogon'] },
]

export default function Persistence() {
  return <EventView title="Persistence" eventTypes={['startup_item', 'wmi_persistence', 'registry_winlogon']} columns={columns} tabs={tabs} />
}
