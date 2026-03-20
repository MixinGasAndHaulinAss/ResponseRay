import EventView from './EventView'

const columns = [
  { id: 'type', header: 'Type', cell: ({ row }: any) => {
    const et = row.original.event_type
    const labels: Record<string, string> = {
      startup_item: 'Startup',
      wmi_persistence: 'WMI',
      registry_winlogon: 'Winlogon',
    }
    return labels[et] || et
  }},
  { id: 'name', header: 'Name / Pattern', cell: ({ row }: any) => {
    const d = row.original.data
    return d.description || d.pattern || d.value_name || '-'
  }},
  { id: 'details', header: 'Details', cell: ({ row }: any) => (
    <span className="max-w-lg truncate block">
      {row.original.data.details || row.original.data.value_data || row.original.data.context || '-'}
    </span>
  )},
  { id: 'config', header: 'Config Type', cell: ({ row }: any) => row.original.data.config_type || '-' },
  { id: 'key', header: 'Registry Key', cell: ({ row }: any) => (
    <span className="max-w-md truncate block font-mono text-xs">{row.original.data.registry_key || '-'}</span>
  )},
  { id: 'user', header: 'User', cell: ({ row }: any) => row.original.data.user_id || '-' },
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
