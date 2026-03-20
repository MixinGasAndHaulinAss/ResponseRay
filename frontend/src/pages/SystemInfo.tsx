import EventView from './EventView'

const columns = [
  { id: 'type', header: 'Type', cell: ({ row }: any) => {
    const labels: Record<string, string> = {
      registry_software: 'Software', registry_networklist: 'Network Profile',
    }
    return labels[row.original.event_type] || row.original.event_type
  }},
  { id: 'name', header: 'Name', cell: ({ row }: any) => {
    const d = row.original.data
    return d.software_name || d.profile_name || '-'
  }},
  { id: 'publisher', header: 'Publisher / Category', cell: ({ row }: any) => row.original.data.publisher || row.original.data.category || '-' },
  { id: 'host', header: 'Host', cell: ({ row }: any) => row.original.host_name || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['registry_software', 'registry_networklist'] },
  { key: 'software', label: 'Installed Software', eventTypes: ['registry_software'] },
  { key: 'network', label: 'Network Profiles', eventTypes: ['registry_networklist'] },
]

export default function SystemInfo() {
  return <EventView title="System Info" eventTypes={['registry_software', 'registry_networklist']} columns={columns} tabs={tabs} />
}
