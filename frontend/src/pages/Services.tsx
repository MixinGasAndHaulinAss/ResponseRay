import EventView from './EventView'

const columns = [
  { id: 'name', header: 'Service', cell: ({ row }: any) => row.original.data.service_name || row.original.data.ServiceName || row.original.data.param1 || '-' },
  { id: 'state', header: 'State', cell: ({ row }: any) => row.original.data.param2 || '-' },
  { id: 'image', header: 'Image Path', cell: ({ row }: any) => (
    <span className="max-w-md truncate block">{row.original.data.image_path || row.original.data.ImagePath || '-'}</span>
  )},
  { id: 'type', header: 'Type', cell: ({ row }: any) => row.original.data.ServiceType || '-' },
  { id: 'start', header: 'Start Type', cell: ({ row }: any) => row.original.data.StartType || '-' },
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => row.original.data.event_identifier || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['registry_service', 'windows_service'] },
  { key: 'registry', label: 'Installed (Registry)', eventTypes: ['registry_service'] },
  { key: 'runtime', label: 'Runtime Events', eventTypes: ['windows_service'] },
]

export default function Services() {
  return <EventView title="Services" eventTypes={['registry_service', 'windows_service']} columns={columns} tabs={tabs} />
}
