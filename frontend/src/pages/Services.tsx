import EventView from './EventView'
import FieldValue from '../components/FieldValue'

const columns = [
  { id: 'name', header: 'Service', cell: ({ row }: any) => {
    const d = row.original.data
    if (d.service_name) {
      const v = String(d.service_name)
      return <FieldValue field="service_name" value={v}>{v}</FieldValue>
    }
    if (d.ServiceName) {
      const v = String(d.ServiceName)
      return <FieldValue field="ServiceName" value={v}>{v}</FieldValue>
    }
    if (d.param1) {
      const v = String(d.param1)
      return <FieldValue field="param1" value={v}>{v}</FieldValue>
    }
    return '-'
  }},
  { id: 'state', header: 'State', cell: ({ row }: any) => {
    const v = String(row.original.data.param2 || '')
    return v ? <FieldValue field="param2" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'image', header: 'Image Path', cell: ({ row }: any) => {
    const d = row.original.data
    const text = String(d.image_path || d.ImagePath || '')
    if (!text) return '-'
    const field = d.image_path ? 'image_path' : 'ImagePath'
    return (
      <span className="max-w-md truncate block">
        <FieldValue field={field} value={text}>{text}</FieldValue>
      </span>
    )
  }},
  { id: 'type', header: 'Type', cell: ({ row }: any) => {
    const v = String(row.original.data.ServiceType || '')
    return v ? <FieldValue field="ServiceType" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'start', header: 'Start Type', cell: ({ row }: any) => {
    const v = String(row.original.data.StartType || '')
    return v ? <FieldValue field="StartType" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => {
    const v = String(row.original.data.event_identifier || '')
    return v ? <FieldValue field="event_identifier" value={v}>{v}</FieldValue> : '-'
  }},
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['registry_service', 'windows_service'] },
  { key: 'registry', label: 'Installed (Registry)', eventTypes: ['registry_service'] },
  { key: 'runtime', label: 'Runtime Events', eventTypes: ['windows_service'] },
  { key: 'running', label: 'Running', eventTypes: ['windows_service'], dataFilter: { param2: 'running' } },
  { key: 'stopped', label: 'Stopped', eventTypes: ['windows_service'], dataFilter: { param2: 'stopped' } },
]

export default function Services() {
  return <EventView title="Services" eventTypes={['registry_service', 'windows_service']} columns={columns} tabs={tabs} sortableColumns={['name']} />
}
