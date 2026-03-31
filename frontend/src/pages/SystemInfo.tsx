import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'type',
    header: 'Type',
    cell: ({ row }: any) => {
      const labels: Record<string, string> = {
        registry_software: 'Software',
        registry_networklist: 'Network Profile',
        os_config: 'System Config',
      }
      const et = row.original.event_type
      const v = String(et || '')
      if (!v) return '-'
      const display = labels[et] || et
      return <FieldValue field="event_type" value={v}>{display}</FieldValue>
    },
  },
  {
    id: 'name',
    header: 'Name',
    cell: ({ row }: any) => {
      const d = row.original.data
      const sn = d.software_name
      if (sn != null && sn !== '') {
        const v = String(sn)
        return <FieldValue field="software_name" value={v}>{v}</FieldValue>
      }
      const pn = d.profile_name
      if (pn != null && pn !== '') {
        const v = String(pn)
        return <FieldValue field="profile_name" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'publisher',
    header: 'Publisher / Category',
    cell: ({ row }: any) => {
      const d = row.original.data
      const pub = d.publisher
      if (pub != null && pub !== '') {
        const v = String(pub)
        return <FieldValue field="publisher" value={v}>{v}</FieldValue>
      }
      const cat = d.category
      if (cat != null && cat !== '') {
        const v = String(cat)
        return <FieldValue field="category" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'host',
    header: 'Host',
    cell: ({ row }: any) => {
      const v = String(row.original.host_name || '')
      return v ? <FieldValue field="host_name" value={v}>{v}</FieldValue> : '-'
    },
  },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['registry_software', 'registry_networklist', 'os_config'] },
  { key: 'software', label: 'Installed Software', eventTypes: ['registry_software'] },
  { key: 'network', label: 'Network Profiles', eventTypes: ['registry_networklist'] },
  { key: 'sysconfig', label: 'System Config', eventTypes: ['os_config'] },
]

export default function SystemInfo() {
  return <EventView title="System Info" eventTypes={['registry_software', 'registry_networklist', 'os_config']} columns={columns} tabs={tabs} />
}
