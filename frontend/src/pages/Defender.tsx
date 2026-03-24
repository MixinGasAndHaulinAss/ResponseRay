import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'eid',
    header: 'Event ID',
    cell: ({ row }: any) => {
      const v = String(row.original.data.event_identifier || '')
      return v ? <FieldValue field="event_identifier" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'threat',
    header: 'Threat',
    cell: ({ row }: any) => {
      const d = row.original.data
      const threat = d['Threat Name']
      if (threat) {
        const v = String(threat)
        return <FieldValue field="Threat Name" value={v}>{v}</FieldValue>
      }
      const cat = d['Category Name']
      if (cat) {
        const v = String(cat)
        return <FieldValue field="Category Name" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'severity',
    header: 'Severity',
    cell: ({ row }: any) => {
      const s = row.original.data['Severity Name']
      if (!s) return '-'
      const v = String(s)
      const colors: Record<string, string> = { Severe: 'text-red-400', High: 'text-red-400', Medium: 'text-amber-400', Low: 'text-yellow-400' }
      return (
        <FieldValue field="Severity Name" value={v}>
          <span className={colors[s] || 'text-gray-300'}>{s}</span>
        </FieldValue>
      )
    },
  },
  {
    id: 'action',
    header: 'Action',
    cell: ({ row }: any) => {
      const v = String(row.original.data['Action Name'] || '')
      return v ? <FieldValue field="Action Name" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'path',
    header: 'Path',
    cell: ({ row }: any) => {
      const d = row.original.data
      const pathVal = d.Path
      const sourceVal = d['Source Path']
      const v = String(pathVal || sourceVal || '')
      if (!v) return '-'
      const field = pathVal != null && pathVal !== '' ? 'Path' : 'Source Path'
      return (
        <FieldValue field={field} value={v}>
          <span className="max-w-md truncate block">{v}</span>
        </FieldValue>
      )
    },
  },
  {
    id: 'product',
    header: 'Version',
    cell: ({ row }: any) => {
      const d = row.original.data
      const pv = d['Product Version']
      if (pv != null && pv !== '') {
        const v = String(pv)
        return <FieldValue field="Product Version" value={v}>{v}</FieldValue>
      }
      const ev = d['Engine version']
      if (ev != null && ev !== '') {
        const v = String(ev)
        return <FieldValue field="Engine version" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

export default function Defender() {
  return <EventView title="Windows Defender" eventTypes={['windows_defender']} columns={columns} />
}
