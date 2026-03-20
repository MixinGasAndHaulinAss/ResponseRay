import EventView from './EventView'
import { EVENT_TYPE_LABELS } from '../lib/utils'

const columns = [
  { id: 'event_type', header: 'Type', cell: ({ row }: any) => (
    <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">
      {EVENT_TYPE_LABELS[row.original.event_type] || row.original.event_type}
    </span>
  )},
  { id: 'source', header: 'Source', cell: ({ row }: any) => row.original.source_short || '-' },
  { id: 'ts_desc', header: 'Timestamp Type', cell: ({ row }: any) => row.original.timestamp_desc || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => (
    <span className="max-w-2xl truncate block">{row.original.message || '-'}</span>
  )},
  { id: 'host', header: 'Host', cell: ({ row }: any) => row.original.host_name || '-' },
]

export default function Timeline() {
  return <EventView title="Timeline" eventTypes={[]} columns={columns} defaultSort="datetime" defaultDir="desc" />
}
