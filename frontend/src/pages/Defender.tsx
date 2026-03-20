import EventView from './EventView'

const columns = [
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => row.original.data.event_identifier || '-' },
  { id: 'threat', header: 'Threat', cell: ({ row }: any) => row.original.data['Threat Name'] || row.original.data['Category Name'] || '-' },
  { id: 'severity', header: 'Severity', cell: ({ row }: any) => {
    const s = row.original.data['Severity Name']
    if (!s) return '-'
    const colors: Record<string, string> = { Severe: 'text-red-400', High: 'text-red-400', Medium: 'text-amber-400', Low: 'text-yellow-400' }
    return <span className={colors[s] || 'text-gray-300'}>{s}</span>
  }},
  { id: 'action', header: 'Action', cell: ({ row }: any) => row.original.data['Action Name'] || '-' },
  { id: 'path', header: 'Path', cell: ({ row }: any) => (
    <span className="max-w-md truncate block">{row.original.data.Path || row.original.data['Source Path'] || '-'}</span>
  )},
  { id: 'product', header: 'Version', cell: ({ row }: any) => row.original.data['Product Version'] || row.original.data['Engine version'] || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

export default function Defender() {
  return <EventView title="Windows Defender" eventTypes={['windows_defender']} columns={columns} />
}
