import EventView from './EventView'

const columns = [
  { id: 'suspicious', header: 'Flag', cell: ({ row }: any) => {
    if (row.original.data.is_suspicious) return <span className="text-amber-400 text-xs font-medium">SUSPICIOUS</span>
    return null
  }},
  { id: 'command', header: 'Command / Script', cell: ({ row }: any) => {
    const d = row.original.data
    const text = d.command || d.ScriptBlockText || ''
    return <span className="max-w-xl truncate block font-mono text-xs" title={text}>{text || '-'}</span>
  }},
  { id: 'source', header: 'Source', cell: ({ row }: any) => {
    const d = row.original.data
    return d.history_file || d.ScriptBlockId || '-'
  }},
  { id: 'line', header: 'Line', cell: ({ row }: any) => row.original.data.line_number || row.original.data.MessageNumber || '-' },
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => row.original.data.event_identifier || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['powershell_history', 'windows_powershell'] },
  { key: 'history', label: 'Command History', eventTypes: ['powershell_history'] },
  { key: 'scripts', label: 'Script Blocks (4104)', eventTypes: ['windows_powershell'] },
]

export default function PowerShell() {
  return <EventView title="PowerShell" eventTypes={['powershell_history', 'windows_powershell']} columns={columns} tabs={tabs} />
}
