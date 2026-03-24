import EventView from './EventView'
import FieldValue from '../components/FieldValue'

const columns = [
  { id: 'suspicious', header: 'Flag', cell: ({ row }: any) => {
    if (row.original.data.is_suspicious) return <span className="text-amber-400 text-xs font-medium">SUSPICIOUS</span>
    return null
  }},
  { id: 'command', header: 'Command / Script', cell: ({ row }: any) => {
    const d = row.original.data
    const text = String(d.command || d.ScriptBlockText || '')
    if (!text) return '-'
    const field = d.command ? 'command' : 'ScriptBlockText'
    return (
      <span className="max-w-xl truncate block font-mono text-xs" title={text}>
        <FieldValue field={field} value={text}>{text}</FieldValue>
      </span>
    )
  }},
  { id: 'source', header: 'Source', cell: ({ row }: any) => {
    const d = row.original.data
    const v = String(d.history_file || d.ScriptBlockId || '')
    if (!v) return '-'
    const field = d.history_file ? 'history_file' : 'ScriptBlockId'
    return <FieldValue field={field} value={v}>{v}</FieldValue>
  }},
  { id: 'line', header: 'Line', cell: ({ row }: any) => {
    const d = row.original.data
    if (d.line_number != null && d.line_number !== '') {
      const v = String(d.line_number)
      return <FieldValue field="line_number" value={v}>{v}</FieldValue>
    }
    if (d.MessageNumber != null && d.MessageNumber !== '') {
      const v = String(d.MessageNumber)
      return <FieldValue field="MessageNumber" value={v}>{v}</FieldValue>
    }
    return '-'
  }},
  { id: 'eid', header: 'Event ID', cell: ({ row }: any) => {
    const v = String(row.original.data.event_identifier || '')
    return v ? <FieldValue field="event_identifier" value={v}>{v}</FieldValue> : '-'
  }},
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
