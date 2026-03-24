import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const typeLabels: Record<string, string> = {
  browser_history: 'Browser',
  registry_typedurls: 'Typed URL',
  file_access: 'File Access',
  registry_recentdocs: 'Recent Doc',
  lnk_target: 'Shortcut',
  registry_runmru: 'Run Command',
  registry_shellbag: 'ShellBag',
  file_deleted: 'Deleted',
}

const columns = [
  {
    id: 'type',
    header: 'Type',
    cell: ({ row }: any) => {
      const v = String(row.original.event_type || '')
      if (!v) return '-'
      return (
        <FieldValue field="event_type" value={v}>
          {typeLabels[v] || v}
        </FieldValue>
      )
    },
  },
  {
    id: 'target',
    header: 'URL / Path',
    cell: ({ row }: any) => {
      const d = row.original.data
      const v = String(d.url || d.file_path || d.link_target || d.commands || '')
      if (!v) return '-'
      const field = d.url ? 'url' : d.file_path ? 'file_path' : d.link_target ? 'link_target' : 'commands'
      return (
        <FieldValue field={field} value={v}>
          <span className="max-w-lg truncate block">{v}</span>
        </FieldValue>
      )
    },
  },
  {
    id: 'title',
    header: 'Title / Name',
    cell: ({ row }: any) => {
      const d = row.original.data
      if (d.title) {
        const v = String(d.title)
        return <FieldValue field="title" value={v}>{v}</FieldValue>
      }
      if (d.file_name) {
        const v = String(d.file_name)
        return <FieldValue field="file_name" value={v}>{v}</FieldValue>
      }
      if (d.lnk_file) {
        const v = String(d.lnk_file)
        return <FieldValue field="lnk_file" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'browser',
    header: 'Browser',
    cell: ({ row }: any) => {
      const v = String(row.original.data.browser || '')
      return v ? <FieldValue field="browser" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'user',
    header: 'User',
    cell: ({ row }: any) => {
      const v = String(row.original.data.user_id || '')
      return v ? <FieldValue field="user_id" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'size',
    header: 'Size',
    cell: ({ row }: any) => {
      const s = row.original.data.file_size
      if (s === undefined || s === null || s === '') return '-'
      const v = String(s)
      const display = `${Math.round(Number(s) / 1024)} KB`
      return <FieldValue field="file_size" value={v}>{display}</FieldValue>
    },
  },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['browser_history', 'registry_typedurls', 'file_access', 'registry_recentdocs', 'lnk_target', 'registry_runmru', 'registry_shellbag', 'file_deleted'] },
  { key: 'browser', label: 'Browser History', eventTypes: ['browser_history'] },
  { key: 'urls', label: 'Typed URLs', eventTypes: ['registry_typedurls'] },
  { key: 'access', label: 'File Access', eventTypes: ['file_access'] },
  { key: 'shortcuts', label: 'Shortcuts', eventTypes: ['lnk_target'] },
  { key: 'deleted', label: 'Deleted Files', eventTypes: ['file_deleted'] },
  { key: 'shellbags', label: 'ShellBags', eventTypes: ['registry_shellbag'] },
]

export default function WebData() {
  return <EventView title="Web Artifacts & Data Accessed" eventTypes={['browser_history', 'registry_typedurls', 'file_access', 'registry_recentdocs', 'lnk_target', 'registry_runmru', 'registry_shellbag', 'file_deleted']} columns={columns} tabs={tabs} />
}
