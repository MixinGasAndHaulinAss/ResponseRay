import EventView from './EventView'

const columns = [
  { id: 'type', header: 'Type', cell: ({ row }: any) => {
    const labels: Record<string, string> = {
      browser_history: 'Browser', registry_typedurls: 'Typed URL', file_access: 'File Access',
      registry_recentdocs: 'Recent Doc', lnk_target: 'Shortcut', registry_runmru: 'Run Command',
      registry_shellbag: 'ShellBag', file_deleted: 'Deleted',
    }
    return labels[row.original.event_type] || row.original.event_type
  }},
  { id: 'target', header: 'URL / Path', cell: ({ row }: any) => {
    const d = row.original.data
    return <span className="max-w-lg truncate block">{d.url || d.file_path || d.link_target || d.commands || '-'}</span>
  }},
  { id: 'title', header: 'Title / Name', cell: ({ row }: any) => row.original.data.title || row.original.data.file_name || row.original.data.lnk_file || '-' },
  { id: 'browser', header: 'Browser', cell: ({ row }: any) => row.original.data.browser || '-' },
  { id: 'user', header: 'User', cell: ({ row }: any) => row.original.data.user_id || '-' },
  { id: 'size', header: 'Size', cell: ({ row }: any) => {
    const s = row.original.data.file_size
    return s ? `${Math.round(Number(s) / 1024)} KB` : '-'
  }},
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
