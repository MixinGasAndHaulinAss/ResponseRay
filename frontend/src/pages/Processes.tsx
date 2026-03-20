import EventView from './EventView'

const columns = [
  { id: 'name', header: 'Process', cell: ({ row }: any) => {
    const d = row.original.data
    return d.NewProcessName || d.process_name || d.program_name || d.file_name || d.value_name || '-'
  }},
  { id: 'cmd', header: 'Command Line', cell: ({ row }: any) => (
    <span className="max-w-md truncate block" title={row.original.data.CommandLine || row.original.data.command_line || ''}>
      {row.original.data.CommandLine || row.original.data.command_line || '-'}
    </span>
  )},
  { id: 'parent', header: 'Parent', cell: ({ row }: any) => row.original.data.ParentProcessName || row.original.data.ParentImage || '-' },
  { id: 'user', header: 'User', cell: ({ row }: any) => row.original.data.SubjectUserName || row.original.data.user_id || row.original.data.User || '-' },
  { id: 'pid', header: 'PID', cell: ({ row }: any) => row.original.data.NewProcessId || row.original.data.ProcessId || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['windows_process', 'process_execution', 'registry_bam', 'registry_amcache', 'registry_userassist'] },
  { key: 'created', label: 'Process Created (4688)', eventTypes: ['windows_process'] },
  { key: 'execution', label: 'Execution Evidence', eventTypes: ['process_execution'] },
  { key: 'bam', label: 'BAM', eventTypes: ['registry_bam'] },
  { key: 'amcache', label: 'Amcache', eventTypes: ['registry_amcache'] },
  { key: 'userassist', label: 'UserAssist', eventTypes: ['registry_userassist'] },
]

export default function Processes() {
  return <EventView title="Processes & Execution" eventTypes={['windows_process', 'process_execution', 'registry_bam', 'registry_amcache', 'registry_userassist']} columns={columns} tabs={tabs} />
}
