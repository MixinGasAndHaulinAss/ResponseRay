import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'name',
    header: 'Process',
    cell: ({ row }: any) => {
      const d = row.original.data
      if (d.NewProcessName) {
        const v = String(d.NewProcessName)
        return <FieldValue field="NewProcessName" value={v}>{v}</FieldValue>
      }
      if (d.process_name) {
        const v = String(d.process_name)
        return <FieldValue field="process_name" value={v}>{v}</FieldValue>
      }
      if (d.program_name) {
        const v = String(d.program_name)
        return <FieldValue field="program_name" value={v}>{v}</FieldValue>
      }
      if (d.file_name) {
        const v = String(d.file_name)
        return <FieldValue field="file_name" value={v}>{v}</FieldValue>
      }
      if (d.value_name) {
        const v = String(d.value_name)
        return <FieldValue field="value_name" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'cmd',
    header: 'Command Line',
    cell: ({ row }: any) => {
      const d = row.original.data
      const v = String(d.CommandLine || d.command_line || '')
      if (!v) return '-'
      const field = d.CommandLine ? 'CommandLine' : 'command_line'
      return (
        <FieldValue field={field} value={v}>
          <span className="max-w-md truncate block" title={v}>
            {v}
          </span>
        </FieldValue>
      )
    },
  },
  {
    id: 'parent',
    header: 'Parent',
    cell: ({ row }: any) => {
      const d = row.original.data
      if (d.ParentProcessName) {
        const v = String(d.ParentProcessName)
        return <FieldValue field="ParentProcessName" value={v}>{v}</FieldValue>
      }
      if (d.ParentImage) {
        const v = String(d.ParentImage)
        return <FieldValue field="ParentImage" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'user',
    header: 'User',
    cell: ({ row }: any) => {
      const d = row.original.data
      if (d.SubjectUserName) {
        const v = String(d.SubjectUserName)
        return <FieldValue field="SubjectUserName" value={v}>{v}</FieldValue>
      }
      if (d.user_id) {
        const v = String(d.user_id)
        return <FieldValue field="user_id" value={v}>{v}</FieldValue>
      }
      if (d.User) {
        const v = String(d.User)
        return <FieldValue field="User" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
  {
    id: 'pid',
    header: 'PID',
    cell: ({ row }: any) => {
      const d = row.original.data
      if (d.NewProcessId !== undefined && d.NewProcessId !== null && d.NewProcessId !== '') {
        const v = String(d.NewProcessId)
        return <FieldValue field="NewProcessId" value={v}>{v}</FieldValue>
      }
      if (d.ProcessId !== undefined && d.ProcessId !== null && d.ProcessId !== '') {
        const v = String(d.ProcessId)
        return <FieldValue field="ProcessId" value={v}>{v}</FieldValue>
      }
      return '-'
    },
  },
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
