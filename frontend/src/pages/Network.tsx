import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'local',
    header: 'Local',
    cell: ({ row }: any) => {
      const d = row.original.data
      const ip = d.local_ip || d.remote_host_name || ''
      const port = d.local_port || ''
      if (!ip) return '-'
      const display = `${ip}${port ? ':' + port : ''}`
      const field = d.local_ip ? 'local_ip' : 'remote_host_name'
      const v = String(d.local_ip || d.remote_host_name)
      return <FieldValue field={field} value={v}>{display}</FieldValue>
    },
  },
  {
    id: 'remote',
    header: 'Remote',
    cell: ({ row }: any) => {
      const d = row.original.data
      const ip = d.remote_ip || d.ServerName || d.remote_share_name || ''
      const port = d.remote_port || ''
      if (!ip) return '-'
      const display = `${ip}${port ? ':' + port : ''}`
      const field = d.remote_ip ? 'remote_ip' : d.ServerName ? 'ServerName' : 'remote_share_name'
      const v = String(d.remote_ip || d.ServerName || d.remote_share_name)
      return <FieldValue field={field} value={v}>{display}</FieldValue>
    },
  },
  {
    id: 'proto',
    header: 'Protocol',
    cell: ({ row }: any) => {
      const d = row.original.data
      const v = String(d.connection_type || d.ConnectionType || '')
      if (!v) return '-'
      const field = d.connection_type ? 'connection_type' : 'ConnectionType'
      return <FieldValue field={field} value={v}>{v}</FieldValue>
    },
  },
  {
    id: 'state',
    header: 'State',
    cell: ({ row }: any) => {
      const d = row.original.data
      const v = String(d.state || d.Status || '')
      if (!v) return '-'
      const field = d.state ? 'state' : 'Status'
      return <FieldValue field={field} value={v}>{v}</FieldValue>
    },
  },
  {
    id: 'pid',
    header: 'PID',
    cell: ({ row }: any) => {
      const v = String(row.original.data.pid || '')
      return v ? <FieldValue field="pid" value={v}>{v}</FieldValue> : '-'
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
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All Connections', eventTypes: ['network_connection'] },
  { key: 'shares', label: 'Shares', eventTypes: ['network_share'] },
  { key: 'smb', label: 'SMB', eventTypes: ['windows_smb'] },
  { key: 'dns', label: 'DNS', eventTypes: ['windows_dns'] },
  { key: 'dhcp', label: 'DHCP', eventTypes: ['dhcp_event'] },
]

export default function Network() {
  return <EventView title="Network" eventTypes={['network_connection', 'network_share', 'windows_smb', 'windows_dns', 'dhcp_event']} columns={columns} tabs={tabs} />
}
