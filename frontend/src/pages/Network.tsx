import EventView from './EventView'

const columns = [
  { id: 'local', header: 'Local', cell: ({ row }: any) => {
    const d = row.original.data
    const ip = d.local_ip || d.remote_host_name || ''
    const port = d.local_port || ''
    return ip ? `${ip}${port ? ':' + port : ''}` : '-'
  }},
  { id: 'remote', header: 'Remote', cell: ({ row }: any) => {
    const d = row.original.data
    const ip = d.remote_ip || d.ServerName || d.remote_share_name || ''
    const port = d.remote_port || ''
    return ip ? `${ip}${port ? ':' + port : ''}` : '-'
  }},
  { id: 'proto', header: 'Protocol', cell: ({ row }: any) => row.original.data.connection_type || row.original.data.ConnectionType || '-' },
  { id: 'state', header: 'State', cell: ({ row }: any) => row.original.data.state || row.original.data.Status || '-' },
  { id: 'pid', header: 'PID', cell: ({ row }: any) => row.original.data.pid || '-' },
  { id: 'user', header: 'User', cell: ({ row }: any) => row.original.data.user_id || '-' },
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
