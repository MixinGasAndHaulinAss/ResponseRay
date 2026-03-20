import EventView from './EventView'

const columns = [
  { id: 'app', header: 'Application', cell: ({ row }: any) => row.original.data.application || '-' },
  { id: 'fg', header: 'Foreground Time', cell: ({ row }: any) => {
    const t = row.original.data.foreground_cycle_time
    return t !== undefined ? Number(t).toLocaleString() : '-'
  }},
  { id: 'bg', header: 'Background Time', cell: ({ row }: any) => {
    const t = row.original.data.background_cycle_time
    return t !== undefined ? Number(t).toLocaleString() : '-'
  }},
  { id: 'connected', header: 'Connected (s)', cell: ({ row }: any) => {
    const t = row.original.data.connected_time
    return t !== undefined ? Number(t).toLocaleString() : '-'
  }},
  { id: 'user', header: 'User SID', cell: ({ row }: any) => <span className="text-xs font-mono">{row.original.data.user_sid || '-'}</span> },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

const tabs = [
  { key: 'all', label: 'All', eventTypes: ['srum_app_usage', 'srum_network_connectivity'] },
  { key: 'app', label: 'App Usage', eventTypes: ['srum_app_usage'] },
  { key: 'net', label: 'Network Connectivity', eventTypes: ['srum_network_connectivity'] },
]

export default function SRUM() {
  return <EventView title="SRUM (System Resource Usage)" eventTypes={['srum_app_usage', 'srum_network_connectivity']} columns={columns} tabs={tabs} />
}
