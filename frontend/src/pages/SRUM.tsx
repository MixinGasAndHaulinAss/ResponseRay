import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'app',
    header: 'Application',
    cell: ({ row }: any) => {
      const v = String(row.original.data.application || '')
      return v ? <FieldValue field="application" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'fg',
    header: 'Foreground Time',
    cell: ({ row }: any) => {
      const t = row.original.data.foreground_cycle_time
      if (t === undefined || t === null || t === '') return '-'
      const v = String(t)
      return <FieldValue field="foreground_cycle_time" value={v}>{Number(t).toLocaleString()}</FieldValue>
    },
  },
  {
    id: 'bg',
    header: 'Background Time',
    cell: ({ row }: any) => {
      const t = row.original.data.background_cycle_time
      if (t === undefined || t === null || t === '') return '-'
      const v = String(t)
      return <FieldValue field="background_cycle_time" value={v}>{Number(t).toLocaleString()}</FieldValue>
    },
  },
  {
    id: 'connected',
    header: 'Connected (s)',
    cell: ({ row }: any) => {
      const t = row.original.data.connected_time
      if (t === undefined || t === null || t === '') return '-'
      const v = String(t)
      return <FieldValue field="connected_time" value={v}>{Number(t).toLocaleString()}</FieldValue>
    },
  },
  {
    id: 'user',
    header: 'User SID',
    cell: ({ row }: any) => {
      const v = String(row.original.data.user_sid || '')
      return v ? (
        <FieldValue field="user_sid" value={v}>
          <span className="text-xs font-mono">{v}</span>
        </FieldValue>
      ) : (
        '-'
      )
    },
  },
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
