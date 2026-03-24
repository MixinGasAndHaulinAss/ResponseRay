import FieldValue from '../components/FieldValue'
import EventView from './EventView'

const columns = [
  {
    id: 'username',
    header: 'Username',
    cell: ({ row }: any) => {
      const v = String(row.original.data.username || '')
      return v ? <FieldValue field="username" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'account_type',
    header: 'Type',
    cell: ({ row }: any) => {
      const v = String(row.original.data.account_type || '')
      return v ? <FieldValue field="account_type" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'admin_priv',
    header: 'Admin',
    cell: ({ row }: any) => {
      const priv = row.original.data.admin_priv
      const v = String(priv ?? '')
      if (!v) return '-'
      if (priv === 'local') {
        return (
          <FieldValue field="admin_priv" value={v}>
            <span className="text-amber-400">Local Admin</span>
          </FieldValue>
        )
      }
      return <FieldValue field="admin_priv" value={v}>{v}</FieldValue>
    },
  },
  {
    id: 'account_status',
    header: 'Status',
    cell: ({ row }: any) => {
      const status = row.original.data.account_status
      const v = String(status ?? '')
      if (!v) return '-'
      if (status === 'Disabled') {
        return (
          <FieldValue field="account_status" value={v}>
            <span className="text-red-400">Disabled</span>
          </FieldValue>
        )
      }
      return (
        <FieldValue field="account_status" value={v}>
          <span className="text-green-400">{v}</span>
        </FieldValue>
      )
    },
  },
  {
    id: 'login_count',
    header: 'Logins',
    cell: ({ row }: any) => {
      const raw = row.original.data.login_count
      if (raw === undefined || raw === null) return '-'
      const v = String(raw)
      return <FieldValue field="login_count" value={v}>{v}</FieldValue>
    },
  },
  {
    id: 'user_domain',
    header: 'Domain',
    cell: ({ row }: any) => {
      const v = String(row.original.data.user_domain || '')
      return v ? <FieldValue field="user_domain" value={v}>{v}</FieldValue> : '-'
    },
  },
  {
    id: 'user_sid',
    header: 'SID',
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

export default function Accounts() {
  return <EventView title="Windows Accounts" eventTypes={['account_created']} columns={columns} />
}
