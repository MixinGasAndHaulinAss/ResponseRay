import EventView from './EventView'

const columns = [
  { id: 'username', header: 'Username', cell: ({ row }: any) => row.original.data.username || '-' },
  { id: 'account_type', header: 'Type', cell: ({ row }: any) => row.original.data.account_type || '-' },
  { id: 'admin_priv', header: 'Admin', cell: ({ row }: any) => {
    const priv = row.original.data.admin_priv
    return priv === 'local' ? <span className="text-amber-400">Local Admin</span> : priv || '-'
  }},
  { id: 'account_status', header: 'Status', cell: ({ row }: any) => {
    const status = row.original.data.account_status
    return status === 'Disabled' ? <span className="text-red-400">Disabled</span> : <span className="text-green-400">{status}</span>
  }},
  { id: 'login_count', header: 'Logins', cell: ({ row }: any) => row.original.data.login_count ?? '-' },
  { id: 'user_domain', header: 'Domain', cell: ({ row }: any) => row.original.data.user_domain || '-' },
  { id: 'user_sid', header: 'SID', cell: ({ row }: any) => <span className="text-xs font-mono">{row.original.data.user_sid || '-'}</span> },
  { id: 'message', header: 'Message', cell: ({ row }: any) => row.original.message || '-' },
]

export default function Accounts() {
  return <EventView title="Windows Accounts" eventTypes={['account_created']} columns={columns} />
}
