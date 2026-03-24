import { useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { ArrowLeft, ChevronRight, Flag, Monitor, Search, ShieldAlert, ShieldCheck, User } from 'lucide-react'
import { api, type Event, type LogonUserSummary } from '../lib/api'
import { useEvents } from '../hooks/useEvents'
import DataTable from '../components/tables/DataTable'
import FindingBadge from '../components/findings/FindingBadge'
import FindingDialog from '../components/findings/FindingDialog'
import EventDetailPanel from '../components/EventDetailPanel'
import { formatDateTime, formatNumber, cn } from '../lib/utils'

const SORTABLE_COLUMNS = new Set(['datetime'])

const LOGON_TYPE_LABELS: Record<string, string> = {
  '2': 'Interactive',
  '3': 'Network',
  '4': 'Batch',
  '5': 'Service',
  '7': 'Unlock',
  '8': 'NetworkClear',
  '9': 'NewCreds',
  '10': 'RemoteInteractive',
  '11': 'CachedInteractive',
}

function UserSummaryList({
  users,
  isLoading,
  searchInput,
  setSearchInput,
  showMachineAccounts,
  setShowMachineAccounts,
  onSelectUser,
}: {
  users: LogonUserSummary[]
  isLoading: boolean
  searchInput: string
  setSearchInput: (v: string) => void
  showMachineAccounts: boolean
  setShowMachineAccounts: (v: boolean) => void
  onSelectUser: (u: LogonUserSummary) => void
}) {
  const filtered = useMemo(() => {
    let list = users
    if (!showMachineAccounts) {
      list = list.filter(u => !u.username.endsWith('$'))
    }
    if (searchInput) {
      const q = searchInput.toLowerCase()
      list = list.filter(u =>
        u.username.toLowerCase().includes(q) ||
        (u.domain && u.domain.toLowerCase().includes(q)) ||
        u.auth_packages.toLowerCase().includes(q)
      )
    }
    return list
  }, [users, searchInput, showMachineAccounts])

  const machineCount = useMemo(() => users.filter(u => u.username.endsWith('$')).length, [users])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-foreground">Logons</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowMachineAccounts(!showMachineAccounts)}
            className={cn(
              'flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-md border transition-colors',
              showMachineAccounts
                ? 'bg-brand-600/20 border-brand-500/40 text-brand-300'
                : 'bg-gray-900 border-gray-700 text-gray-500 hover:text-gray-300'
            )}
          >
            <Monitor className="w-3.5 h-3.5" />
            Machine Accounts ({machineCount})
          </button>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              placeholder="Filter users..."
              className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-foreground placeholder-gray-500 w-64 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
          </div>
        </div>
      </div>

      <div className="text-sm text-gray-400">
        {filtered.length} user{filtered.length !== 1 ? 's' : ''} with logon activity
      </div>

      {isLoading ? (
        <div className="text-center py-12 text-gray-500">Loading user summaries...</div>
      ) : (
        <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
          <div className="grid grid-cols-[1fr_100px_90px_90px_80px_150px_150px_40px] gap-2 px-4 py-2.5 border-b border-gray-700 bg-gray-900">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">User</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider text-right">Events</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider text-right">Success</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider text-right">Failed</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider text-right">IPs</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">First Seen</span>
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">Last Seen</span>
            <span />
          </div>

          <div className="divide-y divide-gray-800/50">
            {filtered.map(user => (
              <button
                key={user.username}
                onClick={() => onSelectUser(user)}
                className="w-full grid grid-cols-[1fr_100px_90px_90px_80px_150px_150px_40px] gap-2 px-4 py-3 hover:bg-gray-800/50 transition-colors text-left group"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <User className="w-4 h-4 text-brand-400 shrink-0" />
                  <div className="min-w-0">
                    <span className="text-sm text-gray-200 group-hover:text-brand-300 font-medium truncate block">
                      {user.username}
                    </span>
                    {user.domain && (
                      <span className="text-xs text-gray-500 truncate block">{user.domain}</span>
                    )}
                  </div>
                </div>
                <span className="text-sm text-gray-300 text-right self-center font-mono">
                  {formatNumber(user.total_events)}
                </span>
                <span className="text-sm text-right self-center font-mono">
                  {user.success_count > 0 ? (
                    <span className="text-green-400">{formatNumber(user.success_count)}</span>
                  ) : (
                    <span className="text-gray-600">0</span>
                  )}
                </span>
                <span className="text-sm text-right self-center font-mono">
                  {user.fail_count > 0 ? (
                    <span className="text-red-400">{formatNumber(user.fail_count)}</span>
                  ) : (
                    <span className="text-gray-600">0</span>
                  )}
                </span>
                <span className="text-sm text-gray-400 text-right self-center font-mono">
                  {user.unique_ips}
                </span>
                <span className="text-xs text-gray-400 self-center font-mono">
                  {formatDateTime(user.first_seen)}
                </span>
                <span className="text-xs text-gray-400 self-center font-mono">
                  {formatDateTime(user.last_seen)}
                </span>
                <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-brand-400 self-center justify-self-end transition-colors" />
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="text-center py-8 text-gray-500">No users found</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

const logonColumns: ColumnDef<Event, unknown>[] = [
  { id: 'logonType', header: 'Type', cell: ({ row }) => {
    const t = String(row.original.data.LogonType || '')
    return t ? `${t} (${LOGON_TYPE_LABELS[t] || '?'})` : '-'
  }},
  { id: 'ip', header: 'Source IP', cell: ({ row }) =>
    String(row.original.data.IpAddress || row.original.data.Address || '-')
  },
  { id: 'domain', header: 'Domain', cell: ({ row }) =>
    String(row.original.data.TargetDomainName || '-')
  },
  { id: 'auth', header: 'Auth Package', cell: ({ row }) =>
    String(row.original.data.AuthenticationPackageName || row.original.data.PackageName || '-')
  },
  { id: 'eid', header: 'Event ID', cell: ({ row }) =>
    String(row.original.data.event_identifier || '-')
  },
  { id: 'message', header: 'Message', cell: ({ row }) =>
    String(row.original.message || '-')
  },
]

const tabs = [
  { key: 'all', label: 'All Logons', eventTypes: ['windows_logon', 'windows_authentication', 'windows_rdp', 'session_logon'] },
  { key: 'success', label: 'Successful', eventTypes: ['windows_logon'], dataFilter: { event_identifier: '4624' } },
  { key: 'failed', label: 'Failed', eventTypes: ['windows_logon'], dataFilter: { event_identifier: '4625' } },
  { key: 'rdp', label: 'RDP', eventTypes: ['windows_rdp'] },
  { key: 'auth', label: 'Authentication', eventTypes: ['windows_authentication'] },
  { key: 'sessions', label: 'Session Processes', eventTypes: ['session_logon'] },
]

function UserLogonDetail({
  user,
  onBack,
}: {
  user: LogonUserSummary
  onBack: () => void
}) {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [activeTab, setActiveTab] = useState(0)
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [findingEvent, setFindingEvent] = useState<Event | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [sortField, setSortField] = useState('datetime')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const handleSortChange = (field: string) => {
    if (sortField === field) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('desc')
    }
    setOffset(0)
  }

  const currentTab = tabs[activeTab]

  const userFilter: Record<string, string> = {}
  if (user.username !== 'unknown') {
    userFilter['TargetUserName'] = user.username
  }
  if (currentTab.dataFilter) {
    Object.assign(userFilter, currentTab.dataFilter)
  }

  const { events, total, offset, setOffset, limit, isLoading } = useEvents({
    siteId: siteId!,
    uploadId,
    eventTypes: currentTab.eventTypes || ['windows_logon', 'windows_authentication', 'windows_rdp', 'session_logon'],
    search,
    dataFilters: userFilter,
    sortField,
    sortDir,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearch(searchInput)
    setOffset(0)
  }

  const handleSaveFinding = async (finding: string | null, note: string | null) => {
    if (!siteId || !findingEvent) return
    await api.updateFinding(siteId, findingEvent.id, { finding, finding_note: note })
    queryClient.invalidateQueries({ queryKey: ['events'] })
    setFindingEvent(null)
  }

  const handleBulkFinding = async (finding: string | null) => {
    if (!siteId || selectedIds.size === 0) return
    await api.bulkUpdateFinding(siteId, {
      event_ids: Array.from(selectedIds),
      finding,
      finding_note: null,
    })
    queryClient.invalidateQueries({ queryKey: ['events'] })
    setSelectedIds(new Set())
  }

  const allColumns: ColumnDef<Event, unknown>[] = useMemo(() => [
    {
      id: 'indicators',
      header: '',
      size: 60,
      cell: ({ row }) => (
        <FindingBadge
          finding={row.original.finding}
          isSuspicious={row.original.is_suspicious}
          ctSignificance={row.original.ct_significance}
          small
        />
      ),
    },
    {
      id: 'datetime',
      header: 'Timestamp',
      cell: ({ row }) => <span className="text-xs font-mono">{formatDateTime(row.original.datetime)}</span>,
    },
    ...logonColumns,
    {
      id: 'actions',
      header: '',
      size: 40,
      cell: ({ row }) => (
        <button
          onClick={(e) => { e.stopPropagation(); setFindingEvent(row.original) }}
          className="p-1 text-gray-600 hover:text-foreground"
        >
          <Flag className="w-3.5 h-3.5" />
        </button>
      ),
    },
  ], [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-foreground bg-gray-800 hover:bg-gray-700 rounded-md transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
          <div>
            <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
              <User className="w-5 h-5 text-brand-400" />
              {user.username}
            </h1>
            {user.domain && <span className="text-sm text-gray-400">{user.domain}</span>}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-1 mr-2">
              <span className="text-xs text-gray-400">{selectedIds.size} selected</span>
              <button onClick={() => handleBulkFinding('bad')} className="px-2 py-1 text-xs bg-red-500/20 text-red-400 rounded hover:bg-red-500/30">Bad</button>
              <button onClick={() => handleBulkFinding('suspicious')} className="px-2 py-1 text-xs bg-amber-500/20 text-amber-400 rounded hover:bg-amber-500/30">Suspicious</button>
              <button onClick={() => handleBulkFinding('good')} className="px-2 py-1 text-xs bg-green-500/20 text-green-400 rounded hover:bg-green-500/30">Good</button>
              <button onClick={() => handleBulkFinding(null)} className="px-2 py-1 text-xs bg-gray-700 text-gray-300 rounded hover:bg-gray-600">Clear</button>
            </div>
          )}
          <form onSubmit={handleSearch} className="flex items-center gap-1">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                placeholder="Search logons..."
                className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-foreground placeholder-gray-500 w-64 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
            </div>
          </form>
        </div>
      </div>

      {/* User stats bar */}
      <div className="grid grid-cols-5 gap-3">
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-center">
          <div className="text-lg font-bold text-foreground">{formatNumber(user.total_events)}</div>
          <div className="text-xs text-gray-400">Total Events</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-center">
          <div className="text-lg font-bold text-green-400 flex items-center justify-center gap-1.5">
            <ShieldCheck className="w-4 h-4" />
            {formatNumber(user.success_count)}
          </div>
          <div className="text-xs text-gray-400">Successful</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-center">
          <div className="text-lg font-bold text-red-400 flex items-center justify-center gap-1.5">
            <ShieldAlert className="w-4 h-4" />
            {formatNumber(user.fail_count)}
          </div>
          <div className="text-xs text-gray-400">Failed</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-center">
          <div className="text-lg font-bold text-brand-400">{user.unique_ips}</div>
          <div className="text-xs text-gray-400">Unique IPs</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 text-center">
          <div className="text-sm font-medium text-gray-200 truncate">
            {user.auth_packages || '-'}
          </div>
          <div className="text-xs text-gray-400">Auth Packages</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs text-gray-400">
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 flex items-center justify-between">
          <span>First seen</span>
          <span className="text-gray-200 font-mono">{formatDateTime(user.first_seen)}</span>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 flex items-center justify-between">
          <span>Last seen</span>
          <span className="text-gray-200 font-mono">{formatDateTime(user.last_seen)}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {tabs.map((tab, i) => (
          <button
            key={tab.key}
            onClick={() => { setActiveTab(i); setOffset(0) }}
            className={cn(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === i
                ? 'border-brand-500 text-brand-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <DataTable
        data={events}
        columns={allColumns}
        total={total}
        offset={offset}
        limit={limit}
        onPageChange={setOffset}
        onRowClick={setSelectedEvent}
        isLoading={isLoading}
        selectedIds={selectedIds}
        onSelectionChange={setSelectedIds}
        sortField={sortField}
        sortDir={sortDir}
        onSortChange={handleSortChange}
        sortableColumns={SORTABLE_COLUMNS}
      />

      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onMarkFinding={() => { setFindingEvent(selectedEvent) }}
        />
      )}

      {findingEvent && (
        <FindingDialog
          currentFinding={findingEvent.finding}
          currentNote={findingEvent.finding_note}
          onSave={handleSaveFinding}
          onClose={() => setFindingEvent(null)}
        />
      )}
    </div>
  )
}

export default function Logons() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const [selectedUser, setSelectedUser] = useState<LogonUserSummary | null>(null)
  const [searchInput, setSearchInput] = useState('')
  const [showMachineAccounts, setShowMachineAccounts] = useState(false)

  const { data: users, isLoading } = useQuery<LogonUserSummary[]>({
    queryKey: ['logon-users', siteId, uploadId],
    queryFn: () => api.getLogonUsers(siteId!, uploadId),
  })

  if (selectedUser) {
    return <UserLogonDetail user={selectedUser} onBack={() => setSelectedUser(null)} />
  }

  return (
    <UserSummaryList
      users={users || []}
      isLoading={isLoading}
      searchInput={searchInput}
      setSearchInput={setSearchInput}
      showMachineAccounts={showMachineAccounts}
      setShowMachineAccounts={setShowMachineAccounts}
      onSelectUser={setSelectedUser}
    />
  )
}
