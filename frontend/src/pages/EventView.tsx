import { useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { type ColumnDef } from '@tanstack/react-table'
import { Flag, Search } from 'lucide-react'
import { api, type Event } from '../lib/api'
import { useEvents } from '../hooks/useEvents'
import DataTable from '../components/tables/DataTable'
import FindingBadge from '../components/findings/FindingBadge'
import FindingDialog from '../components/findings/FindingDialog'
import EventDetailPanel from '../components/EventDetailPanel'
import { formatDateTime, cn } from '../lib/utils'

interface EventViewProps {
  title: string
  eventTypes: string[]
  columns: ColumnDef<Event, unknown>[]
  tabs?: { key: string; label: string; eventTypes?: string[]; channel?: string; dataFilter?: Record<string, string> }[]
  defaultSort?: string
  defaultDir?: string
}

const SORTABLE_COLUMNS = new Set(['datetime'])

export default function EventView({ title, eventTypes, columns, tabs, defaultSort, defaultDir }: EventViewProps) {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [activeTab, setActiveTab] = useState(0)
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [findingEvent, setFindingEvent] = useState<Event | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())
  const [sortField, setSortField] = useState(defaultSort || 'datetime')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>((defaultDir as 'asc' | 'desc') || 'desc')

  const handleSortChange = (field: string) => {
    if (sortField === field) {
      setSortDir(prev => prev === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDir('desc')
    }
    setOffset(0)
  }

  const currentTab = tabs?.[activeTab]
  const activeEventTypes = currentTab?.eventTypes || eventTypes
  const activeChannel = currentTab?.channel
  const activeDataFilter = currentTab?.dataFilter

  const { events, total, offset, setOffset, limit, isLoading } = useEvents({
    siteId: siteId!,
    uploadId,
    eventTypes: activeEventTypes,
    search,
    channel: activeChannel,
    dataFilters: activeDataFilter,
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
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
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
    queryClient.invalidateQueries({ queryKey: ['dashboard'] })
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
    ...columns,
    {
      id: 'actions',
      header: '',
      size: 40,
      cell: ({ row }) => (
        <button
          onClick={(e) => { e.stopPropagation(); setFindingEvent(row.original) }}
          className="p-1 text-gray-600 hover:text-white"
          title="Mark Finding"
        >
          <Flag className="w-3.5 h-3.5" />
        </button>
      ),
    },
  ], [columns])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">{title}</h1>
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
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Search..."
                className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 w-64 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
            </div>
          </form>
        </div>
      </div>

      {tabs && (
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
      )}

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
          onMarkFinding={() => { setFindingEvent(selectedEvent); }}
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
