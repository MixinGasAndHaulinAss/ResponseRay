import { useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Flag, Search, Calendar, X } from 'lucide-react'
import { api, type Event } from '../lib/api'
import { useEvents } from '../hooks/useEvents'
import { useQueryContext } from '../context/QueryContext'
import QueryBar from '../components/QueryBar'
import FieldValue from '../components/FieldValue'
import DataTable from '../components/tables/DataTable'
import FindingBadge from '../components/findings/FindingBadge'
import FindingDialog from '../components/findings/FindingDialog'
import EventDetailPanel from '../components/EventDetailPanel'
import { formatDateTime, EVENT_TYPE_LABELS, cn } from '../lib/utils'

export default function Timeline() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const queryClient = useQueryClient()
  const { query: luceneQuery } = useQueryContext()
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [findingEvent, setFindingEvent] = useState<Event | null>(null)
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set())

  const [jumpDate, setJumpDate] = useState('')
  const [jumpTime, setJumpTime] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const { events, total, offset, setOffset, limit, isLoading } = useEvents({
    siteId: siteId!,
    uploadId,
    eventTypes: [],
    search,
    sortField: 'datetime',
    sortDir,
    dateFrom,
    dateTo,
    query: luceneQuery,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearch(searchInput)
    setOffset(0)
  }

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault()
    if (!jumpDate) return

    const time = jumpTime || '00:00'
    const from = `${jumpDate}T${time}:00Z`

    const [h, m] = time.split(':').map(Number)
    const endH = h + 1 > 23 ? 23 : h + 1
    const to = `${jumpDate}T${String(endH).padStart(2, '0')}:${String(m).padStart(2, '0')}:59Z`

    setDateFrom(from)
    setDateTo(to)
    setSortDir('asc')
    setOffset(0)
  }

  const clearDateFilter = () => {
    setDateFrom('')
    setDateTo('')
    setJumpDate('')
    setJumpTime('')
    setSortDir('desc')
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

  const columns = useMemo(() => [
    {
      id: 'indicators', header: '', size: 60,
      cell: ({ row }: any) => (
        <FindingBadge
          finding={row.original.finding}
          isSuspicious={row.original.is_suspicious}
          ctSignificance={row.original.ct_significance}
          small
        />
      ),
    },
    {
      id: 'datetime', header: 'Timestamp',
      cell: ({ row }: any) => (
        <FieldValue field="datetime" value={row.original.datetime}>
          <span className="text-xs font-mono">{formatDateTime(row.original.datetime)}</span>
        </FieldValue>
      ),
    },
    {
      id: 'event_type', header: 'Type',
      cell: ({ row }: any) => (
        <FieldValue field="event_type" value={row.original.event_type}>
          <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">
            {EVENT_TYPE_LABELS[row.original.event_type] || row.original.event_type}
          </span>
        </FieldValue>
      ),
    },
    {
      id: 'source', header: 'Source',
      cell: ({ row }: any) => {
        const v = row.original.source_short || ''
        return v ? <FieldValue field="source_short" value={v}>{v}</FieldValue> : '-'
      },
    },
    {
      id: 'ts_desc', header: 'Timestamp Type',
      cell: ({ row }: any) => {
        const v = row.original.timestamp_desc || ''
        return v ? <FieldValue field="timestamp_desc" value={v}>{v}</FieldValue> : '-'
      },
    },
    {
      id: 'message', header: 'Message',
      cell: ({ row }: any) => <span className="max-w-2xl truncate block">{row.original.message || '-'}</span>,
    },
    {
      id: 'host', header: 'Host',
      cell: ({ row }: any) => {
        const v = row.original.host_name || ''
        return v ? <FieldValue field="host_name" value={v}>{v}</FieldValue> : '-'
      },
    },
    {
      id: 'actions', header: '', size: 40,
      cell: ({ row }: any) => (
        <button
          onClick={(e: React.MouseEvent) => { e.stopPropagation(); setFindingEvent(row.original) }}
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
        <h1 className="text-xl font-bold text-foreground">Timeline</h1>
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
                className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-foreground placeholder-gray-500 w-48 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
            </div>
          </form>
        </div>
      </div>

      <QueryBar />

      {/* Jump to Date/Time */}
      <div className="flex items-center gap-3 bg-gray-900 border border-gray-800 rounded-lg px-4 py-3">
        <Calendar className="w-4 h-4 text-brand-400 shrink-0" />
        <form onSubmit={handleJump} className="flex items-center gap-2 flex-1">
          <label className="text-sm text-gray-400 shrink-0">Jump to:</label>
          <input
            type="date"
            value={jumpDate}
            onChange={(e) => setJumpDate(e.target.value)}
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500 dark:[color-scheme:dark]"
          />
          <input
            type="time"
            value={jumpTime}
            onChange={(e) => setJumpTime(e.target.value)}
            step="1"
            className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-md text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-brand-500 dark:[color-scheme:dark]"
          />
          <button
            type="submit"
            disabled={!jumpDate}
            className={cn(
              'px-4 py-1.5 text-sm font-medium rounded-md transition-colors',
              jumpDate
                ? 'bg-brand-600 text-white hover:bg-brand-500'
                : 'bg-gray-800 text-gray-500 cursor-not-allowed'
            )}
          >
            Go
          </button>
          {dateFrom && (
            <button
              type="button"
              onClick={clearDateFilter}
              className="flex items-center gap-1 px-3 py-1.5 text-sm text-gray-400 hover:text-foreground bg-gray-800 rounded-md"
            >
              <X className="w-3.5 h-3.5" />
              Clear
            </button>
          )}
        </form>
        {dateFrom && (
          <span className="text-xs text-brand-400 shrink-0">
            Showing: {new Date(dateFrom).toLocaleString()} &mdash; {new Date(dateTo).toLocaleString()}
          </span>
        )}
      </div>

      <DataTable
        data={events}
        columns={columns}
        total={total}
        offset={offset}
        limit={limit}
        onPageChange={setOffset}
        onRowClick={setSelectedEvent}
        isLoading={isLoading}
        selectedIds={selectedIds}
        onSelectionChange={setSelectedIds}
        sortField="datetime"
        sortDir={sortDir}
        onSortChange={() => { setSortDir(sortDir === 'asc' ? 'desc' : 'asc'); setOffset(0) }}
        sortableColumns={new Set(['datetime'])}
      />

      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onMarkFinding={() => setFindingEvent(selectedEvent)}
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
