import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Search, Hash, Globe, User } from 'lucide-react'
import { useEvents } from '../hooks/useEvents'
import { api, type Event } from '../lib/api'
import { formatDateTime, EVENT_TYPE_LABELS, cn } from '../lib/utils'
import DataTable from '../components/tables/DataTable'
import FindingBadge from '../components/findings/FindingBadge'
import FindingDialog from '../components/findings/FindingDialog'
import EventDetailPanel from '../components/EventDetailPanel'

const columns = [
  {
    id: 'indicators', header: '', size: 60,
    cell: ({ row }: any) => <FindingBadge finding={row.original.finding} isSuspicious={row.original.is_suspicious} ctSignificance={row.original.ct_significance} small />,
  },
  { id: 'datetime', header: 'Timestamp', cell: ({ row }: any) => <span className="text-xs font-mono">{formatDateTime(row.original.datetime)}</span> },
  { id: 'event_type', header: 'Type', cell: ({ row }: any) => (
    <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">
      {EVENT_TYPE_LABELS[row.original.event_type] || row.original.event_type}
    </span>
  )},
  { id: 'source', header: 'Source', cell: ({ row }: any) => row.original.source_short || '-' },
  { id: 'message', header: 'Message', cell: ({ row }: any) => (
    <span className="max-w-2xl truncate block">{row.original.message || '-'}</span>
  )},
]

export default function SearchPage() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const queryClient = useQueryClient()
  const [query, setQuery] = useState('')
  const [activeQuery, setActiveQuery] = useState('')
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [findingEvent, setFindingEvent] = useState<Event | null>(null)
  const [findingFilter, setFindingFilter] = useState('')

  const { events, total, offset, setOffset, limit, isLoading } = useEvents({
    siteId: siteId!,
    uploadId,
    search: activeQuery,
    finding: findingFilter,
    enabled: activeQuery.length > 0,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setActiveQuery(query)
    setOffset(0)
  }

  const handleSaveFinding = async (finding: string | null, note: string | null) => {
    if (!siteId || !findingEvent) return
    await api.updateFinding(siteId, findingEvent.id, { finding, finding_note: note })
    queryClient.invalidateQueries({ queryKey: ['events'] })
    setFindingEvent(null)
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">Search</h1>

      <form onSubmit={handleSearch} className="flex items-center gap-2">
        <div className="relative flex-1 max-w-2xl">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search messages, IPs, hashes, users, file paths..."
            autoFocus
            className="w-full pl-10 pr-4 py-2.5 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
        </div>
        <button type="submit" className="px-6 py-2.5 bg-brand-600 text-white rounded-lg hover:bg-brand-500 font-medium">
          Search
        </button>
      </form>

      <div className="flex items-center gap-2 text-sm">
        <span className="text-gray-500">Filter:</span>
        {['', 'bad', 'suspicious', 'good', 'none'].map((f) => (
          <button
            key={f}
            onClick={() => { setFindingFilter(f); setOffset(0) }}
            className={cn(
              'px-2.5 py-1 rounded text-xs font-medium transition-colors',
              findingFilter === f
                ? 'bg-brand-500/20 text-brand-400'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            )}
          >
            {f === '' ? 'All' : f === 'none' ? 'Unmarked' : f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {activeQuery && (
        <DataTable
          data={events}
          columns={columns}
          total={total}
          offset={offset}
          limit={limit}
          onPageChange={setOffset}
          onRowClick={setSelectedEvent}
          isLoading={isLoading}
        />
      )}

      {!activeQuery && (
        <div className="text-center text-gray-500 py-16">
          <Search className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p>Enter a search query to find events across all data</p>
          <div className="flex justify-center gap-6 mt-4 text-xs text-gray-600">
            <span className="flex items-center gap-1"><Hash className="w-3 h-3" /> MD5 / SHA256 hashes</span>
            <span className="flex items-center gap-1"><Globe className="w-3 h-3" /> IP addresses</span>
            <span className="flex items-center gap-1"><User className="w-3 h-3" /> Usernames</span>
          </div>
        </div>
      )}

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
