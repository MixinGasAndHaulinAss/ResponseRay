import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Folder, File, ChevronRight, AlertTriangle, Flag, Search } from 'lucide-react'
import { useEvents } from '../hooks/useEvents'
import { api, type Event } from '../lib/api'
import { formatDateTime, formatNumber } from '../lib/utils'
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
  { id: 'name', header: 'Name', cell: ({ row }: any) => {
    const d = row.original.data
    const isDir = d.meta_type === 'Dir'
    return (
      <div className="flex items-center gap-1.5">
        {isDir ? <Folder className="w-3.5 h-3.5 text-brand-400" /> : <File className="w-3.5 h-3.5 text-gray-500" />}
        <span>{d.file_name || '-'}</span>
      </div>
    )
  }},
  { id: 'path', header: 'Path', cell: ({ row }: any) => <span className="max-w-md truncate block">{row.original.data.file_path || '-'}</span> },
  { id: 'size', header: 'Size', cell: ({ row }: any) => {
    const s = row.original.data.file_size
    if (!s || row.original.data.meta_type === 'Dir') return '-'
    return s > 1048576 ? `${(s / 1048576).toFixed(1)} MB` : `${Math.round(s / 1024)} KB`
  }},
  { id: 'type', header: 'MIME', cell: ({ row }: any) => row.original.data.file_mime_type || '-' },
  { id: 'ts_desc', header: 'Timestamp Type', cell: ({ row }: any) => row.original.timestamp_desc || '-' },
  { id: 'hashes', header: 'Hashes', cell: ({ row }: any) => {
    const d = row.original.data
    if (d.md5) return <span className="font-mono text-xs" title={`MD5: ${d.md5}\nSHA256: ${d.sha256 || 'n/a'}`}>{d.md5?.substring(0, 12)}...</span>
    return '-'
  }},
  { id: 'deleted', header: 'Deleted', cell: ({ row }: any) => row.original.data.is_deleted ? <span className="text-red-400">Yes</span> : '-' },
  { id: 'timestomp', header: 'Timestomp', cell: ({ row }: any) => row.original.data.timestompNote ? <AlertTriangle className="w-3.5 h-3.5 text-amber-400" /> : null },
  { id: 'actions', header: '', size: 40, cell: () => null },
]

export default function FileSystem() {
  const { siteId } = useParams<{ siteId: string }>()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [selectedEvent, setSelectedEvent] = useState<Event | null>(null)
  const [findingEvent, setFindingEvent] = useState<Event | null>(null)

  const { events, total, offset, setOffset, limit, isLoading } = useEvents({
    siteId: siteId!,
    eventTypes: ['file_timeline', 'file_timeline_fn'],
    search,
    limit: 100,
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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">File System</h1>
        <form onSubmit={handleSearch} className="flex items-center gap-1">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search files, hashes..."
              className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 w-72 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
          </div>
        </form>
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
