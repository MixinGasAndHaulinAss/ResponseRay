import { useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, AlertOctagon, CheckCircle, Upload, FileUp,
  Shield, Activity, Clock
} from 'lucide-react'
import { api, type DashboardStats, type Upload as UploadType } from '../lib/api'
import { formatNumber, EVENT_TYPE_LABELS, formatDateTimeShort } from '../lib/utils'

export default function Dashboard() {
  const { siteId } = useParams<{ siteId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)

  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ['dashboard', siteId],
    queryFn: () => api.getDashboard(siteId!),
    refetchInterval: 10000,
  })

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !siteId) return

    try {
      setUploadProgress(0)
      await api.uploadFile(siteId, file, setUploadProgress)
      setUploadProgress(null)
      queryClient.invalidateQueries({ queryKey: ['dashboard', siteId] })
    } catch (err) {
      setUploadProgress(null)
      alert('Upload failed: ' + (err as Error).message)
    }
    if (fileRef.current) fileRef.current.value = ''
  }

  if (isLoading || !stats) return <div className="text-gray-500">Loading dashboard...</div>

  const sortedTypes = Object.entries(stats.event_counts).sort((a, b) => b[1] - a[1])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Dashboard</h1>
        <div className="flex items-center gap-3">
          {uploadProgress !== null && (
            <div className="flex items-center gap-2 text-sm text-brand-400">
              <FileUp className="w-4 h-4 animate-pulse" />
              Uploading {uploadProgress}%
            </div>
          )}
          <label className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-500 text-sm font-medium cursor-pointer">
            <Upload className="w-4 h-4" />
            Upload Capture
            <input ref={fileRef} type="file" accept=".json.gz,.gz" onChange={handleUpload} className="hidden" />
          </label>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Total Events" value={formatNumber(stats.total_events)} color="text-brand-400" />
        <StatCard
          icon={AlertOctagon}
          label="Notable (CT)"
          value={formatNumber(stats.notable_count)}
          color="text-purple-400"
          onClick={() => navigate(`/sites/${siteId}/findings?filter=notable`)}
        />
        <StatCard
          icon={AlertTriangle}
          label="Suspicious"
          value={formatNumber(stats.suspicious_count)}
          color="text-amber-400"
          onClick={() => navigate(`/sites/${siteId}/findings?filter=suspicious`)}
        />
        <StatCard
          icon={Shield}
          label="Findings"
          value={formatNumber(
            (stats.finding_counts.bad || 0) +
            (stats.finding_counts.suspicious || 0) +
            (stats.finding_counts.good || 0)
          )}
          color="text-green-400"
          onClick={() => navigate(`/sites/${siteId}/findings?filter=all-findings`)}
        />
      </div>

      {/* Findings Breakdown */}
      {Object.keys(stats.finding_counts).length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase mb-3">Findings</h2>
          <div className="flex gap-6">
            {stats.finding_counts.bad != null && stats.finding_counts.bad > 0 && (
              <button
                onClick={() => navigate(`/sites/${siteId}/findings?filter=bad`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-sm text-gray-300">Bad: {formatNumber(stats.finding_counts.bad)}</span>
              </button>
            )}
            {stats.finding_counts.suspicious != null && stats.finding_counts.suspicious > 0 && (
              <button
                onClick={() => navigate(`/sites/${siteId}/findings?filter=finding-suspicious`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-amber-500" />
                <span className="text-sm text-gray-300">Suspicious: {formatNumber(stats.finding_counts.suspicious)}</span>
              </button>
            )}
            {stats.finding_counts.good != null && stats.finding_counts.good > 0 && (
              <button
                onClick={() => navigate(`/sites/${siteId}/findings?filter=good`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-sm text-gray-300">Good: {formatNumber(stats.finding_counts.good)}</span>
              </button>
            )}
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 gap-6">
        {/* Event Type Breakdown */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase mb-3">Event Types</h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {sortedTypes.map(([type, count]) => (
              <div key={type} className="flex items-center justify-between text-sm">
                <span className="text-gray-300 truncate mr-4">{EVENT_TYPE_LABELS[type] || type}</span>
                <span className="text-gray-500 font-mono text-xs">{formatNumber(count)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Uploads */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase mb-3">Uploads</h2>
          {stats.uploads.length === 0 ? (
            <p className="text-gray-500 text-sm">No uploads yet</p>
          ) : (
            <div className="space-y-3">
              {stats.uploads.map((u) => (
                <UploadCard key={u.id} upload={u} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ icon: Icon, label, value, color, onClick }: {
  icon: typeof Activity; label: string; value: string; color: string; onClick?: () => void
}) {
  const Wrapper = onClick ? 'button' : 'div'
  return (
    <Wrapper
      onClick={onClick}
      className={`bg-gray-900 border border-gray-800 rounded-lg p-4 text-left w-full ${
        onClick ? 'cursor-pointer hover:border-gray-600 hover:bg-gray-800/80 transition-colors' : ''
      }`}
    >
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`w-4 h-4 ${color}`} />
        <span className="text-xs font-medium text-gray-500 uppercase">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
    </Wrapper>
  )
}

function UploadCard({ upload }: { upload: UploadType }) {
  const statusColors: Record<string, string> = {
    pending: 'text-yellow-400',
    processing: 'text-blue-400',
    complete: 'text-green-400',
    error: 'text-red-400',
  }

  return (
    <div className="bg-gray-800/50 rounded-md p-3">
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-200 font-medium truncate">{upload.filename}</span>
        <span className={`text-xs font-medium capitalize ${statusColors[upload.status] || 'text-gray-400'}`}>
          {upload.status}
        </span>
      </div>
      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
        {upload.host_name && <span>{upload.host_name}</span>}
        {upload.event_count > 0 && <span>{formatNumber(upload.event_count)} events</span>}
        <span>{formatDateTimeShort(upload.created_at)}</span>
      </div>
      {upload.error_msg && (
        <p className="mt-1 text-xs text-red-400">{upload.error_msg}</p>
      )}
    </div>
  )
}
