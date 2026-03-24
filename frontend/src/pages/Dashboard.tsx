import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle, AlertOctagon, CheckCircle, Shield, Activity
} from 'lucide-react'
import { api, type DashboardStats } from '../lib/api'
import { formatNumber, EVENT_TYPE_LABELS } from '../lib/utils'

export default function Dashboard() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const navigate = useNavigate()

  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ['dashboard', siteId, uploadId],
    queryFn: () => api.getDashboard(siteId!, uploadId),
    refetchInterval: 10000,
  })

  if (isLoading || !stats) return <div className="text-gray-500">Loading dashboard...</div>

  const sortedTypes = Object.entries(stats.event_counts).sort((a, b) => b[1] - a[1])
  const basePath = `/sites/${siteId}/captures/${uploadId}`

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-foreground">Dashboard</h1>
        <span className="text-xs text-foreground font-mono">v{__APP_VERSION__}</span>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={Activity} label="Total Events" value={formatNumber(stats.total_events)} color="text-brand-400" />
        <StatCard
          icon={AlertOctagon}
          label="Notable (CT)"
          value={formatNumber(stats.notable_count)}
          color="text-purple-400"
          onClick={() => navigate(`${basePath}/findings?filter=notable`)}
        />
        <StatCard
          icon={AlertTriangle}
          label="Suspicious"
          value={formatNumber(stats.suspicious_count)}
          color="text-amber-400"
          onClick={() => navigate(`${basePath}/findings?filter=suspicious`)}
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
          onClick={() => navigate(`${basePath}/findings?filter=all-findings`)}
        />
      </div>

      {/* Findings Breakdown */}
      {Object.keys(stats.finding_counts).length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-gray-400 uppercase mb-3">Findings</h2>
          <div className="flex gap-6">
            {stats.finding_counts.bad != null && stats.finding_counts.bad > 0 && (
              <button
                onClick={() => navigate(`${basePath}/findings?filter=bad`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-red-500" />
                <span className="text-sm text-gray-300">Bad: {formatNumber(stats.finding_counts.bad)}</span>
              </button>
            )}
            {stats.finding_counts.suspicious != null && stats.finding_counts.suspicious > 0 && (
              <button
                onClick={() => navigate(`${basePath}/findings?filter=finding-suspicious`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-amber-500" />
                <span className="text-sm text-gray-300">Suspicious: {formatNumber(stats.finding_counts.suspicious)}</span>
              </button>
            )}
            {stats.finding_counts.good != null && stats.finding_counts.good > 0 && (
              <button
                onClick={() => navigate(`${basePath}/findings?filter=good`)}
                className="flex items-center gap-2 hover:opacity-80 transition-opacity"
              >
                <span className="w-3 h-3 rounded-full bg-green-500" />
                <span className="text-sm text-gray-300">Good: {formatNumber(stats.finding_counts.good)}</span>
              </button>
            )}
          </div>
        </div>
      )}

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
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </Wrapper>
  )
}
