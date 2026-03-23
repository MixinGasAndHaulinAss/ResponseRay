import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Radio, AlertTriangle, Shield, Eye, ChevronRight,
  ExternalLink, Clock
} from 'lucide-react'
import { api, type RemoteAccessTool } from '../lib/api'
import { formatDateTime, formatNumber, cn } from '../lib/utils'

const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  'Commercial RMM':        { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  'Open Source Remote':    { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  'Dual-Use / Suspicious': { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  'Legacy Remote':         { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
  'Tunneling':             { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  'VPN/Mesh':              { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  'Lateral Movement':      { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  'Built-in Remote':       { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
}

const CATEGORY_ICONS: Record<string, typeof Radio> = {
  'Commercial RMM': Radio,
  'Open Source Remote': Radio,
  'Dual-Use / Suspicious': AlertTriangle,
  'Legacy Remote': Radio,
  'Tunneling': ExternalLink,
  'VPN/Mesh': Shield,
  'Lateral Movement': AlertTriangle,
  'Built-in Remote': Eye,
}

export default function RemoteAccess() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const navigate = useNavigate()
  const [selectedTool, setSelectedTool] = useState<RemoteAccessTool | null>(null)
  const [filterCategory, setFilterCategory] = useState<string>('')

  const { data: tools, isLoading } = useQuery({
    queryKey: ['remote-access', siteId, uploadId],
    queryFn: () => api.detectRemoteAccess(siteId!, uploadId),
  })

  if (isLoading) return <div className="text-gray-500">Scanning for remote access software...</div>

  const detected = tools || []
  const categories = [...new Set(detected.map(t => t.category))]
  const filtered = filterCategory ? detected.filter(t => t.category === filterCategory) : detected

  const totalTools = detected.length
  const totalEvents = detected.reduce((sum, t) => sum + t.event_count, 0)
  const suspiciousCount = detected.filter(t =>
    t.category === 'Dual-Use / Suspicious' || t.category === 'Tunneling' || t.category === 'Lateral Movement'
  ).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Remote Access Software</h1>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-4 h-4 text-brand-400" />
            <span className="text-xs font-medium text-gray-500 uppercase">Tools Detected</span>
          </div>
          <p className="text-2xl font-bold text-white">{totalTools}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-1">
            <Eye className="w-4 h-4 text-blue-400" />
            <span className="text-xs font-medium text-gray-500 uppercase">Related Events</span>
          </div>
          <p className="text-2xl font-bold text-white">{formatNumber(totalEvents)}</p>
        </div>
        <div className={cn(
          "border rounded-lg p-4",
          suspiciousCount > 0
            ? "bg-amber-500/5 border-amber-500/30"
            : "bg-gray-900 border-gray-800"
        )}>
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className={cn("w-4 h-4", suspiciousCount > 0 ? "text-amber-400" : "text-gray-500")} />
            <span className="text-xs font-medium text-gray-500 uppercase">Suspicious / Tunneling</span>
          </div>
          <p className={cn("text-2xl font-bold", suspiciousCount > 0 ? "text-amber-400" : "text-white")}>{suspiciousCount}</p>
        </div>
      </div>

      {detected.length === 0 ? (
        <div className="text-center py-16">
          <Shield className="w-12 h-12 mx-auto mb-3 text-green-500 opacity-50" />
          <p className="text-gray-400">No remote access software detected in this dataset</p>
        </div>
      ) : (
        <>
          {/* Category Filter */}
          <div className="flex gap-1 border-b border-gray-800">
            <button
              onClick={() => setFilterCategory('')}
              className={cn(
                'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
                !filterCategory
                  ? 'border-brand-500 text-brand-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200'
              )}
            >
              All ({detected.length})
            </button>
            {categories.map(cat => {
              const colors = CATEGORY_COLORS[cat] || CATEGORY_COLORS['Legacy Remote']
              const count = detected.filter(t => t.category === cat).length
              return (
                <button
                  key={cat}
                  onClick={() => setFilterCategory(cat)}
                  className={cn(
                    'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
                    filterCategory === cat
                      ? `border-brand-500 ${colors.text}`
                      : 'border-transparent text-gray-400 hover:text-gray-200'
                  )}
                >
                  {cat} ({count})
                </button>
              )
            })}
          </div>

          {/* Tool Cards */}
          <div className="grid grid-cols-1 gap-3">
            {filtered.map(tool => {
              const colors = CATEGORY_COLORS[tool.category] || CATEGORY_COLORS['Legacy Remote']
              const Icon = CATEGORY_ICONS[tool.category] || Radio

              return (
                <div
                  key={tool.name}
                  className={cn(
                    'border rounded-lg p-4 cursor-pointer transition-colors hover:bg-gray-800/50',
                    selectedTool?.name === tool.name ? `${colors.bg} ${colors.border}` : 'bg-gray-900 border-gray-800'
                  )}
                  onClick={() => setSelectedTool(selectedTool?.name === tool.name ? null : tool)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={cn('p-2 rounded-lg', colors.bg)}>
                        <Icon className={cn('w-5 h-5', colors.text)} />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold text-white">{tool.name}</h3>
                        <span className={cn('text-xs', colors.text)}>{tool.category}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <p className="text-lg font-bold text-white">{formatNumber(tool.event_count)}</p>
                        <p className="text-xs text-gray-500">events</p>
                      </div>
                      <ChevronRight className={cn(
                        'w-5 h-5 text-gray-500 transition-transform',
                        selectedTool?.name === tool.name && 'rotate-90'
                      )} />
                    </div>
                  </div>

                  {selectedTool?.name === tool.name && (
                    <div className="mt-4 pt-4 border-t border-gray-800 space-y-3">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <span className="text-xs text-gray-500 uppercase">First Seen</span>
                          <p className="text-sm font-mono text-gray-300 mt-0.5 flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-gray-500" />
                            {tool.first_seen ? formatDateTime(tool.first_seen) : 'N/A'}
                          </p>
                        </div>
                        <div>
                          <span className="text-xs text-gray-500 uppercase">Last Seen</span>
                          <p className="text-sm font-mono text-gray-300 mt-0.5 flex items-center gap-1.5">
                            <Clock className="w-3.5 h-3.5 text-gray-500" />
                            {tool.last_seen ? formatDateTime(tool.last_seen) : 'N/A'}
                          </p>
                        </div>
                      </div>

                      <div>
                        <span className="text-xs text-gray-500 uppercase">Seen In Event Types</span>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {tool.event_types.map(et => (
                            <span key={et} className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-300">{et}</span>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="text-xs text-gray-500 uppercase">Matched Keywords</span>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {tool.search_terms.map(st => (
                            <span key={st} className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 font-mono">{st}</span>
                          ))}
                        </div>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          navigate(`/sites/${siteId}/captures/${uploadId}/search?q=${encodeURIComponent(tool.search_terms[0])}`)
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-brand-600 text-white rounded-md hover:bg-brand-500 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        View All Events
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
