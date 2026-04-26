import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, FolderOpen, Key, Sun, Moon, Download, Apple, Server, Terminal, Monitor, AlertCircle, Loader2 } from 'lucide-react'
import { api, type SiteWithCounts, type CollectorInfo } from '../lib/api'
import { formatNumber, formatDateTimeShort, formatBytes } from '../lib/utils'
import { useTheme } from '../hooks/useTheme'

const COLLECTOR_ICON: Record<string, typeof Monitor> = {
  windows: Monitor,
  linux: Terminal,
  macos: Apple,
  esxi: Server,
}

const COLLECTOR_FALLBACK: CollectorInfo[] = [
  { platform: 'windows', display_name: 'Windows Collector', filename: 'ResponseRayCollector.exe', description: 'VSS-aware live triage covering 300+ Windows artifacts (registry, EVTX, prefetch, USN, MFT, browsers).', architecture: 'x64', available: false, error: 'Loading…' },
  { platform: 'linux', display_name: 'Linux Collector', filename: 'responseray-collector-linux', description: 'Static Go binary. journald, packages, persistence, Docker, auditd.', architecture: 'amd64', available: false, error: 'Loading…' },
  { platform: 'macos', display_name: 'macOS Collector', filename: 'responseray-collector-macos', description: 'Unified logs, launchd/btm, TCC, KnowledgeC, FSEvents, browsers.', architecture: 'amd64', available: false, error: 'Loading…' },
  { platform: 'esxi', display_name: 'ESXi Collector', filename: 'responseray-collector-esxi.sh', description: 'POSIX shell script using esxcli/vim-cmd. Host config + VM metadata.', architecture: 'POSIX sh', available: false, error: 'Loading…' },
]

export default function Sites() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const { isDark, toggle: toggleTheme } = useTheme()

  const { data: sites = [], isLoading } = useQuery({
    queryKey: ['sites'],
    queryFn: api.listSites,
  })

  const createMutation = useMutation({
    mutationFn: () => api.createSite({ name, description }),
    onSuccess: (site) => {
      queryClient.invalidateQueries({ queryKey: ['sites'] })
      setShowCreate(false)
      setName('')
      setDescription('')
      navigate(`/sites/${site.id}`)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteSite(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sites'] }),
  })

  const { data: collectors } = useQuery({
    queryKey: ['collectors'],
    queryFn: api.listCollectors,
    staleTime: 5 * 60 * 1000,
  })

  const [collectorsOpen, setCollectorsOpen] = useState(false)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  const handleDownload = async (platform: string) => {
    setDownloadError(null)
    setDownloading(platform)
    try {
      await api.downloadCollector(platform)
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : String(e))
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <div className="max-w-4xl mx-auto py-12 px-6">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-brand-500" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">ResponseRay</h1>
              <p className="text-sm text-gray-400">DFIR Investigation Platform <span className="text-foreground">v{__APP_VERSION__}</span></p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              className="p-2 text-gray-400 hover:text-foreground transition-colors rounded-lg hover:bg-gray-800"
              title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
            <button
              onClick={() => setCollectorsOpen((v) => !v)}
              className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 hover:text-foreground text-sm font-medium border border-gray-700"
            >
              <Download className="w-4 h-4" />
              Collectors
            </button>
            <button
              onClick={() => navigate('/api-keys')}
              className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700 hover:text-foreground text-sm font-medium border border-gray-700"
            >
              <Key className="w-4 h-4" />
              API Keys
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-500 text-sm font-medium"
            >
              <Plus className="w-4 h-4" />
              New Incident
            </button>
          </div>
        </div>

        {collectorsOpen && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-lg font-semibold text-foreground">Download Collectors</h2>
                <p className="text-xs text-gray-400 mt-1">
                  Run the appropriate collector on the target host as administrator/root, then upload the resulting archive into an incident below.
                </p>
              </div>
              <button
                onClick={() => setCollectorsOpen(false)}
                className="text-xs text-gray-500 hover:text-foreground"
              >
                Hide
              </button>
            </div>

            {downloadError && (
              <div className="flex items-start gap-2 bg-red-900/30 border border-red-800/60 text-red-300 text-xs rounded-md px-3 py-2 mb-3">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{downloadError}</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {(collectors ?? COLLECTOR_FALLBACK).map((c) => {
                const Icon = COLLECTOR_ICON[c.platform] ?? Server
                const isLoading = downloading === c.platform
                return (
                  <div
                    key={c.platform}
                    className="bg-gray-950 border border-gray-800 rounded-md p-4 flex flex-col"
                  >
                    <div className="flex items-start gap-3 mb-3">
                      <div className="p-2 rounded-md bg-gray-800 text-brand-400 shrink-0">
                        <Icon className="w-5 h-5" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="text-sm font-semibold text-foreground">{c.display_name}</h3>
                          <span className="text-[10px] uppercase tracking-wide text-gray-500 bg-gray-800/80 px-1.5 py-0.5 rounded">
                            {c.architecture}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 mt-1">{c.description}</p>
                      </div>
                    </div>

                    <div className="text-[11px] text-gray-500 mb-3 font-mono truncate">
                      {c.filename}
                      {c.available && c.size != null && (
                        <span className="ml-2 text-gray-600">{formatBytes(c.size)}</span>
                      )}
                    </div>

                    <button
                      onClick={() => handleDownload(c.platform)}
                      disabled={!c.available || isLoading}
                      className="mt-auto flex items-center justify-center gap-2 px-3 py-2 text-sm rounded-md bg-brand-600 text-white hover:bg-brand-500 disabled:bg-gray-800 disabled:text-gray-500 disabled:cursor-not-allowed transition-colors"
                      title={!c.available ? (c.error || 'Not bundled with this deployment') : undefined}
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          Downloading…
                        </>
                      ) : c.available ? (
                        <>
                          <Download className="w-4 h-4" />
                          Download
                        </>
                      ) : (
                        <>
                          <AlertCircle className="w-4 h-4" />
                          Unavailable
                        </>
                      )}
                    </button>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {showCreate && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Create Incident</h2>
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate() }} className="space-y-3">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Incident name (e.g., Workstation-042 Compromise)"
                autoFocus
                required
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-md text-foreground placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Description (optional)"
                rows={2}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-md text-foreground placeholder-gray-500 resize-none focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <div className="flex gap-2">
                <button type="submit" className="px-4 py-2 bg-brand-600 text-white rounded-md hover:bg-brand-500 text-sm">
                  Create
                </button>
                <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 text-gray-400 hover:text-foreground text-sm">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {isLoading ? (
          <div className="text-center text-gray-500 py-12">Loading...</div>
        ) : sites.length === 0 ? (
          <div className="text-center text-gray-500 py-12">
            <FolderOpen className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No incidents yet. Create one to get started.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {sites.map((site) => (
              <div
                key={site.id}
                onClick={() => navigate(`/sites/${site.id}`)}
                className="bg-gray-900 border border-gray-800 rounded-lg p-5 hover:border-gray-700 cursor-pointer transition-colors group"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-foreground group-hover:text-brand-400 transition-colors">
                      {site.name}
                    </h3>
                    {site.description && (
                      <p className="text-sm text-gray-400 mt-1">{site.description}</p>
                    )}
                    <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
                      <span>{site.upload_count} upload{site.upload_count !== 1 ? 's' : ''}</span>
                      <span>{formatNumber(site.event_count)} events</span>
                      <span>Created {formatDateTimeShort(site.created_at)}</span>
                    </div>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      if (confirm(`Delete incident "${site.name}"? This cannot be undone.`)) {
                        deleteMutation.mutate(site.id)
                      }
                    }}
                    className="p-2 text-gray-600 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
