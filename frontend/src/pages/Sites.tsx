import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Shield, Plus, Trash2, FolderOpen } from 'lucide-react'
import { api, type SiteWithCounts } from '../lib/api'
import { formatNumber, formatDateTimeShort } from '../lib/utils'

export default function Sites() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

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

  return (
    <div className="min-h-screen bg-gray-950">
      <div className="max-w-4xl mx-auto py-12 px-6">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-brand-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">ResponseRay</h1>
              <p className="text-sm text-gray-400">DFIR Investigation Platform <span className="text-gray-600">v{__APP_VERSION__}</span></p>
            </div>
          </div>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-500 text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            New Incident
          </button>
        </div>

        {showCreate && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
            <h2 className="text-lg font-semibold text-white mb-4">Create Incident</h2>
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate() }} className="space-y-3">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Incident name (e.g., Workstation-042 Compromise)"
                autoFocus
                required
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Description (optional)"
                rows={2}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-500 resize-none focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <div className="flex gap-2">
                <button type="submit" className="px-4 py-2 bg-brand-600 text-white rounded-md hover:bg-brand-500 text-sm">
                  Create
                </button>
                <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 text-gray-400 hover:text-white text-sm">
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
                    <h3 className="text-lg font-semibold text-white group-hover:text-brand-400 transition-colors">
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
