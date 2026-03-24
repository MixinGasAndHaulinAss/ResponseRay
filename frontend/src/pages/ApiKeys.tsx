import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Plus, Trash2, Copy, Check, ArrowLeft } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api, type ApiKey } from '../lib/api'
import { formatDateTimeShort } from '../lib/utils'

export default function ApiKeys() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [name, setName] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys = [], isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: api.listApiKeys,
  })

  const createMutation = useMutation({
    mutationFn: () => api.createApiKey(name),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
      setNewKey(data.key)
      setName('')
      setShowCreate(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteApiKey(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const copyKey = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <div className="max-w-4xl mx-auto py-12 px-6">
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/')}
              className="p-1.5 text-gray-400 hover:text-white transition-colors"
              title="Back to incidents"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <Key className="w-7 h-7 text-brand-500" />
            <div>
              <h1 className="text-2xl font-bold text-white">API Keys</h1>
              <p className="text-sm text-gray-400">Manage keys for external API access</p>
            </div>
          </div>
          <button
            onClick={() => { setShowCreate(true); setNewKey(null) }}
            className="flex items-center gap-2 px-4 py-2 bg-brand-600 text-white rounded-lg hover:bg-brand-500 text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            Create Key
          </button>
        </div>

        {/* New key reveal */}
        {newKey && (
          <div className="bg-green-900/30 border border-green-700 rounded-lg p-5 mb-6">
            <h3 className="text-sm font-semibold text-green-400 mb-2">API Key Created</h3>
            <p className="text-xs text-green-300/70 mb-3">
              Copy this key now. It will not be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-white font-mono break-all select-all">
                {newKey}
              </code>
              <button
                onClick={copyKey}
                className="shrink-0 px-3 py-2 bg-gray-800 border border-gray-700 rounded hover:bg-gray-700 transition-colors"
                title="Copy to clipboard"
              >
                {copied
                  ? <Check className="w-4 h-4 text-green-400" />
                  : <Copy className="w-4 h-4 text-gray-400" />
                }
              </button>
            </div>
          </div>
        )}

        {/* Create form */}
        {showCreate && (
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
            <h2 className="text-lg font-semibold text-white mb-4">Create API Key</h2>
            <form onSubmit={(e) => { e.preventDefault(); createMutation.mutate() }} className="space-y-3">
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Key name (e.g., SOAR Integration, Export Script)"
                autoFocus
                required
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded-md text-white placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
              />
              <div className="flex gap-2">
                <button type="submit" disabled={createMutation.isPending} className="px-4 py-2 bg-brand-600 text-white rounded-md hover:bg-brand-500 text-sm">
                  {createMutation.isPending ? 'Creating...' : 'Create'}
                </button>
                <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 text-gray-400 hover:text-white text-sm">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Keys list */}
        {isLoading ? (
          <div className="text-center text-gray-500 py-12">Loading...</div>
        ) : keys.length === 0 ? (
          <div className="text-center text-gray-500 py-12">
            <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No API keys yet. Create one for external access.</p>
          </div>
        ) : (
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <div className="grid grid-cols-[1fr_140px_160px_160px_50px] gap-2 px-4 py-2 bg-gray-800/50 border-b border-gray-800 text-xs font-medium text-gray-500 uppercase">
              <span>Name</span>
              <span>Key Prefix</span>
              <span>Created</span>
              <span>Last Used</span>
              <span />
            </div>
            {keys.map((k: ApiKey) => (
              <div
                key={k.id}
                className="grid grid-cols-[1fr_140px_160px_160px_50px] gap-2 px-4 py-3 border-b border-gray-800/50 items-center group"
              >
                <span className="text-sm text-white truncate">{k.name}</span>
                <span className="text-sm text-gray-400 font-mono">{k.prefix}...</span>
                <span className="text-xs text-gray-500">{formatDateTimeShort(k.created_at)}</span>
                <span className="text-xs text-gray-500">
                  {k.last_used ? formatDateTimeShort(k.last_used) : 'Never'}
                </span>
                <button
                  onClick={() => {
                    if (confirm(`Delete API key "${k.name}"? Any integrations using it will stop working.`)) {
                      deleteMutation.mutate(k.id)
                    }
                  }}
                  className="p-1.5 text-gray-600 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                  title="Delete key"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        {/* Usage hint */}
        <div className="mt-8 bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-3">Usage</h3>
          <div className="space-y-2 text-sm text-gray-400">
            <p>Include your API key in the <code className="text-gray-300 bg-gray-800 px-1.5 py-0.5 rounded text-xs">X-API-Key</code> header:</p>
            <pre className="bg-gray-800 rounded p-3 text-xs text-gray-300 overflow-x-auto">
{`curl -H "X-API-Key: rr_your_key_here" \\
  https://your-server/api/sites/`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}
