import { useState, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Upload, FileUp, HardDrive, Clock, AlertCircle,
  CheckCircle2, Loader2, ChevronRight
} from 'lucide-react'
import { api, type Upload as UploadType } from '../lib/api'
import { formatNumber, formatDateTimeShort } from '../lib/utils'

const statusConfig: Record<string, { icon: typeof CheckCircle2; color: string; bg: string }> = {
  complete:   { icon: CheckCircle2, color: 'text-green-400', bg: 'bg-green-500/10' },
  processing: { icon: Loader2, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  pending:    { icon: Clock, color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
  chunking:   { icon: Loader2, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  error:      { icon: AlertCircle, color: 'text-red-400', bg: 'bg-red-500/10' },
}

export default function Captures() {
  const { siteId } = useParams<{ siteId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)

  const { data: uploads, isLoading } = useQuery({
    queryKey: ['uploads', siteId],
    queryFn: () => api.listUploads(siteId!),
    refetchInterval: 5000,
  })

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !siteId) return

    try {
      setUploadProgress(0)
      await api.uploadFile(siteId, file, setUploadProgress)
      setUploadProgress(null)
      queryClient.invalidateQueries({ queryKey: ['uploads', siteId] })
    } catch (err) {
      setUploadProgress(null)
      alert('Upload failed: ' + (err as Error).message)
    }
    if (fileRef.current) fileRef.current.value = ''
  }

  const handleSelect = (upload: UploadType) => {
    if (upload.status === 'complete') {
      navigate(`/sites/${siteId}/captures/${upload.id}/dashboard`)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-foreground">Captures</h1>
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

      {isLoading ? (
        <div className="text-center py-16 text-gray-500">Loading captures...</div>
      ) : !uploads || uploads.length === 0 ? (
        <div className="text-center py-16">
          <HardDrive className="w-12 h-12 mx-auto mb-3 text-gray-600" />
          <p className="text-gray-400 mb-2">No captures uploaded yet</p>
          <p className="text-sm text-gray-500">Upload a CyberTriage capture file to get started</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {uploads.map(upload => {
            const cfg = statusConfig[upload.status] || statusConfig.pending
            const StatusIcon = cfg.icon
            const isReady = upload.status === 'complete'

            return (
              <button
                key={upload.id}
                onClick={() => handleSelect(upload)}
                disabled={!isReady}
                className={`w-full text-left border rounded-lg p-5 transition-colors ${
                  isReady
                    ? 'bg-gray-900 border-gray-800 hover:border-gray-600 hover:bg-gray-800/80 cursor-pointer'
                    : 'bg-gray-900/50 border-gray-800/50 cursor-default opacity-75'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4 min-w-0">
                    <div className={`p-3 rounded-lg ${cfg.bg}`}>
                      <HardDrive className={`w-6 h-6 ${cfg.color}`} />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-base font-semibold text-foreground truncate">
                        {upload.filename}
                      </h3>
                      <div className="flex items-center gap-4 mt-1 text-sm text-gray-400">
                        <span className={`flex items-center gap-1.5 ${cfg.color}`}>
                          <StatusIcon className={`w-3.5 h-3.5 ${upload.status === 'processing' || upload.status === 'chunking' ? 'animate-spin' : ''}`} />
                          <span className="capitalize">{upload.status}</span>
                        </span>
                        {upload.host_name && (
                          <span>{upload.host_name}</span>
                        )}
                        {upload.event_count > 0 && (
                          <span>{formatNumber(upload.event_count)} events</span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatDateTimeShort(upload.created_at)}
                        </span>
                      </div>
                      {upload.error_msg && (
                        <p className="mt-1 text-xs text-red-400">{upload.error_msg}</p>
                      )}
                    </div>
                  </div>
                  {isReady && (
                    <ChevronRight className="w-5 h-5 text-gray-500 shrink-0" />
                  )}
                </div>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
