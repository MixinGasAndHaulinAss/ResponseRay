import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Folder, File, ChevronRight, Home, AlertTriangle, Search,
  ArrowUp, Shield, Hash, Download
} from 'lucide-react'
import { api, type FilesystemEntry } from '../lib/api'
import { formatDateTimeShort } from '../lib/utils'

export default function FileSystem() {
  const { siteId, uploadId } = useParams<{ siteId: string; uploadId: string }>()
  const [currentPath, setCurrentPath] = useState('/')
  const [searchInput, setSearchInput] = useState('')
  const [searchFilter, setSearchFilter] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['filesystem', siteId, uploadId, currentPath],
    queryFn: () => api.listDirectory(siteId!, currentPath, uploadId),
    enabled: !!siteId,
  })

  const pathSegments = currentPath.split('/').filter(Boolean)

  const navigateTo = (path: string) => {
    setCurrentPath(path)
    setSearchFilter('')
    setSearchInput('')
  }

  const navigateUp = () => {
    if (currentPath === '/') return
    const parts = currentPath.split('/').filter(Boolean)
    parts.pop()
    navigateTo('/' + (parts.length ? parts.join('/') + '/' : ''))
  }

  const openFolder = (name: string) => {
    navigateTo(currentPath + name + '/')
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setSearchFilter(searchInput.toLowerCase())
  }

  const entries = data?.entries || []
  const dirs = entries.filter(e => e.is_dir)
  const files = entries.filter(e => !e.is_dir)

  const filteredDirs = searchFilter
    ? dirs.filter(d => d.name.toLowerCase().includes(searchFilter))
    : dirs
  const filteredFiles = searchFilter
    ? files.filter(f => f.name.toLowerCase().includes(searchFilter))
    : files

  const formatSize = (size?: number) => {
    if (!size) return '-'
    if (size > 1073741824) return `${(size / 1073741824).toFixed(1)} GB`
    if (size > 1048576) return `${(size / 1048576).toFixed(1)} MB`
    if (size > 1024) return `${(size / 1024).toFixed(1)} KB`
    return `${size} B`
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
              placeholder="Filter current directory..."
              className="pl-8 pr-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 w-72 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
          </div>
        </form>
      </div>

      {/* Breadcrumbs */}
      <div className="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-lg px-4 py-2.5 overflow-x-auto">
        <button
          onClick={() => navigateTo('/')}
          className="flex items-center gap-1 text-sm text-brand-400 hover:text-brand-300 shrink-0"
        >
          <Home className="w-4 h-4" />
          <span>Root</span>
        </button>
        {pathSegments.map((segment, i) => (
          <span key={i} className="flex items-center gap-1 shrink-0">
            <ChevronRight className="w-3.5 h-3.5 text-gray-600" />
            <button
              onClick={() => navigateTo('/' + pathSegments.slice(0, i + 1).join('/') + '/')}
              className={`text-sm ${i === pathSegments.length - 1 ? 'text-white font-medium' : 'text-brand-400 hover:text-brand-300'}`}
            >
              {segment}
            </button>
          </span>
        ))}
      </div>

      {isLoading ? (
        <div className="text-center text-gray-500 py-12">Loading directory...</div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[1fr_100px_160px_80px] gap-2 px-4 py-2 bg-gray-800/50 border-b border-gray-800 text-xs font-medium text-gray-500 uppercase">
            <span>Name</span>
            <span className="text-right">Size</span>
            <span className="text-right">Modified</span>
            <span className="text-center">Flags</span>
          </div>

          {/* Up directory */}
          {currentPath !== '/' && (
            <button
              onClick={navigateUp}
              className="w-full grid grid-cols-[1fr_100px_160px_80px] gap-2 px-4 py-2 hover:bg-gray-800/50 transition-colors border-b border-gray-800/50 text-left"
            >
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <ArrowUp className="w-4 h-4" />
                <span>..</span>
              </div>
              <span />
              <span />
              <span />
            </button>
          )}

          {/* Directories */}
          {filteredDirs.map((entry) => (
            <button
              key={'d-' + entry.name}
              onClick={() => openFolder(entry.name)}
              className="w-full grid grid-cols-[1fr_100px_160px_80px] gap-2 px-4 py-2 hover:bg-gray-800/50 transition-colors border-b border-gray-800/50 text-left group"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Folder className="w-4 h-4 text-brand-400 shrink-0" />
                <span className="text-sm text-gray-200 group-hover:text-brand-300 truncate">{entry.name}</span>
              </div>
              <span className="text-xs text-gray-500 text-right self-center">
                {entry.file_count ? `${entry.file_count} items` : ''}
              </span>
              <span />
              <span />
            </button>
          ))}

          {/* Files */}
          {filteredFiles.map((entry) => (
            <FileRow key={'f-' + entry.name} entry={entry} formatSize={formatSize} siteId={siteId!} uploadId={uploadId} currentPath={currentPath} />
          ))}

          {filteredDirs.length === 0 && filteredFiles.length === 0 && (
            <div className="px-4 py-8 text-center text-gray-500 text-sm">
              {searchFilter ? 'No matches found' : 'Empty directory'}
            </div>
          )}
        </div>
      )}

      {/* Stats bar */}
      <div className="flex items-center gap-4 text-xs text-gray-500">
        <span>{dirs.length} folder{dirs.length !== 1 ? 's' : ''}</span>
        <span>{files.length} file{files.length !== 1 ? 's' : ''}</span>
        {searchFilter && (
          <span className="text-brand-400">
            Showing {filteredDirs.length + filteredFiles.length} of {dirs.length + files.length}
          </span>
        )}
      </div>
    </div>
  )
}

function FileRow({ entry, formatSize, siteId, uploadId, currentPath }: {
  entry: FilesystemEntry
  formatSize: (s?: number) => string
  siteId: string
  uploadId?: string
  currentPath: string
}) {
  const [expanded, setExpanded] = useState(false)

  const handleDownload = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!uploadId) return
    const password = localStorage.getItem('responseray_password') || ''
    const authHeader = 'Basic ' + btoa('analyst:' + password)
    const qs = new URLSearchParams({ path: currentPath, name: entry.name }).toString()
    fetch(`/api/sites/${siteId}/filesystem/download/${uploadId}?${qs}`, {
      headers: { 'Authorization': authHeader },
    })
      .then(res => {
        if (!res.ok) throw new Error('Download failed')
        return res.blob()
      })
      .then(blob => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = entry.name
        a.click()
        URL.revokeObjectURL(url)
      })
      .catch(err => alert(err.message))
  }

  return (
    <>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full grid grid-cols-[1fr_100px_160px_80px] gap-2 px-4 py-2 hover:bg-gray-800/50 transition-colors border-b border-gray-800/50 text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          <File className="w-4 h-4 text-gray-500 shrink-0" />
          <span className={`text-sm truncate ${entry.is_deleted ? 'text-red-400 line-through' : 'text-gray-300'}`}>
            {entry.name}
          </span>
          {entry.has_artifact && (
            <span
              onClick={handleDownload}
              title="Download captured file"
              className="shrink-0 p-0.5 rounded hover:bg-gray-700 text-brand-400 hover:text-brand-300 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
            </span>
          )}
        </div>
        <span className="text-xs text-gray-500 text-right font-mono self-center">
          {formatSize(entry.size)}
        </span>
        <span className="text-xs text-gray-500 text-right self-center">
          {entry.latest_time ? formatDateTimeShort(entry.latest_time) : '-'}
        </span>
        <div className="flex items-center justify-center gap-1">
          {entry.has_timestomp && (
            <span title="Possible timestomping"><AlertTriangle className="w-3.5 h-3.5 text-amber-400" /></span>
          )}
          {entry.is_suspicious && (
            <span title="Suspicious"><Shield className="w-3.5 h-3.5 text-amber-400" /></span>
          )}
          {entry.significance && (
            <span title={entry.significance}><AlertTriangle className="w-3.5 h-3.5 text-purple-400" /></span>
          )}
          {entry.md5 && (
            <span title="Has hash"><Hash className="w-3.5 h-3.5 text-gray-600" /></span>
          )}
        </div>
      </button>

      {expanded && (
        <div className="px-4 py-3 bg-gray-800/30 border-b border-gray-800/50 text-xs space-y-1">
          {entry.has_artifact && (
            <div className="flex gap-2">
              <button
                onClick={handleDownload}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-brand-600 text-white rounded hover:bg-brand-500 transition-colors text-xs font-medium"
              >
                <Download className="w-3.5 h-3.5" />
                Download Captured File
              </button>
            </div>
          )}
          {entry.md5 && (
            <div className="flex gap-2">
              <span className="text-gray-500 w-14">MD5</span>
              <span className="text-gray-300 font-mono">{entry.md5}</span>
            </div>
          )}
          {entry.sha256 && (
            <div className="flex gap-2">
              <span className="text-gray-500 w-14">SHA256</span>
              <span className="text-gray-300 font-mono break-all">{entry.sha256}</span>
            </div>
          )}
          {entry.is_deleted && (
            <div className="flex gap-2">
              <span className="text-red-400">Deleted file</span>
            </div>
          )}
          {entry.has_timestomp && (
            <div className="flex gap-2">
              <span className="text-amber-400">Possible timestomping detected</span>
            </div>
          )}
          {entry.significance && (
            <div className="flex gap-2">
              <span className="text-gray-500 w-14">CT</span>
              <span className="text-purple-400">{entry.significance}</span>
            </div>
          )}
        </div>
      )}
    </>
  )
}
