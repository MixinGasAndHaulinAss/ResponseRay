const API_BASE = '/api'

function getAuthHeader(): string {
  const password = localStorage.getItem('responseray_password') || ''
  return 'Basic ' + btoa('analyst:' + password)
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(API_BASE + path, {
    ...options,
    headers: {
      'Authorization': getAuthHeader(),
      ...options?.headers,
    },
  })

  if (res.status === 401) {
    localStorage.removeItem('responseray_password')
    window.location.reload()
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || res.statusText)
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  setPassword(password: string) {
    localStorage.setItem('responseray_password', password)
  },

  getPassword(): string | null {
    return localStorage.getItem('responseray_password')
  },

  async checkAuth(): Promise<boolean> {
    try {
      await request('/health')
      return true
    } catch {
      return false
    }
  },

  // Sites
  listSites: () => request<SiteWithCounts[]>('/sites/'),
  createSite: (data: { name: string; description: string }) =>
    request<Site>('/sites/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
  getSite: (id: string) => request<Site>(`/sites/${id}/`),
  updateSite: (id: string, data: { name: string; description: string }) =>
    request<void>(`/sites/${id}/`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
  deleteSite: (id: string) => request<void>(`/sites/${id}/`, { method: 'DELETE' }),

  // Dashboard
  getDashboard: (siteId: string, uploadId?: string) => {
    const qs = uploadId ? `?upload_id=${uploadId}` : ''
    return request<DashboardStats>(`/sites/${siteId}/dashboard${qs}`)
  },

  // Uploads
  listUploads: (siteId: string) => request<Upload[]>(`/sites/${siteId}/uploads`),
  uploadFile: async (siteId: string, file: File, onProgress?: (pct: number) => void): Promise<Upload> => {
    const CHUNK_SIZE = 50 * 1024 * 1024 // 50 MB
    const totalParts = Math.ceil(file.size / CHUNK_SIZE)

    const initRes = await fetch(`${API_BASE}/sites/${siteId}/uploads/init`, {
      method: 'POST',
      headers: { 'Authorization': getAuthHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name,
        total_size: file.size,
        chunk_size: CHUNK_SIZE,
        total_parts: totalParts,
      }),
    })
    if (!initRes.ok) {
      const text = await initRes.text()
      throw new Error(text || 'Failed to initialize upload')
    }
    const { upload_id } = await initRes.json()

    for (let i = 0; i < totalParts; i++) {
      const start = i * CHUNK_SIZE
      const end = Math.min(start + CHUNK_SIZE, file.size)
      const chunk = file.slice(start, end)

      await new Promise<void>((resolve, reject) => {
        const xhr = new XMLHttpRequest()
        xhr.open('PUT', `${API_BASE}/sites/${siteId}/uploads/${upload_id}/chunks/${i}`)
        xhr.setRequestHeader('Authorization', getAuthHeader())

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable && onProgress) {
            const chunkProgress = e.loaded / e.total
            const overall = ((i + chunkProgress) / totalParts) * 100
            onProgress(Math.round(overall))
          }
        }

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) resolve()
          else {
            const text = xhr.responseText || xhr.statusText
            const isHtml = text.trimStart().startsWith('<')
            reject(new Error(isHtml ? `Chunk ${i + 1}/${totalParts} failed (${xhr.status})` : text))
          }
        }
        xhr.onerror = () => reject(new Error(`Chunk ${i + 1}/${totalParts} failed — network error`))
        xhr.send(chunk)
      })
    }

    const completeRes = await fetch(`${API_BASE}/sites/${siteId}/uploads/${upload_id}/complete`, {
      method: 'POST',
      headers: { 'Authorization': getAuthHeader() },
    })
    if (!completeRes.ok) {
      const text = await completeRes.text()
      throw new Error(text || 'Failed to finalize upload')
    }

    onProgress?.(100)
    return { id: upload_id, site_id: siteId, filename: file.name, host_name: '', status: 'pending', event_count: 0, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
  },
  getUploadStatus: (siteId: string, uploadId: string) =>
    request<Upload>(`/sites/${siteId}/uploads/${uploadId}`),
  deleteUpload: (siteId: string, uploadId: string) =>
    request<void>(`/sites/${siteId}/uploads/${uploadId}`, { method: 'DELETE' }),

  // Filesystem
  listDirectory: (siteId: string, path: string, uploadId?: string) => {
    let qs = `path=${encodeURIComponent(path)}`
    if (uploadId) qs += `&upload_id=${uploadId}`
    return request<FilesystemResponse>(`/sites/${siteId}/filesystem?${qs}`)
  },

  // Logons
  getLogonUsers: (siteId: string, uploadId?: string) => {
    const qs = uploadId ? `?upload_id=${uploadId}` : ''
    return request<LogonUserSummary[]>(`/sites/${siteId}/logons/users${qs}`)
  },

  // Remote Access
  detectRemoteAccess: (siteId: string, uploadId?: string) => {
    const qs = uploadId ? `?upload_id=${uploadId}` : ''
    return request<RemoteAccessTool[]>(`/sites/${siteId}/remote-access${qs}`)
  },

  // Events
  queryEvents: (siteId: string, params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString()
    return request<PagedResult<Event>>(`/sites/${siteId}/events?${qs}`)
  },
  updateFinding: (siteId: string, eventId: number, data: { finding: string | null; finding_note: string | null }) =>
    request<void>(`/sites/${siteId}/events/${eventId}/finding`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
  bulkUpdateFinding: (siteId: string, data: { event_ids: number[]; finding: string | null; finding_note: string | null }) =>
    request<void>(`/sites/${siteId}/events/findings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),

  // API Keys
  listApiKeys: () => request<ApiKey[]>('/keys/'),
  createApiKey: (name: string) =>
    request<ApiKeyCreateResponse>('/keys/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) }),
  deleteApiKey: (keyId: string) =>
    request<void>(`/keys/${keyId}`, { method: 'DELETE' }),

  // Platforms
  getPlatforms: (siteId: string) => request<PlatformInfo[]>(`/sites/${siteId}/platforms`),

  // Collectors
  listCollectors: () => request<CollectorInfo[]>('/collectors/'),
  downloadCollector: async (platform: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/collectors/${platform}/download`, {
      headers: { 'Authorization': getAuthHeader() },
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(text || `Failed to download ${platform} collector`)
    }
    const blob = await res.blob()
    const disposition = res.headers.get('content-disposition') || ''
    const match = /filename="?([^";]+)"?/i.exec(disposition)
    const filename = match ? match[1] : `responseray-collector-${platform}`
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  },
}

// Types
export interface Site {
  id: string
  name: string
  description: string
  created_at: string
  updated_at: string
}

export interface SiteWithCounts extends Site {
  upload_count: number
  event_count: number
}

export interface Upload {
  id: string
  site_id: string
  filename: string
  host_name: string
  status: 'pending' | 'processing' | 'complete' | 'error' | 'chunking'
  event_count: number
  error_msg?: string
  created_at: string
  updated_at: string
  progress_stage?: string
  progress_percent?: number
  events_processed?: number
  events_total?: number
  queue_position?: number
  queue_length?: number
  processing_started_at?: string
}

export interface Event {
  id: number
  upload_id: string
  site_id: string
  datetime: string
  event_type: string
  data_type?: string
  message?: string
  host_name?: string
  source_short?: string
  timestamp_desc?: string
  ct_significance?: string
  is_suspicious: boolean
  finding?: string | null
  finding_note?: string | null
  data: Record<string, unknown>
}

export interface PagedResult<T> {
  items: T[]
  total: number
  offset: number
  limit: number
  has_more: boolean
}

export interface FilesystemEntry {
  name: string
  is_dir: boolean
  size?: number
  file_count?: number
  latest_time?: string
  md5?: string
  sha256?: string
  is_deleted?: boolean
  has_timestomp?: boolean
  significance?: string
  is_suspicious?: boolean
  has_artifact?: boolean
}

export interface FilesystemResponse {
  path: string
  entries: FilesystemEntry[]
}

export interface LogonUserSummary {
  username: string
  total_events: number
  success_count: number
  fail_count: number
  unique_ips: number
  first_seen: string
  last_seen: string
  auth_packages: string
  logon_types: string
  domain?: string
}

export interface RemoteAccessTool {
  name: string
  category: string
  event_count: number
  event_types: string[]
  first_seen: string | null
  last_seen: string | null
  search_terms: string[]
}

export interface DashboardStats {
  total_events: number
  event_counts: Record<string, number>
  notable_count: number
  suspicious_count: number
  finding_counts: Record<string, number>
  uploads: Upload[]
}

export interface ApiKey {
  id: string
  name: string
  prefix: string
  created_at: string
  last_used: string | null
  is_active: boolean
}

export interface ApiKeyCreateResponse extends ApiKey {
  key: string
}

export interface CollectorInfo {
  platform: string
  display_name: string
  filename: string
  description: string
  architecture: string
  available: boolean
  size?: number
  sha256?: string
  modified_at?: string
  error?: string
}

export interface PlatformInfo {
  platform: string
  upload_count: number
  event_count: number
}
