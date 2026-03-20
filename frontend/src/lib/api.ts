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
  getDashboard: (siteId: string) => request<DashboardStats>(`/sites/${siteId}/dashboard`),

  // Uploads
  listUploads: (siteId: string) => request<Upload[]>(`/sites/${siteId}/uploads`),
  uploadFile: async (siteId: string, file: File, onProgress?: (pct: number) => void): Promise<Upload> => {
    const formData = new FormData()
    formData.append('file', file)

    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('POST', `${API_BASE}/sites/${siteId}/uploads`)
      xhr.setRequestHeader('Authorization', getAuthHeader())

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && onProgress) {
          onProgress(Math.round((e.loaded / e.total) * 100))
        }
      }

      xhr.onload = () => {
        if (xhr.status === 201) resolve(JSON.parse(xhr.responseText))
        else reject(new Error(xhr.responseText || xhr.statusText))
      }
      xhr.onerror = () => reject(new Error('Upload failed'))
      xhr.send(formData)
    })
  },
  getUploadStatus: (siteId: string, uploadId: string) =>
    request<Upload>(`/sites/${siteId}/uploads/${uploadId}`),
  deleteUpload: (siteId: string, uploadId: string) =>
    request<void>(`/sites/${siteId}/uploads/${uploadId}`, { method: 'DELETE' }),

  // Events
  queryEvents: (siteId: string, params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString()
    return request<PagedResult<Event>>(`/sites/${siteId}/events?${qs}`)
  },
  updateFinding: (siteId: string, eventId: number, data: { finding: string | null; finding_note: string | null }) =>
    request<void>(`/sites/${siteId}/events/${eventId}/finding`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
  bulkUpdateFinding: (siteId: string, data: { event_ids: number[]; finding: string | null; finding_note: string | null }) =>
    request<void>(`/sites/${siteId}/events/findings`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }),
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
  status: 'pending' | 'processing' | 'complete' | 'error'
  event_count: number
  error_msg?: string
  created_at: string
  updated_at: string
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

export interface DashboardStats {
  total_events: number
  event_counts: Record<string, number>
  notable_count: number
  suspicious_count: number
  finding_counts: Record<string, number>
  uploads: Upload[]
}
