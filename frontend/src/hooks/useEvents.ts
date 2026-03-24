import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type Event, type PagedResult } from '../lib/api'

interface UseEventsOptions {
  siteId: string
  uploadId?: string
  eventTypes?: string[]
  search?: string
  channel?: string
  finding?: string
  notable?: boolean
  suspicious?: boolean
  limit?: number
  sortField?: string
  sortDir?: string
  dataFilters?: Record<string, string>
  dateFrom?: string
  dateTo?: string
  query?: string
  enabled?: boolean
}

export function useEvents(options: UseEventsOptions) {
  const [offset, setOffset] = useState(0)
  const pageLimit = options.limit || 100

  const params: Record<string, string> = {
    offset: String(offset),
    limit: String(pageLimit),
  }
  if (options.uploadId) params.upload_id = options.uploadId
  if (options.eventTypes?.length) params.event_types = options.eventTypes.join(',')
  if (options.search) params.search = options.search
  if (options.channel) params.channel = options.channel
  if (options.finding) params.finding = options.finding
  if (options.notable) params.notable = 'true'
  if (options.suspicious) params.suspicious = 'true'
  if (options.sortField) params.sort = options.sortField
  if (options.sortDir) params.dir = options.sortDir
  if (options.dateFrom) params.date_from = options.dateFrom
  if (options.dateTo) params.date_to = options.dateTo
  if (options.query) params.q = options.query

  if (options.dataFilters) {
    for (const [k, v] of Object.entries(options.dataFilters)) {
      params[`data.${k}`] = v
    }
  }

  const query = useQuery<PagedResult<Event>>({
    queryKey: ['events', options.siteId, params],
    queryFn: () => api.queryEvents(options.siteId, params),
    enabled: options.enabled !== false,
  })

  return {
    ...query,
    offset,
    setOffset,
    limit: pageLimit,
    events: query.data?.items || [],
    total: query.data?.total || 0,
  }
}
