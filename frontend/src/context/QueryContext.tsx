import { createContext, useContext, useCallback, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'

interface QueryContextValue {
  query: string
  setQuery: (q: string) => void
  addFilter: (field: string, value: string, exclude?: boolean) => void
  removeFilter: (field: string, value: string) => void
  clearQuery: () => void
}

const QueryCtx = createContext<QueryContextValue>({
  query: '',
  setQuery: () => {},
  addFilter: () => {},
  removeFilter: () => {},
  clearQuery: () => {},
})

export function useQueryContext() {
  return useContext(QueryCtx)
}

function escapeValue(value: string): string {
  if (/[\s":()]/.test(value)) {
    return `"${value.replace(/"/g, '\\"')}"`
  }
  return value
}

function buildFilterToken(field: string, value: string, exclude?: boolean): string {
  const prefix = exclude ? '-' : ''
  return `${prefix}${field}:${escapeValue(value)}`
}

export function parseFilters(query: string): { field: string; value: string; exclude: boolean; raw: string }[] {
  const filters: { field: string; value: string; exclude: boolean; raw: string }[] = []
  const regex = /(-?)(\w[\w.]*):((?:"(?:[^"\\]|\\.)*")|(?:\S+))/g
  let match
  while ((match = regex.exec(query)) !== null) {
    const exclude = match[1] === '-'
    const field = match[2]
    let value = match[3]
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\"/g, '"')
    }
    filters.push({ field, value, exclude, raw: match[0] })
  }
  return filters
}

export function QueryProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const query = searchParams.get('q') || ''

  const setQuery = useCallback((q: string) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (q) {
        next.set('q', q)
      } else {
        next.delete('q')
      }
      return next
    }, { replace: true })
  }, [setSearchParams])

  const addFilter = useCallback((field: string, value: string, exclude?: boolean) => {
    const token = buildFilterToken(field, value, exclude)
    const existing = parseFilters(query)
    const duplicate = existing.find(f => f.field === field && f.value === value && f.exclude === !!exclude)
    if (duplicate) return

    const opposite = existing.find(f => f.field === field && f.value === value && f.exclude !== !!exclude)
    let newQuery = query
    if (opposite) {
      newQuery = newQuery.replace(opposite.raw, '').replace(/\s{2,}/g, ' ').trim()
    }

    newQuery = newQuery ? `${newQuery} AND ${token}` : token
    setQuery(newQuery)
  }, [query, setQuery])

  const removeFilter = useCallback((field: string, value: string) => {
    const existing = parseFilters(query)
    const target = existing.find(f => f.field === field && f.value === value)
    if (!target) return

    let newQuery = query.replace(target.raw, '').trim()
    newQuery = newQuery.replace(/^AND\s+/i, '').replace(/\s+AND\s*$/i, '').replace(/\s+AND\s+AND\s+/gi, ' AND ')
    setQuery(newQuery)
  }, [query, setQuery])

  const clearQuery = useCallback(() => {
    setQuery('')
  }, [setQuery])

  return (
    <QueryCtx.Provider value={{ query, setQuery, addFilter, removeFilter, clearQuery }}>
      {children}
    </QueryCtx.Provider>
  )
}
