import { useState, useEffect } from 'react'
import { Search, X } from 'lucide-react'
import { useQueryContext, parseFilters } from '../context/QueryContext'
import { cn } from '../lib/utils'

export default function QueryBar() {
  const { query, setQuery, removeFilter, clearQuery } = useQueryContext()
  const [input, setInput] = useState(query)

  useEffect(() => {
    setInput(query)
  }, [query])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setQuery(input.trim())
  }

  const filters = parseFilters(query)

  return (
    <div className="space-y-2">
      <form onSubmit={handleSubmit} className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='Lucene query — e.g. event_type:windows_logon AND -host_name:"DC01"'
            className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-foreground placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
          />
        </div>
        {query && (
          <button
            type="button"
            onClick={clearQuery}
            className="px-3 py-2 text-gray-400 hover:text-foreground bg-gray-900 border border-gray-700 rounded-lg text-sm transition-colors"
            title="Clear query"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </form>

      {filters.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {filters.map((f, i) => (
            <span
              key={i}
              className={cn(
                'inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono border',
                f.exclude
                  ? 'bg-red-500/10 border-red-500/30 text-red-400'
                  : 'bg-brand-500/10 border-brand-500/30 text-brand-400'
              )}
            >
              <span className="opacity-60">{f.exclude ? '- ' : '+ '}</span>
              <span className="text-gray-400">{f.field}:</span>
              <span>{f.value}</span>
              <button
                onClick={() => removeFilter(f.field, f.value)}
                className="ml-0.5 hover:text-foreground transition-colors"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
