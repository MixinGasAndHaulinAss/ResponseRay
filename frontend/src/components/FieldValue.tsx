import { useState, useRef, useEffect, type ReactNode } from 'react'
import { Plus, Minus } from 'lucide-react'
import { useQueryContext } from '../context/QueryContext'

interface Props {
  field: string
  value: string
  children: ReactNode
}

export default function FieldValue({ field, value, children }: Props) {
  const { addFilter } = useQueryContext()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLSpanElement>(null)

  useEffect(() => {
    if (!open) return
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [open])

  if (!value || value === '-') {
    return <>{children}</>
  }

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation()
    setOpen(!open)
  }

  const handleInclude = (e: React.MouseEvent) => {
    e.stopPropagation()
    addFilter(field, value, false)
    setOpen(false)
  }

  const handleExclude = (e: React.MouseEvent) => {
    e.stopPropagation()
    addFilter(field, value, true)
    setOpen(false)
  }

  return (
    <span ref={ref} className="relative inline-flex items-center">
      <button
        onClick={handleClick}
        className="hover:bg-brand-500/10 hover:text-brand-300 rounded px-0.5 -mx-0.5 transition-colors cursor-pointer text-left"
      >
        {children}
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 z-50 bg-gray-900 border border-gray-700 rounded-lg shadow-xl py-1 min-w-[140px]">
          <button
            onClick={handleInclude}
            className="w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-gray-800 transition-colors text-left"
          >
            <Plus className="w-3.5 h-3.5 text-green-400" />
            <span className="text-gray-300">Include</span>
            <span className="text-gray-500 font-mono ml-auto truncate max-w-[100px]">{value}</span>
          </button>
          <button
            onClick={handleExclude}
            className="w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-gray-800 transition-colors text-left"
          >
            <Minus className="w-3.5 h-3.5 text-red-400" />
            <span className="text-gray-300">Exclude</span>
            <span className="text-gray-500 font-mono ml-auto truncate max-w-[100px]">{value}</span>
          </button>
        </div>
      )}
    </span>
  )
}
