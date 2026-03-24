import { useState, useRef, useEffect, useCallback, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
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
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null)
  const btnRef = useRef<HTMLButtonElement>(null)

  const updatePosition = useCallback(() => {
    if (!btnRef.current) return
    const rect = btnRef.current.getBoundingClientRect()
    setPos({ top: rect.bottom + 4, left: rect.left })
  }, [])

  useEffect(() => {
    if (!open) return
    updatePosition()
    const handler = (e: MouseEvent) => {
      if (btnRef.current && btnRef.current.contains(e.target as Node)) return
      setOpen(false)
    }
    const onScroll = () => setOpen(false)
    document.addEventListener('mousedown', handler)
    window.addEventListener('scroll', onScroll, true)
    return () => {
      document.removeEventListener('mousedown', handler)
      window.removeEventListener('scroll', onScroll, true)
    }
  }, [open, updatePosition])

  if (!value || value === '-') {
    return <>{children}</>
  }

  const handleClick = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setOpen(!open)
  }

  const handleInclude = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    addFilter(field, value, false)
    setOpen(false)
  }

  const handleExclude = (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    addFilter(field, value, true)
    setOpen(false)
  }

  return (
    <span className="relative inline-flex items-center field-value-wrapper" data-field-value="true">
      <button
        ref={btnRef}
        onClick={handleClick}
        className="hover:bg-brand-500/10 hover:text-brand-300 rounded px-0.5 -mx-0.5 transition-colors cursor-pointer text-left"
      >
        {children}
      </button>
      {open && pos && createPortal(
        <div
          className="fixed z-[9999] bg-gray-900 border border-gray-700 rounded-lg shadow-xl py-1 min-w-[140px]"
          style={{ top: pos.top, left: pos.left }}
          onMouseDown={(e) => e.stopPropagation()}
        >
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
        </div>,
        document.body
      )}
    </span>
  )
}
