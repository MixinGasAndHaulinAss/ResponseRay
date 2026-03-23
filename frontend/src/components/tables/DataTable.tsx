import { useState } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react'
import { cn, formatNumber } from '../../lib/utils'

interface DataTableProps<T> {
  data: T[]
  columns: ColumnDef<T, unknown>[]
  total: number
  offset: number
  limit: number
  onPageChange: (offset: number) => void
  onRowClick?: (row: T) => void
  isLoading?: boolean
  selectedIds?: Set<number>
  onSelectionChange?: (ids: Set<number>) => void
  sortField?: string
  sortDir?: 'asc' | 'desc'
  onSortChange?: (field: string) => void
  sortableColumns?: Set<string>
}

export default function DataTable<T extends { id: number }>({
  data,
  columns,
  total,
  offset,
  limit,
  onPageChange,
  onRowClick,
  isLoading,
  selectedIds,
  onSelectionChange,
  sortField,
  sortDir,
  onSortChange,
  sortableColumns,
}: DataTableProps<T>) {
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  })

  const page = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit)

  return (
    <div className="space-y-3">
      <div className="border border-gray-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id} className="bg-gray-900/80 border-b border-gray-800">
                  {selectedIds !== undefined && (
                    <th className="px-3 py-2.5 w-10">
                      <input
                        type="checkbox"
                        checked={data.length > 0 && data.every((d) => selectedIds.has(d.id))}
                        onChange={(e) => {
                          if (!onSelectionChange) return
                          const next = new Set(selectedIds)
                          if (e.target.checked) data.forEach((d) => next.add(d.id))
                          else data.forEach((d) => next.delete(d.id))
                          onSelectionChange(next)
                        }}
                        className="rounded border-gray-600 bg-gray-800"
                      />
                    </th>
                  )}
                  {hg.headers.map((h) => {
                    const isSortable = sortableColumns?.has(h.id) && onSortChange
                    const isActive = sortField === h.id
                    return (
                      <th
                        key={h.id}
                        className={cn(
                          'px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wider whitespace-nowrap',
                          isSortable ? 'cursor-pointer select-none hover:text-gray-200 transition-colors' : '',
                          isActive ? 'text-brand-400' : 'text-gray-400'
                        )}
                        onClick={isSortable ? () => onSortChange(h.id) : undefined}
                      >
                        <span className="inline-flex items-center gap-1">
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          {isSortable && (
                            isActive
                              ? sortDir === 'asc'
                                ? <ArrowUp className="w-3 h-3" />
                                : <ArrowDown className="w-3 h-3" />
                              : <ArrowUpDown className="w-3 h-3 opacity-30" />
                          )}
                        </span>
                      </th>
                    )
                  })}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {isLoading ? (
                <tr>
                  <td colSpan={columns.length + (selectedIds !== undefined ? 1 : 0)} className="px-3 py-12 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : data.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + (selectedIds !== undefined ? 1 : 0)} className="px-3 py-12 text-center text-gray-500">
                    No results found
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => onRowClick?.(row.original)}
                    className={cn(
                      'hover:bg-gray-800/30 transition-colors',
                      onRowClick && 'cursor-pointer',
                      selectedIds?.has(row.original.id) && 'bg-brand-500/5'
                    )}
                  >
                    {selectedIds !== undefined && (
                      <td className="px-3 py-2 w-10">
                        <input
                          type="checkbox"
                          checked={selectedIds.has(row.original.id)}
                          onChange={(e) => {
                            e.stopPropagation()
                            if (!onSelectionChange) return
                            const next = new Set(selectedIds)
                            if (e.target.checked) next.add(row.original.id)
                            else next.delete(row.original.id)
                            onSelectionChange(next)
                          }}
                          onClick={(e) => e.stopPropagation()}
                          className="rounded border-gray-600 bg-gray-800"
                        />
                      </td>
                    )}
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className="px-3 py-2 text-gray-300 whitespace-nowrap max-w-md truncate">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400">
        <span>{formatNumber(total)} total results</span>
        <div className="flex items-center gap-1">
          <button onClick={() => onPageChange(0)} disabled={page <= 1} className="p-1.5 hover:text-white disabled:opacity-30">
            <ChevronsLeft className="w-4 h-4" />
          </button>
          <button onClick={() => onPageChange(Math.max(0, offset - limit))} disabled={page <= 1} className="p-1.5 hover:text-white disabled:opacity-30">
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="px-3">Page {page} of {totalPages || 1}</span>
          <button onClick={() => onPageChange(offset + limit)} disabled={page >= totalPages} className="p-1.5 hover:text-white disabled:opacity-30">
            <ChevronRight className="w-4 h-4" />
          </button>
          <button onClick={() => onPageChange((totalPages - 1) * limit)} disabled={page >= totalPages} className="p-1.5 hover:text-white disabled:opacity-30">
            <ChevronsRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}
