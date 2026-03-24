import { useState } from 'react'
import { X, Flag, Copy, Check } from 'lucide-react'
import { Event } from '../lib/api'
import { formatDateTime, EVENT_TYPE_LABELS } from '../lib/utils'
import FindingBadge from './findings/FindingBadge'

interface Props {
  event: Event
  onClose: () => void
  onMarkFinding: () => void
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!value) return
    await navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  if (!value || value === '-') return null

  return (
    <button
      onClick={handleCopy}
      className="p-0.5 text-gray-600 hover:text-brand-400 transition-colors shrink-0"
    >
      {copied
        ? <Check className="w-3.5 h-3.5 text-green-400" />
        : <Copy className="w-3.5 h-3.5" />
      }
    </button>
  )
}

export default function EventDetailPanel({ event, onClose, onMarkFinding }: Props) {
  const skipKeys = new Set([
    'id', 'upload_id', 'site_id', 'datetime', 'event_type', 'data_type',
    'message', 'host_name', 'source_short', 'timestamp_desc',
    'ct_significance', 'is_suspicious', 'finding', 'finding_note',
  ])

  const dataEntries = Object.entries(event.data).filter(([k]) => !skipKeys.has(k))

  return (
    <div className="fixed inset-y-0 right-0 w-[560px] bg-gray-900 border-l border-gray-800 shadow-2xl z-40 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <h3 className="font-semibold text-foreground">Event Detail</h3>
          <FindingBadge finding={event.finding} isSuspicious={event.is_suspicious} ctSignificance={event.ct_significance} small />
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onMarkFinding} className="p-1.5 text-gray-400 hover:text-foreground" title="Mark Finding">
            <Flag className="w-4 h-4" />
          </button>
          <button onClick={onClose} className="p-1.5 text-gray-400 hover:text-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="grid grid-cols-2 gap-3 text-sm">
          <Field label="Timestamp" value={formatDateTime(event.datetime)} />
          <Field label="Type" value={EVENT_TYPE_LABELS[event.event_type] || event.event_type} />
          <Field label="Data Type" value={event.data_type} />
          <Field label="Source" value={event.source_short} />
          <Field label="Host" value={event.host_name} />
          <Field label="Timestamp Desc" value={event.timestamp_desc} />
        </div>

        {event.message && (
          <div>
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-gray-500 uppercase">Message</label>
              <CopyButton value={event.message} />
            </div>
            <p className="mt-1 text-sm text-gray-200 bg-gray-800/50 p-3 rounded-md break-all">{event.message}</p>
          </div>
        )}

        {event.finding_note && (
          <div>
            <div className="flex items-center justify-between">
              <label className="text-xs font-medium text-gray-500 uppercase">Finding Note</label>
              <CopyButton value={event.finding_note} />
            </div>
            <p className="mt-1 text-sm text-gray-200 bg-gray-800/50 p-3 rounded-md">{event.finding_note}</p>
          </div>
        )}

        <div>
          <label className="text-xs font-medium text-gray-500 uppercase mb-2 block">Event Data</label>
          <div className="bg-gray-800/50 rounded-md divide-y divide-gray-800">
            {dataEntries.map(([key, value]) => {
              const displayValue = typeof value === 'object' ? JSON.stringify(value) : String(value ?? '')
              return (
                <div key={key} className="flex gap-3 px-3 py-2 text-sm group">
                  <span className="text-gray-500 font-mono text-xs min-w-[160px] flex-shrink-0 pt-0.5">{key}</span>
                  <span className="text-gray-200 break-all flex-1">{displayValue}</span>
                  <span className="opacity-0 group-hover:opacity-100 transition-opacity self-start pt-0.5">
                    <CopyButton value={displayValue} />
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value?: string | null }) {
  const displayValue = value || '-'
  return (
    <div className="group flex items-start justify-between gap-1">
      <div className="min-w-0">
        <label className="text-xs font-medium text-gray-500 uppercase">{label}</label>
        <p className="mt-0.5 text-sm text-gray-200 truncate">{displayValue}</p>
      </div>
      <span className="opacity-0 group-hover:opacity-100 transition-opacity mt-3.5">
        <CopyButton value={displayValue} />
      </span>
    </div>
  )
}
