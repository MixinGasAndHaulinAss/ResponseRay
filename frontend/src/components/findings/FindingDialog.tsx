import { useState } from 'react'
import { X } from 'lucide-react'
import { cn, FINDING_COLORS } from '../../lib/utils'

interface FindingDialogProps {
  currentFinding?: string | null
  currentNote?: string | null
  onSave: (finding: string | null, note: string | null) => void
  onClose: () => void
}

export default function FindingDialog({ currentFinding, currentNote, onSave, onClose }: FindingDialogProps) {
  const [finding, setFinding] = useState<string | null>(currentFinding || null)
  const [note, setNote] = useState(currentNote || '')

  const findings = ['bad', 'suspicious', 'good']

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 w-96 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Mark Finding</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex gap-2 mb-4">
          {findings.map((f) => (
            <button
              key={f}
              onClick={() => setFinding(finding === f ? null : f)}
              className={cn(
                'flex-1 py-2 px-3 rounded-md border text-sm font-medium transition-colors capitalize',
                finding === f
                  ? FINDING_COLORS[f]
                  : 'border-gray-700 text-gray-400 hover:text-white hover:border-gray-600'
              )}
            >
              {f}
            </button>
          ))}
        </div>

        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Add a note (optional)..."
          rows={3}
          className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-sm text-gray-200 placeholder-gray-500 resize-none focus:outline-none focus:ring-1 focus:ring-brand-500"
        />

        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white">
            Cancel
          </button>
          <button
            onClick={() => onSave(finding, note || null)}
            className="px-4 py-2 text-sm bg-brand-600 text-white rounded-md hover:bg-brand-500"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  )
}
