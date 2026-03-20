import { cn, FINDING_COLORS } from '../../lib/utils'

interface FindingBadgeProps {
  finding?: string | null
  isSuspicious?: boolean
  ctSignificance?: string
  small?: boolean
}

export default function FindingBadge({ finding, isSuspicious, ctSignificance, small }: FindingBadgeProps) {
  if (!finding && !isSuspicious && ctSignificance !== 'LikelyNotable') return null

  const badges: JSX.Element[] = []

  if (finding) {
    badges.push(
      <span
        key="finding"
        className={cn(
          'inline-flex items-center border rounded-full font-medium',
          FINDING_COLORS[finding],
          small ? 'px-1.5 py-0.5 text-xs' : 'px-2 py-0.5 text-xs'
        )}
      >
        {finding}
      </span>
    )
  }

  if (isSuspicious) {
    badges.push(
      <span key="suspicious" className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/30">
        suspicious
      </span>
    )
  }

  if (ctSignificance === 'LikelyNotable') {
    badges.push(
      <span key="notable" className="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium bg-purple-500/20 text-purple-400 border border-purple-500/30">
        notable
      </span>
    )
  }

  return <div className="flex items-center gap-1">{badges}</div>
}
