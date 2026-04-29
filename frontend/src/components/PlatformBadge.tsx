import { Monitor, Apple, Server, Cpu } from 'lucide-react'
import { cn } from '../lib/utils'

interface Props {
  platform?: string
  className?: string
}

const platformConfig: Record<string, { icon: typeof Monitor; label: string; color: string }> = {
  windows: { icon: Monitor, label: 'Windows', color: 'text-blue-400' },
  macos: { icon: Apple, label: 'macOS', color: 'text-gray-300' },
  linux: { icon: Server, label: 'Linux', color: 'text-orange-400' },
  esxi: { icon: Cpu, label: 'ESXi', color: 'text-green-400' },
}

export default function PlatformBadge({ platform, className }: Props) {
  if (!platform || platform === 'unknown') return null

  const config = platformConfig[platform.toLowerCase()]
  if (!config) return null

  const Icon = config.icon

  return (
    <span className={cn('inline-flex items-center gap-1 text-xs', config.color, className)} title={config.label}>
      <Icon className="w-3 h-3" />
    </span>
  )
}

export function detectPlatformFromSource(source?: string): string | undefined {
  if (!source) return undefined
  const s = source.toLowerCase()
  if (s.includes('rr-macos') || s.includes('darwin')) return 'macos'
  if (s.includes('rr-linux') || s.includes('linux')) return 'linux'
  if (s.includes('rr-esxi') || s.includes('esxi')) return 'esxi'
  if (s.includes('windows') || s.includes('evtx') || s.includes('registry')) return 'windows'
  return undefined
}
