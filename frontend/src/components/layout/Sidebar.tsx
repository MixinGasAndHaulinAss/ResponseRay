import { NavLink, useParams } from 'react-router-dom'
import {
  LayoutDashboard, Users, LogIn, Cpu, Terminal, Server,
  Shield, Network, Globe, ShieldAlert, BarChart3, Monitor,
  ScrollText, FolderTree, Clock, Search, Zap, HardDrive,
  FileText, Settings
} from 'lucide-react'
import { cn } from '../../lib/utils'

const navItems = [
  { to: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: 'accounts', label: 'Accounts', icon: Users },
  { to: 'logons', label: 'Logons', icon: LogIn },
  { to: 'processes', label: 'Processes', icon: Cpu },
  { to: 'powershell', label: 'PowerShell', icon: Terminal },
  { to: 'services', label: 'Services', icon: Server },
  { to: 'persistence', label: 'Persistence', icon: Zap },
  { to: 'network', label: 'Network', icon: Network },
  { to: 'web-data', label: 'Web & Data', icon: Globe },
  { to: 'defender', label: 'Defender', icon: ShieldAlert },
  { to: 'srum', label: 'SRUM', icon: BarChart3 },
  { to: 'system', label: 'System Info', icon: Monitor },
  { to: 'eventlog', label: 'Event Log', icon: ScrollText },
  { to: 'filesystem', label: 'File System', icon: FolderTree },
  { to: 'timeline', label: 'Timeline', icon: Clock },
  { to: 'search', label: 'Search', icon: Search },
]

export default function Sidebar() {
  const { siteId } = useParams()

  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-800 flex flex-col h-screen fixed left-0 top-0">
      <div className="p-4 border-b border-gray-800">
        <NavLink to="/" className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-brand-500" />
          <span className="text-lg font-bold text-white">ResponseRay</span>
        </NavLink>
      </div>

      {siteId && (
        <nav className="flex-1 overflow-y-auto py-2">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={`/sites/${siteId}/${to}`}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2.5 px-4 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-brand-500/10 text-brand-400 border-r-2 border-brand-500'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                )
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>
      )}

      <div className="p-3 border-t border-gray-800 text-xs text-gray-500">
        v2026.3.19.1
      </div>
    </aside>
  )
}
