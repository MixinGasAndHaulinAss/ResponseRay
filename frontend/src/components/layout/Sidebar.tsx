import { NavLink, useParams } from 'react-router-dom'
import {
  LayoutDashboard, Users, LogIn, Cpu, Terminal, Server,
  Shield, Network, Globe, ShieldAlert, BarChart3, Monitor,
  ScrollText, FolderTree, Clock, Search, Zap, Radio,
  PanelLeftClose, PanelLeftOpen
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
  { to: 'remote-access', label: 'Remote Access', icon: Radio },
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

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { siteId } = useParams()

  return (
    <aside
      className={cn(
        'bg-gray-900 border-r border-gray-800 flex flex-col h-screen fixed left-0 top-0 transition-all duration-200 z-30',
        collapsed ? 'w-14' : 'w-56'
      )}
    >
      <div className={cn('border-b border-gray-800 flex items-center', collapsed ? 'px-2 py-4 justify-center' : 'p-4')}>
        <NavLink to="/" className="flex items-center gap-2 min-w-0">
          <Shield className="w-6 h-6 text-brand-500 shrink-0" />
          {!collapsed && <span className="text-lg font-bold text-white truncate">ResponseRay</span>}
        </NavLink>
      </div>

      {siteId && (
        <nav className="flex-1 overflow-y-auto py-2">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={`/sites/${siteId}/${to}`}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                cn(
                  'flex items-center text-sm transition-colors',
                  collapsed ? 'justify-center px-2 py-2.5' : 'gap-2.5 px-4 py-2',
                  isActive
                    ? 'bg-brand-500/10 text-brand-400 border-r-2 border-brand-500'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                )
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              {!collapsed && label}
            </NavLink>
          ))}
        </nav>
      )}

      <div className="border-t border-gray-800">
        <button
          onClick={onToggle}
          className={cn(
            'w-full flex items-center text-gray-500 hover:text-gray-200 transition-colors',
            collapsed ? 'justify-center py-3' : 'gap-2 px-4 py-3'
          )}
        >
          {collapsed
            ? <PanelLeftOpen className="w-4 h-4" />
            : <>
                <PanelLeftClose className="w-4 h-4" />
                <span className="text-xs">Collapse</span>
              </>
          }
        </button>
      </div>
    </aside>
  )
}
