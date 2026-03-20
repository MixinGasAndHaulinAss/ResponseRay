import { Outlet, useParams, NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight } from 'lucide-react'
import Sidebar from './Sidebar'
import { api } from '../../lib/api'

export default function Layout() {
  const { siteId } = useParams()

  const { data: site } = useQuery({
    queryKey: ['site', siteId],
    queryFn: () => api.getSite(siteId!),
    enabled: !!siteId,
  })

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex-1 ml-56">
        {siteId && (
          <header className="bg-gray-900/50 border-b border-gray-800 px-6 py-3">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <NavLink to="/" className="hover:text-white transition-colors">Sites</NavLink>
              <ChevronRight className="w-3 h-3" />
              <span className="text-white font-medium">{site?.name || '...'}</span>
            </div>
          </header>
        )}
        <main className="p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
