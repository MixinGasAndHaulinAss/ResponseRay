import { useState } from 'react'
import { Outlet, useParams, NavLink } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronRight } from 'lucide-react'
import Sidebar from './Sidebar'
import { api } from '../../lib/api'

const STORAGE_KEY = 'responseray_sidebar_collapsed'

export default function Layout() {
  const { siteId, uploadId } = useParams()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem(STORAGE_KEY) === 'true')

  const handleToggle = () => {
    setCollapsed(prev => {
      const next = !prev
      localStorage.setItem(STORAGE_KEY, String(next))
      return next
    })
  }

  const { data: site } = useQuery({
    queryKey: ['site', siteId],
    queryFn: () => api.getSite(siteId!),
    enabled: !!siteId,
  })

  const { data: uploads } = useQuery({
    queryKey: ['uploads', siteId],
    queryFn: () => api.listUploads(siteId!),
    enabled: !!siteId,
  })

  const currentUpload = uploads?.find(u => u.id === uploadId)

  return (
    <div className="flex min-h-screen">
      <Sidebar collapsed={collapsed} onToggle={handleToggle} />
      <div className={`flex-1 transition-all duration-200 ${collapsed ? 'ml-14' : 'ml-56'}`}>
        {siteId && (
          <header className="bg-gray-900/50 border-b border-gray-800 px-6 py-3">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <NavLink to="/" className="hover:text-foreground transition-colors">Sites</NavLink>
              <ChevronRight className="w-3 h-3" />
              <NavLink to={`/sites/${siteId}`} className="hover:text-foreground transition-colors">
                {site?.name || '...'}
              </NavLink>
              {uploadId && currentUpload && (
                <>
                  <ChevronRight className="w-3 h-3" />
                  <span className="text-foreground font-medium">{currentUpload.filename}</span>
                </>
              )}
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
