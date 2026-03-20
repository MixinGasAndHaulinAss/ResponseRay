import { useState, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { api } from './lib/api'
import Layout from './components/layout/Layout'
import Login from './pages/Login'
import Sites from './pages/Sites'
import Dashboard from './pages/Dashboard'
import Accounts from './pages/Accounts'
import Logons from './pages/Logons'
import Processes from './pages/Processes'
import PowerShell from './pages/PowerShell'
import Services from './pages/Services'
import Persistence from './pages/Persistence'
import Network from './pages/Network'
import WebData from './pages/WebData'
import Defender from './pages/Defender'
import SRUM from './pages/SRUM'
import SystemInfo from './pages/SystemInfo'
import EventLog from './pages/EventLog'
import FileSystem from './pages/FileSystem'
import Timeline from './pages/Timeline'
import SearchPage from './pages/SearchPage'

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null)

  useEffect(() => {
    if (api.getPassword()) {
      api.checkAuth().then(setAuthed)
    } else {
      setAuthed(false)
    }
  }, [])

  if (authed === null) {
    return <div className="min-h-screen flex items-center justify-center text-gray-500">Loading...</div>
  }

  if (!authed) {
    return <Login onLogin={() => setAuthed(true)} />
  }

  return (
    <Routes>
      <Route path="/" element={<Sites />} />
      <Route path="/sites/:siteId" element={<Layout />}>
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="accounts" element={<Accounts />} />
        <Route path="logons" element={<Logons />} />
        <Route path="processes" element={<Processes />} />
        <Route path="powershell" element={<PowerShell />} />
        <Route path="services" element={<Services />} />
        <Route path="persistence" element={<Persistence />} />
        <Route path="network" element={<Network />} />
        <Route path="web-data" element={<WebData />} />
        <Route path="defender" element={<Defender />} />
        <Route path="srum" element={<SRUM />} />
        <Route path="system" element={<SystemInfo />} />
        <Route path="eventlog" element={<EventLog />} />
        <Route path="filesystem" element={<FileSystem />} />
        <Route path="timeline" element={<Timeline />} />
        <Route path="search" element={<SearchPage />} />
      </Route>
    </Routes>
  )
}
