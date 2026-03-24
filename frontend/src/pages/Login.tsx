import { useState } from 'react'
import { Sun, Moon } from 'lucide-react'
import { api } from '../lib/api'
import { useTheme } from '../hooks/useTheme'

interface Props {
  onLogin: () => void
}

export default function Login({ onLogin }: Props) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const { isDark, toggle: toggleTheme } = useTheme()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    api.setPassword(password)
    const ok = await api.checkAuth()
    if (ok) {
      onLogin()
    } else {
      setError('Invalid password')
      api.setPassword('')
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 relative">
      <button
        onClick={toggleTheme}
        className="absolute top-4 right-4 p-2 text-gray-400 hover:text-foreground transition-colors rounded-lg hover:bg-gray-800"
        title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      >
        {isDark ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </button>
      <div className="w-80">
        <div className="flex flex-col items-center mb-8">
          <img src="/responseray.png" alt="ResponseRay" className="h-40 mb-4" />
          <p className="text-sm text-gray-400 mt-1">DFIR Investigation Platform</p>
          <span className="text-xs text-foreground font-mono mt-1">v{__APP_VERSION__}</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); setError('') }}
            placeholder="Password"
            autoFocus
            className="w-full px-4 py-2.5 bg-gray-900 border border-gray-700 rounded-lg text-foreground placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          />
          {error && <p className="text-red-400 text-sm">{error}</p>}
          <button
            type="submit"
            className="w-full py-2.5 bg-brand-600 text-white rounded-lg font-medium hover:bg-brand-500 transition-colors"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  )
}
