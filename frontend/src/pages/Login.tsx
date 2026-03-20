import { useState } from 'react'
import { api } from '../lib/api'

interface Props {
  onLogin: () => void
}

export default function Login({ onLogin }: Props) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

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
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="w-80">
        <div className="flex flex-col items-center mb-8">
          <img src="/responseray.png" alt="ResponseRay" className="h-24 mb-4" />
          <p className="text-sm text-gray-400 mt-1">DFIR Investigation Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            value={password}
            onChange={(e) => { setPassword(e.target.value); setError('') }}
            placeholder="Password"
            autoFocus
            className="w-full px-4 py-2.5 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
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
