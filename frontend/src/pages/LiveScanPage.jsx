import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function LiveScanPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)

  useEffect(() => {
    const timer = setInterval(async () => {
      const res = await fetch(`${API}/scan/${id}`)
      const data = await res.json()
      setScan(data)
      if (data.status === 'completed') {
        clearInterval(timer)
        navigate(`/results/${id}`)
      }
    }, 2000)
    return () => clearInterval(timer)
  }, [id, navigate])

  if (!scan) return <p>Loading scan...</p>

  return (
    <main>
      <h2>Live Scan: {scan.target_url}</h2>
      <p>Status: {scan.status} | Tool: {scan.current_tool} | Progress: {scan.progress}% | Simulate: {scan.simulate_attack ? 'on' : 'off'}</p>
      <pre className="terminal">{scan.logs.join('\n')}</pre>
    </main>
  )
}
