import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function HomePage() {
  const [url, setUrl] = useState('http://testphp.vulnweb.com')
  const [mode, setMode] = useState('docker')
  const [demo, setDemo] = useState(true)
  const [simulateAttack, setSimulateAttack] = useState(false)
  const [compareToScanId, setCompareToScanId] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const submit = async (e) => {
    e.preventDefault()
    setLoading(true)
    const res = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url,
        mode,
        demo_safe_target: demo,
        simulate_attack: simulateAttack,
        compare_to_scan_id: compareToScanId.trim(),
      }),
    })
    const data = await res.json()
    setLoading(false)
    navigate(`/scan/${data.scan_id}`)
  }

  return (
    <main>
      <h2>Automated Vulnerability Assessment & Reporting</h2>
      <form onSubmit={submit} className="card">
        <label>Target URL</label>
        <input value={url} onChange={(e) => setUrl(e.target.value)} required />

        <label>Execution Mode</label>
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="docker">Docker (Preferred)</option>
          <option value="wsl">WSL Kali</option>
        </select>

        <label className="check">
          <input type="checkbox" checked={demo} onChange={(e) => setDemo(e.target.checked)} />
          Demo Safe Target (testphp.vulnweb.com)
        </label>

        <label className="check">
          <input type="checkbox" checked={simulateAttack} onChange={(e) => setSimulateAttack(e.target.checked)} />
          Simulate Attack (safe query probes only)
        </label>

        <label>Compare Against Previous Scan ID (optional)</label>
        <input
          placeholder="paste baseline scan id"
          value={compareToScanId}
          onChange={(e) => setCompareToScanId(e.target.value)}
        />

        <button disabled={loading}>{loading ? 'Starting...' : 'Start Scan'}</button>
      </form>
    </main>
  )
}
