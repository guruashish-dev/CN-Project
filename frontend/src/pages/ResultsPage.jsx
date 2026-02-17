import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import FindingCard from '../components/FindingCard'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function ResultsPage() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)

  useEffect(() => {
    fetch(`${API}/scan/${id}`).then((r) => r.json()).then(setScan)
  }, [id])

  const grouped = useMemo(() => {
    if (!scan) return {}
    return scan.findings.reduce((acc, finding) => {
      const key = finding.severity || 'Low'
      acc[key] = acc[key] || []
      acc[key].push(finding)
      return acc
    }, {})
  }, [scan])

  if (!scan) return <p>Loading...</p>

  return (
    <main>
      <h2>Results Dashboard</h2>
      <p>Risk Score: {scan.risk_score?.score}/100 ({scan.risk_score?.label})</p>
      <p>Simulation Requests: {scan.metrics?.simulation?.requests_sent || 0} | Blocked Rate: {scan.metrics?.simulation?.blocked_rate || 0}</p>
      <p>Latency Baseline/Post: {scan.metrics?.baseline_http?.avg_latency_ms || 0} ms → {scan.metrics?.post_scan_http?.avg_latency_ms || 0} ms</p>

      {scan.comparison && (
        <section className="card">
          <h3>Before/After Comparison</h3>
          <p>Baseline Scan: {scan.comparison.baseline_scan_id}</p>
          <p>Risk Delta: {scan.comparison.risk_score_delta}</p>
          <p>Total Findings Delta: {scan.comparison.findings_delta}</p>
          <p>Latency Delta (ms): {scan.comparison.latency_delta_ms}</p>
          <p>Blocked Rate Delta: {scan.comparison.blocked_rate_delta}</p>
        </section>
      )}

      {['Critical', 'High', 'Medium', 'Low'].map((sev) => (
        <section key={sev}>
          <h3>{sev} ({(grouped[sev] || []).length})</h3>
          {(grouped[sev] || []).map((f, idx) => <FindingCard key={`${sev}-${idx}`} finding={f} />)}
        </section>
      ))}
      <div className="actions">
        <a href={`${API}/report/${id}`} target="_blank">Open HTML Report</a>
        <a href={`${API}/report/${id}/pdf`} target="_blank">Download PDF</a>
      </div>
    </main>
  )
}
