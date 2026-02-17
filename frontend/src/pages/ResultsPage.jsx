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
