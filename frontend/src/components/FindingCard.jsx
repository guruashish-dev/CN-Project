export default function FindingCard({ finding }) {
  return (
    <details className={`finding ${finding.severity}`}>
      <summary>
        [{finding.severity}] {finding.title} <small>({finding.source_tool})</small>
      </summary>
      <p>{finding.description}</p>
      <p><strong>Evidence:</strong> {finding.evidence}</p>
      <p><strong>Remediation:</strong> {finding.remediation}</p>
    </details>
  )
}
