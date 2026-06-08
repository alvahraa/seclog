export default function SeverityBadge({ severity }) {
  return <span className={`badge sev-${severity}`}>{severity}</span>
}
