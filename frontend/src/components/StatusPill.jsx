export default function StatusPill({ status }) {
  const cls =
    status >= 500 ? 's-5xx' : status >= 400 ? 's-4xx' : status >= 300 ? 's-3xx' : 's-2xx'
  return <span className={`pill ${cls}`}>{status}</span>
}
