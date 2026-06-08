import { useEffect, useState } from 'react'
import { get, query } from '../api.js'
import { num, isoTime, relative } from '../format.js'
import StatusPill from '../components/StatusPill.jsx'

const limit = 50

const emptyFilters = { ip: '', status: '', path: '' }

export default function Events() {
  const [form, setForm] = useState(emptyFilters)
  const [filters, setFilters] = useState(emptyFilters)
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    setError(null)
    const qs = query({ ...filters, limit, offset })
    get(`/api/events${qs}`)
      .then((d) => {
        if (active) setData(d)
      })
      .catch((err) => {
        if (active) setError(err.message)
      })
    return () => {
      active = false
    }
  }, [filters, offset])

  function apply(e) {
    e.preventDefault()
    setOffset(0)
    setFilters(form)
  }

  function reset() {
    setForm(emptyFilters)
    setFilters(emptyFilters)
    setOffset(0)
  }

  const events = data ? data.events : []
  const total = data ? data.total : 0
  const start = total === 0 ? 0 : offset + 1
  const end = Math.min(offset + limit, total)

  return (
    <div>
      <h1>Events</h1>

      <form className="controls" onSubmit={apply}>
        <input
          placeholder="IP"
          value={form.ip}
          onChange={(e) => setForm({ ...form, ip: e.target.value })}
          style={{ width: 150 }}
        />
        <input
          placeholder="Status"
          value={form.status}
          onChange={(e) => setForm({ ...form, status: e.target.value })}
          style={{ width: 90 }}
        />
        <input
          placeholder="Path contains"
          value={form.path}
          onChange={(e) => setForm({ ...form, path: e.target.value })}
          style={{ width: 220 }}
        />
        <button type="submit" className="btn primary">Apply</button>
        <button type="button" className="btn" onClick={reset}>Reset</button>
      </form>

      {error && <div className="error">Failed to load events: {error}</div>}

      <div className="panel" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th className="nowrap">Time (UTC)</th>
              <th>IP</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>User agent</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td className="mono nowrap" title={relative(ev.time)}>{isoTime(ev.time)}</td>
                <td className="mono">{ev.ip || <span className="muted">unparsed</span>}</td>
                <td className="mono">{ev.method}</td>
                <td className="mono truncate" title={ev.path}>{ev.path}</td>
                <td>{ev.status ? <StatusPill status={ev.status} /> : <span className="muted">-</span>}</td>
                <td className="truncate muted" title={ev.user_agent}>{ev.user_agent}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && !error && (
          <div className="empty">No events match. Run scripts/seed to load demo data.</div>
        )}
      </div>

      <div className="pager">
        <button className="btn" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
          Previous
        </button>
        <button className="btn" disabled={end >= total} onClick={() => setOffset(offset + limit)}>
          Next
        </button>
        <span>
          {num(start)}&ndash;{num(end)} of {num(total)}
        </span>
      </div>
    </div>
  )
}
