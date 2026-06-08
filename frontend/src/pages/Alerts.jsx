import { useEffect, useState } from 'react'
import { get, query } from '../api.js'
import { isoTime, relative } from '../format.js'
import SeverityBadge from '../components/SeverityBadge.jsx'

const severities = [
  { label: 'All', value: '' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
]

const ruleLabels = {
  auth_failures: 'Auth failures',
  rate_spike: 'Rate spike',
  suspicious_path: 'Sensitive path',
  suspicious_user_agent: 'User agent',
}

export default function Alerts() {
  const [severity, setSeverity] = useState('')
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    setError(null)
    get(`/api/alerts${query({ severity, limit: 200 })}`)
      .then((d) => {
        if (active) setData(d)
      })
      .catch((err) => {
        if (active) setError(err.message)
      })
    return () => {
      active = false
    }
  }, [severity])

  const alerts = data ? data.alerts : []

  return (
    <div>
      <div className="controls">
        <h1 style={{ margin: 0, flex: 1 }}>Alerts</h1>
        <div className="seg">
          {severities.map((s) => (
            <button
              key={s.value}
              className={s.value === severity ? 'active' : ''}
              onClick={() => setSeverity(s.value)}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {error && <div className="error">Failed to load alerts: {error}</div>}

      <div className="panel" style={{ padding: 0 }}>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Rule</th>
              <th>Source IP</th>
              <th>Detail</th>
              <th style={{ textAlign: 'right' }}>Events</th>
              <th className="nowrap">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td><SeverityBadge severity={a.severity} /></td>
                <td className="nowrap">{ruleLabels[a.rule] || a.rule}</td>
                <td className="mono">{a.ip}</td>
                <td>
                  <div>{a.title}</div>
                  <div className="detail">{a.detail}</div>
                </td>
                <td className="mono" style={{ textAlign: 'right' }}>{a.count}</td>
                <td className="mono nowrap" title={isoTime(a.last_seen)}>{relative(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && !error && (
          <div className="empty">No alerts. Run scripts/seed to generate traffic that triggers detections.</div>
        )}
      </div>
    </div>
  )
}
