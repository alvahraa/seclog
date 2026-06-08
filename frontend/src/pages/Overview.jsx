import { useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from 'recharts'
import { get, query } from '../api.js'
import { num, clockTime, isoTime } from '../format.js'
import StatCard from '../components/StatCard.jsx'

const windows = [
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '24h', seconds: 86400 },
]

function statusColor(status) {
  if (status >= 500) return '#d8624a'
  if (status >= 400) return '#cf9a3b'
  if (status >= 300) return '#4f9cd6'
  return '#4caf72'
}

const chartGrid = '#262d38'
const axisColor = '#8a94a3'

export default function Overview() {
  const [windowSec, setWindowSec] = useState(21600)
  const [stats, setStats] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    setError(null)
    get(`/api/stats${query({ window: windowSec })}`)
      .then((data) => {
        if (active) setStats(data)
      })
      .catch((err) => {
        if (active) setError(err.message)
      })
    return () => {
      active = false
    }
  }, [windowSec])

  if (error) return <div className="error">Failed to load stats: {error}</div>
  if (!stats) return <div className="empty">Loading.</div>

  const errors = (stats.statuses || []).reduce(
    (acc, s) => (s.status >= 400 ? acc + s.count : acc),
    0,
  )
  const errorRate = stats.total_events ? (errors / stats.total_events) * 100 : 0
  const series = (stats.series || []).map((p) => ({ t: p.time, count: p.count }))
  const statuses = (stats.statuses || []).map((s) => ({ status: String(s.status), count: s.count, code: s.status }))
  const topIPs = stats.top_ips || []

  return (
    <div>
      <div className="controls">
        <h1 style={{ margin: 0, flex: 1 }}>Overview</h1>
        <div className="seg">
          {windows.map((w) => (
            <button
              key={w.seconds}
              className={w.seconds === windowSec ? 'active' : ''}
              onClick={() => setWindowSec(w.seconds)}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <div className="cards">
        <StatCard label="Requests" value={num(stats.total_events)} />
        <StatCard label="Unique source IPs" value={num(stats.unique_ips)} />
        <StatCard label="Alerts" value={num(stats.total_alerts)} />
        <StatCard label="4xx/5xx rate" value={`${errorRate.toFixed(1)}%`} />
      </div>

      <div className="panel grow" style={{ marginBottom: 16 }}>
        <h2>Requests per bucket</h2>
        {stats.total_events === 0 ? (
          <div className="empty">No events yet. Run scripts/seed to load demo data.</div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={series} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
              <CartesianGrid stroke={chartGrid} vertical={false} />
              <XAxis dataKey="t" tickFormatter={clockTime} stroke={axisColor} fontSize={12} minTickGap={40} />
              <YAxis stroke={axisColor} fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #262d38', fontSize: 12 }}
                labelFormatter={isoTime}
                labelStyle={{ color: '#8a94a3' }}
              />
              <Area type="monotone" dataKey="count" stroke="#4f9cd6" fill="rgba(79,156,214,0.15)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="row">
        <div className="panel grow">
          <h2>Status codes</h2>
          {statuses.length === 0 ? (
            <div className="empty">No data.</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={statuses} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                <CartesianGrid stroke={chartGrid} vertical={false} />
                <XAxis dataKey="status" stroke={axisColor} fontSize={12} />
                <YAxis stroke={axisColor} fontSize={12} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  contentStyle={{ background: '#161b22', border: '1px solid #262d38', fontSize: 12 }}
                />
                <Bar dataKey="count">
                  {statuses.map((s) => (
                    <Cell key={s.status} fill={statusColor(s.code)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="panel grow">
          <h2>Top source IPs</h2>
          {topIPs.length === 0 ? (
            <div className="empty">No data.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th style={{ textAlign: 'right' }}>Requests</th>
                </tr>
              </thead>
              <tbody>
                {topIPs.map((ip) => (
                  <tr key={ip.ip}>
                    <td className="mono">{ip.ip}</td>
                    <td className="mono" style={{ textAlign: 'right' }}>{num(ip.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
