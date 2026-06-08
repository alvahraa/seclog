const numberFormat = new Intl.NumberFormat('en-US')

export function num(n) {
  return numberFormat.format(n ?? 0)
}

// isoTime renders a timestamp as "YYYY-MM-DD HH:MM:SSZ" in UTC.
export function isoTime(t) {
  const d = new Date(t)
  if (Number.isNaN(d.getTime())) return String(t)
  return d.toISOString().slice(0, 19).replace('T', ' ') + 'Z'
}

// clockTime renders just HH:MM for chart axes.
export function clockTime(t) {
  const d = new Date(t)
  if (Number.isNaN(d.getTime())) return ''
  return d.toISOString().slice(11, 16)
}

export function relative(t) {
  const ms = new Date(t).getTime()
  if (Number.isNaN(ms)) return ''
  const s = Math.round((Date.now() - ms) / 1000)
  if (s < 0) return 'just now'
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.round(h / 24)
  return `${d}d ago`
}
