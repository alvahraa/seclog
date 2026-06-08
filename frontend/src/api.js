async function request(path, options) {
  const res = await fetch(path, options)
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body && body.error) detail = body.error
    } catch {
      // response had no JSON body
    }
    throw new Error(detail)
  }
  return res.json()
}

export function get(path) {
  return request(path)
}

export function post(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

// query builds a querystring from a params object, dropping empty values.
export function query(params) {
  const usp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== '' && v !== null && v !== undefined) usp.set(k, v)
  }
  const s = usp.toString()
  return s ? `?${s}` : ''
}
