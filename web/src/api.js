async function req(path, options = {}) {
  const r = await fetch('/api' + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  })
  if (!r.ok) {
    let detail = r.statusText
    try { detail = (await r.json()).detail || detail } catch { /* keep */ }
    throw new Error(detail)
  }
  return r.json()
}

export const api = {
  meta: () => req('/meta'),
  listScans: () => req('/scans'),
  startScan: (body) => req('/scans', { method: 'POST', body: JSON.stringify(body) }),
  scan: (id) => req('/scans/' + id),
  findings: (id, params = {}) => {
    const q = new URLSearchParams(
      Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
    ).toString()
    return req(`/scans/${id}/findings${q ? '?' + q : ''}`)
  },
  triage: (id, fid, body) =>
    req(`/scans/${id}/findings/${encodeURIComponent(fid)}`, {
      method: 'PATCH', body: JSON.stringify(body)
    }),
  promote: (id, body) =>
    req(`/scans/${id}/promote`, { method: 'POST', body: JSON.stringify(body) }),
  artifacts: (id) => req(`/scans/${id}/artifacts`),
  artifact: (id, path) => req(`/scans/${id}/artifacts/${path}`)
}
