import { reactive } from 'vue'

const LS_KEY = 'wildtrace.activeScan'

export const store = reactive({
  scanId: localStorage.getItem(LS_KEY) || '',
  scan: null,          // latest GET /api/scans/{id} payload
  selectedFinding: null
})

export function setActiveScan(id) {
  store.scanId = id
  store.scan = null
  store.selectedFinding = null
  if (id) localStorage.setItem(LS_KEY, id)
  else localStorage.removeItem(LS_KEY)
}
