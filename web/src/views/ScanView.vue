<template>
  <div>
    <div class="card">
      <h2>发起扫描</h2>
      <div class="row">
        <label>源码根</label>
        <input type="text" v-model="form.source_root"
               placeholder="例如 D:/cve_data/oh_dsoftbus 或任意本地 C/C++ 源码树" />
      </div>
      <div class="row" style="margin-top: 10px">
        <label>最低置信度</label>
        <input type="number" v-model.number="form.min_confidence" min="0" max="100" style="width: 90px" />
        <label style="margin-left: 12px">
          <input type="checkbox" v-model="form.joern" /> Joern CPG 层（需 WSL /opt/joern，不可用则自动跳过）
        </label>
        <button @click="start" :disabled="starting || !form.source_root">
          {{ starting ? '提交中…' : '开始扫描' }}
        </button>
        <span v-if="error" class="error-text">{{ error }}</span>
      </div>
      <p class="muted" style="margin-bottom: 0">
        管线：调用图 → P1-P9 模式层 → 跨函数 UAF →（可选）Joern → 报告与 PoC（置信度 ≥50）。
        所有分析仅本地读取，不执行目标代码。
      </p>
    </div>

    <div class="card">
      <h2>扫描历史</h2>
      <table>
        <thead>
          <tr>
            <th>扫描</th><th>状态</th><th>源码根</th><th>发现</th><th>PoC</th>
            <th>耗时</th><th>时间</th><th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in scans" :key="s.id" class="clickable"
              :class="{ selected: s.id === store.scanId }" @click="pick(s)">
            <td>{{ s.id }}</td>
            <td><span class="chip" :class="s.status">{{ statusText(s.status) }}</span></td>
            <td class="muted">{{ s.source_root }}</td>
            <td v-if="s.summary">{{ s.summary.total }}（高 {{ s.summary.high }} / 中 {{ s.summary.medium }}）</td>
            <td v-else class="muted">{{ lastPhase(s) }}</td>
            <td>{{ s.summary ? s.summary.pocs : '—' }}</td>
            <td>{{ s.elapsed || (s.summary && s.elapsed_seconds) || '—' }}</td>
            <td class="muted">{{ (s.created_at || '').replace('T', ' ') }}</td>
            <td><button class="ghost" v-if="s.status === 'done'" @click.stop="pick(s)">设为当前</button></td>
          </tr>
          <tr v-if="!scans.length"><td colspan="8" class="muted">暂无扫描记录</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { api } from '../api.js'
import { store, setActiveScan } from '../store.js'

const form = reactive({
  source_root: localStorage.getItem('wildtrace.srcRoot') || '',
  min_confidence: 0,
  joern: false
})
const starting = ref(false)
const error = ref('')
const scans = ref([])
let timer = null

const statusText = (s) => ({ queued: '排队', running: '运行中', done: '完成', error: '出错' }[s] || s)
const lastPhase = (s) => {
  const p = s.progress && s.progress[s.progress.length - 1]
  return p ? `${p.phase}${p.detail ? ' · ' + p.detail : ''} · ${p.elapsed}s` : '…'
}

async function refresh() {
  try { scans.value = (await api.listScans()).scans } catch { /* backend away */ }
}
async function start() {
  starting.value = true; error.value = ''
  try {
    localStorage.setItem('wildtrace.srcRoot', form.source_root)
    const r = await api.startScan({ ...form })
    setActiveScan(r.scan_id)
    await refresh()
  } catch (e) { error.value = e.message } finally { starting.value = false }
}
function pick(s) {
  if (s.status === 'done') setActiveScan(s.id)
}

onMounted(() => { refresh(); timer = setInterval(refresh, 2000) })
onUnmounted(() => clearInterval(timer))
</script>
