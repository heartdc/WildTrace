<template>
  <div v-if="!ready">
    <div class="card muted">
      {{ store.scanId ? '扫描尚未完成，状态：' + (store.scan && store.scan.status) : '请先在「扫描」页选择一次已完成的扫描。' }}
    </div>
  </div>
  <div v-else>
    <div class="card">
      <h2>分诊 · {{ total }} 条 lead</h2>
      <div class="row">
        <select v-model="filters.severity">
          <option value="">全部严重度</option><option>high</option><option>medium</option>
        </select>
        <select v-model="filters.status">
          <option value="">全部状态</option>
          <option v-for="s in statuses" :key="s" :value="s">{{ statusText(s) }}</option>
        </select>
        <input type="number" v-model.number="filters.min_conf" min="0" max="100" style="width: 110px" title="最低置信度" />
        <input type="text" v-model="filters.pattern" placeholder="模式，如 P6" style="min-width: 130px" />
        <input type="text" v-model="filters.cwe" placeholder="CWE" style="min-width: 110px" />
        <input type="text" v-model="filters.q" placeholder="文件/函数/描述搜索" style="min-width: 200px" />
        <button class="ghost" @click="reset">重置</button>
      </div>
      <table style="margin-top: 12px">
        <thead>
          <tr>
            <th>置信度</th><th>模式</th><th>严重度</th><th>位置</th><th>函数</th>
            <th>CWE</th><th>状态</th><th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in items" :key="f.finding_id" class="clickable"
              :class="{ selected: selected && selected.finding_id === f.finding_id }"
              @click="select(f)">
            <td><b :style="{ color: f.confidence >= 70 ? 'var(--accent)' : 'inherit' }">{{ f.confidence }}</b></td>
            <td>{{ f.pattern }}</td>
            <td><span class="chip" :class="f.severity">{{ f.severity }}</span></td>
            <td class="muted" style="max-width: 260px; overflow-wrap: anywhere">{{ shortPath(f.file) }}:{{ f.line }}</td>
            <td>{{ f.function }}</td>
            <td>{{ f.cwe }}</td>
            <td><span class="chip" :class="f.triage.status">{{ statusText(f.triage.status) }}</span></td>
            <td @click.stop>
              <button class="ghost" @click="mark(f, 'kept')">保留</button>
              <button class="warn" @click="mark(f, 'false_positive')">误报</button>
            </td>
          </tr>
          <tr v-if="!items.length"><td colspan="8" class="muted">无匹配条目</td></tr>
        </tbody>
      </table>
      <div class="pager">
        <span class="muted">{{ page }} / {{ pageCount || 1 }} 页 · 共 {{ total }} 条</span>
        <button class="ghost" :disabled="page <= 1" @click="page--; load()">上一页</button>
        <button class="ghost" :disabled="page >= pageCount" @click="page++; load()">下一页</button>
      </div>
    </div>

    <div class="card drawer" v-if="selected">
      <h2>lead 详情</h2>
      <div class="row" style="gap: 18px">
        <span><b>{{ selected.pattern }}</b></span>
        <span class="muted">{{ selected.file }}:{{ selected.line }} · {{ selected.function }}</span>
        <span class="chip" :class="selected.severity">{{ selected.severity }}</span>
        <span class="chip" :class="selected.triage.status">{{ statusText(selected.triage.status) }}</span>
      </div>
      <p style="margin: 10px 0 6px">{{ selected.description }}</p>
      <h3>评分因子</h3>
      <p class="muted" style="margin: 4px 0">{{ selected.confidence_factors || '—' }}</p>
      <h3>触发提示</h3>
      <p class="muted" style="margin: 4px 0">{{ selected.trigger_hint || '—' }}</p>
      <h3>可达性</h3>
      <p class="muted" style="margin: 4px 0">{{ selected.reachability || 'n/a' }}</p>
      <h3>源码片段</h3>
      <pre class="snippet">{{ selected.source_snippet || '（无片段）' }}</pre>
      <h3>复核备注</h3>
      <div class="row">
        <textarea v-model="note" rows="2" style="flex: 1"></textarea>
        <button @click="saveNote">保存备注</button>
      </div>
      <h3>LLM PoC 生成</h3>
      <div class="row">
        <button :disabled="llmBusy || !store.llm.key_configured" @click="genPoc">
          {{ llmBusy ? '生成中…（最长 60s）' : 'LLM 生成 PoC' }}
        </button>
        <select v-model="llmProvider">
          <option value="https://api.z.ai/api/anthropic">z.ai（国际站）</option>
          <option value="https://open.bigmodel.cn/api/anthropic">open.bigmodel.cn（国内站）</option>
        </select>
        <select v-model="llmModel" :disabled="llmBusy">
          <option>glm-5.3</option>
        </select>
        <span v-if="!store.llm.key_configured" class="error-text">
          未配置 API 密钥：设置环境变量 OSLOVELACE_API_KEY 后重启服务（见 docs/engineering/LLM_LOCAL_OPERATOR.md）
        </span>
      </div>
      <template v-if="llmResult">
        <div class="row" style="margin-top: 8px">
          <span class="chip" :class="llmResult.result.validated ? 'kept' : 'false_positive'">
            {{ llmResult.result.validated ? '通过验证' : '未通过：' + (llmResult.result.validation_note || llmResult.result.error || '') }}
          </span>
          <span class="muted">模型 {{ llmResult.result.model }} · sha256 {{ (llmResult.result.sha256 || '').slice(0, 12) }}…</span>
          <span v-if="llmResult.result.artifact" class="muted">已落盘 {{ llmResult.result.artifact }}</span>
        </div>
        <pre class="snippet" v-if="llmResult.code">{{ llmResult.code }}</pre>
        <p class="muted" style="margin: 6px 0 0">
          模型输出是 PoC 起点（model_invoked=true 已留痕 llm_attempts/），不是漏洞结论。
        </p>
      </template>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { api } from '../api.js'
import { store } from '../store.js'

const statuses = ['open', 'kept', 'false_positive', 'promoted']
const statusText = (s) => ({ open: '未处理', kept: '保留', false_positive: '误报', promoted: '已建案' }[s] || s)

const filters = reactive({ severity: '', status: '', pattern: '', cwe: '', q: '', min_conf: 0 })
const items = ref([])
const total = ref(0)
const page = ref(1)
const size = 50
const selected = ref(null)
const note = ref('')
const llmBusy = ref(false)
const llmModel = ref('glm-5.3')
const llmProvider = ref('https://api.z.ai/api/anthropic')
const llmResult = ref(null)
const ready = computed(() => store.scan && store.scan.status === 'done')
const pageCount = computed(() => Math.ceil(total.value / size) || 1)

const shortPath = (p) => String(p).split(/[\\/]/).slice(-2).join('/')

async function load() {
  if (!ready.value) return
  const r = await api.findings(store.scanId, { ...filters, page: page.value, size })
  total.value = r.total
  items.value = r.items
}
function select(f) {
  selected.value = f
  note.value = f.triage.note || ''
  store.selectedFinding = f
}
async function mark(f, status) {
  try {
    const rec = await api.triage(store.scanId, f.finding_id,
                                 { status, note: f.triage.note || '' })
    f.triage = rec
    if (selected.value && selected.value.finding_id === f.finding_id) selected.value.triage = rec
  } catch (e) { alert(e.message) }
}
async function saveNote() {
  if (!selected.value) return
  const rec = await api.triage(store.scanId, selected.value.finding_id,
                               { status: selected.value.triage.status, note: note.value })
  selected.value.triage = rec
}
async function genPoc() {
  if (!selected.value || llmBusy.value) return
  llmBusy.value = true
  llmResult.value = null
  try {
    llmResult.value = await api.llmPoc(store.scanId, selected.value.finding_id,
                                       { model: llmModel.value, base_url: llmProvider.value })
  } catch (e) {
    llmResult.value = { result: { validated: false, error: e.message } }
  } finally { llmBusy.value = false }
}
function reset() {
  Object.assign(filters, { severity: '', status: '', pattern: '', cwe: '', q: '', min_conf: 0 })
  page.value = 1
}
watch(filters, () => { page.value = 1; load() })
watch(() => store.scanId, async () => {
  selected.value = null
  if (store.scanId) { store.scan = await api.scan(store.scanId) }
  load()
})
onMounted(async () => {
  if (store.scanId && !store.scan) {
    try { store.scan = await api.scan(store.scanId) } catch { store.scan = null }
  }
  load()
})
</script>
