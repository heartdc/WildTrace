<template>
  <div v-if="!ready">
    <div class="card muted">
      {{ store.scanId ? '扫描尚未完成。' : '请先在「扫描」页选择一次已完成的扫描。' }}
    </div>
  </div>
  <div v-else>
    <div class="card">
      <h2>扫描结果</h2>
      <div class="row" style="justify-content: space-between; padding: 4px 0">
        <div class="stat"><div class="n">{{ summary.total }}</div><div class="t">lead 总数</div></div>
        <div class="stat"><div class="n acc">{{ summary.high }}</div><div class="t">高危</div></div>
        <div class="stat"><div class="n">{{ summary.medium }}</div><div class="t">中危</div></div>
        <div class="stat"><div class="n">{{ summary.pocs }}</div><div class="t">PoC（置信度≥50）</div></div>
        <div class="stat"><div class="n">{{ summary.conf_70plus ?? '—' }}</div><div class="t">置信度≥70</div></div>
        <div class="stat"><div class="n">{{ scan.elapsed_seconds ?? '—' }}s</div><div class="t">管线耗时</div></div>
      </div>
      <p class="muted" style="margin: 6px 0 0">
        扫描面：C++ {{ surface.cpp }} · C {{ surface.c }} · CJ {{ surface.cj }} ·
        ~{{ surface.lines_est?.toLocaleString() }} 行 · 调用图 {{ surface.call_graph_functions }} 函数
        <span v-if="scan.joern && scan.joern.enabled">
          · Joern：{{ scan.joern.available ? scan.joern.findings + ' 条' : '不可用（已跳过）' }}
        </span>
      </p>
    </div>

    <div class="card">
      <h2>产出物</h2>
      <div class="row" style="align-items: flex-start">
        <table style="max-width: 420px">
          <thead><tr><th>文件</th><th>大小</th></tr></thead>
          <tbody>
            <tr v-for="a in artifacts" :key="a.path" class="clickable"
                :class="{ selected: activeArtifact === a.path }" @click="openArtifact(a.path)">
              <td style="overflow-wrap: anywhere">{{ a.path }}</td>
              <td class="muted">{{ a.bytes }} B</td>
            </tr>
            <tr v-if="!artifacts.length"><td colspan="2" class="muted">无产出文件</td></tr>
          </tbody>
        </table>
        <div style="flex: 1; min-width: 0">
          <pre class="snippet" v-if="artifactContent">{{ artifactContent }}</pre>
          <p v-else class="muted">点击左侧文件预览（findings.md / findings.json / pocs/*.c）。</p>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>lead → 案例骨架</h2>
      <p class="muted" style="margin-top: 0">
        在「分诊」页选中一条 lead 后，在此填入组件路径（如 foundation/communication/ipc）生成
        case.json 骨架（status=lead，next_gate=manual_review）。
      </p>
      <div class="row">
        <template v-if="selectedFinding">
          <span class="chip kept">{{ selectedFinding.pattern }}</span>
          <span class="muted">{{ selectedFinding.file }}:{{ selectedFinding.line }} · 置信度 {{ selectedFinding.confidence }}</span>
        </template>
        <span v-else class="muted">尚未选择 lead（分诊页点击表格行）</span>
      </div>
      <div class="row" style="margin-top: 10px">
        <label>组件路径</label>
        <input type="text" v-model="component" placeholder="foundation/xxx 或 base/xxx" style="min-width: 320px" />
        <button :disabled="!selectedFinding || !component" @click="promote">生成案例骨架</button>
        <span v-if="promoteMsg" :class="promoteOk ? 'muted' : 'error-text'">{{ promoteMsg }}</span>
      </div>
    </div>

    <div class="banner">
      lead ≠ 漏洞：置信度是模式启发式的优先级排序。案例骨架需经人工复核 → 源码等价复现 →
      真库验证（T3 阶梯）后才构成可提交主张。
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import { store } from '../store.js'

const artifacts = ref([])
const activeArtifact = ref('')
const artifactContent = ref('')
const component = ref('')
const promoteMsg = ref('')
const promoteOk = ref(false)

const ready = computed(() => store.scan && store.scan.status === 'done')
const scan = computed(() => store.scan || {})
const summary = computed(() => scan.value.summary || {})
const surface = computed(() => scan.value.surface || {})
const selectedFinding = computed(() => store.selectedFinding)

async function openArtifact(path) {
  activeArtifact.value = path
  artifactContent.value = ''
  try {
    const r = await api.artifact(store.scanId, path)
    artifactContent.value = r.content ?? `（二进制/大文件，共 ${r.bytes ?? '?'} 字节）`
  } catch (e) { artifactContent.value = '加载失败：' + e.message }
}
async function promote() {
  promoteMsg.value = ''
  try {
    const r = await api.promote(store.scanId, {
      finding_id: selectedFinding.value.finding_id,
      component: component.value
    })
    promoteOk.value = true
    promoteMsg.value = '已生成：' + r.case_dir
  } catch (e) { promoteOk.value = false; promoteMsg.value = e.message }
}
onMounted(async () => {
  if (store.scanId && !store.scan) {
    try { store.scan = await api.scan(store.scanId) } catch { store.scan = null }
  }
  if (ready.value) artifacts.value = (await api.artifacts(store.scanId)).artifacts
})
</script>
