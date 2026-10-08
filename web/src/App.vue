<template>
  <div>
    <header class="header">
      <div class="brand">
        <span>WildTrace 工作台</span>
        <span class="boundary">- - -</span>
        <span style="font-weight: 400; font-size: 13px; color: #93a6bd">仓颉 FFI 边界 · 本地挖掘闭环</span>
      </div>
      <nav class="nav">
        <router-link to="/scan">扫描</router-link>
        <router-link to="/triage">分诊</router-link>
        <router-link to="/output">产出</router-link>
      </nav>
      <div class="badges">
        <span class="badge" v-for="b in badges" :key="b">{{ b }}</span>
      </div>
    </header>
    <main>
      <div class="banner" v-if="scanId">
        当前扫描：<b>{{ scanId }}</b>
        <span v-if="scan && scan.status" class="muted">（{{ scan.status }}{{ scan.elapsed ? ' · ' + scan.elapsed + 's' : '' }}）</span>
      </div>
      <div class="banner" v-else>尚未选择扫描：先在「扫描」页发起或从历史中选择一次扫描。</div>
      <router-view />
    </main>
  </div>
</template>

<script setup>
import { onMounted, ref, computed } from 'vue'
import { api } from './api.js'
import { store } from './store.js'

const badges = ref(['local_only', 'no_execution', 'no_network'])
const meta = ref(null)
const scanId = computed(() => store.scanId)
const scan = computed(() => store.scan)

onMounted(async () => {
  try {
    meta.value = await api.meta()
    if (meta.value.safety) badges.value = Object.keys(meta.value.safety)
  } catch { /* backend not running — pages will surface errors */ }
  try { store.llm = await api.llmStatus() } catch { /* keep default */ }
})
</script>
