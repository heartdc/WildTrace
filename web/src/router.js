import { createRouter, createWebHashHistory } from 'vue-router'
import ScanView from './views/ScanView.vue'
import TriageView from './views/TriageView.vue'
import OutputView from './views/OutputView.vue'

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', redirect: '/scan' },
    { path: '/scan', component: ScanView },
    { path: '/triage', component: TriageView },
    { path: '/output', component: OutputView }
  ]
})
