<template>
  <div class="max-w-[1800px] mx-auto p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-lg font-mono font-bold text-neon-cyan tracking-wider">AUDIT LOG</h1>
      <div class="flex gap-2">
        <button v-for="f in verdictFilters" :key="f.value" @click="filter = f.value"
          class="px-3 py-1 rounded-lg text-xs font-mono transition-all"
          :class="filter === f.value ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/30' : 'text-slate-500 hover:text-slate-300'">
          {{ f.label }}
        </button>
      </div>
    </div>

    <div class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-xs font-mono">
          <thead class="bg-bastion-800 sticky top-0">
            <tr class="text-slate-500 uppercase tracking-wider">
              <th class="px-4 py-3 text-left">Время</th>
              <th class="px-2 py-3 text-left">Сессия</th>
              <th class="px-2 py-3 text-left">Пользователь</th>
              <th class="px-2 py-3 text-left">Профиль</th>
              <th class="px-2 py-3 text-left">Команда</th>
              <th class="px-2 py-3 text-left">Вердикт</th>
              <th class="px-2 py-3 text-left">Severity</th>
              <th class="px-4 py-3 text-left">Причина</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in store.recentLogs" :key="log.id" class="border-b border-bastion-700/30 hover:bg-bastion-700/20 transition-colors">
              <td class="px-4 py-2 text-slate-500 whitespace-nowrap">{{ formatDateTime(log.created_at) }}</td>
              <td class="px-2 py-2 text-slate-500">{{ log.session_id?.slice(0, 8) }}</td>
              <td class="px-2 py-2 text-slate-300">{{ log.username }}</td>
              <td class="px-2 py-2 text-neon-cyan">{{ log.server_vendor || log.server_profile || 'linux' }}</td>
              <td class="px-2 py-2 text-slate-300 max-w-[250px] truncate"><code class="bg-bastion-900/50 px-1.5 py-0.5 rounded">{{ log.command }}</code></td>
              <td class="px-2 py-2">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold"
                  :class="verdictClass(log.verdict)">{{ log.verdict?.toUpperCase() }}</span>
              </td>
              <td class="px-2 py-2">
                <span class="text-[10px]" :class="sevClass(log.severity)">{{ log.severity }}</span>
              </td>
              <td class="px-4 py-2 text-slate-500 max-w-[350px] truncate">{{ log.reason }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard.js'

const store = useDashboardStore()
const filter = ref(null)

const verdictFilters = [
  { label: 'Все', value: null },
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' },
  { label: 'Escalate', value: 'escalate' },
]

function formatDateTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
function verdictClass(v) {
  return { 'bg-green-500/20 text-green-400': v === 'allow', 'bg-red-500/20 text-red-400': v === 'deny', 'bg-yellow-500/20 text-yellow-400': v === 'escalate' }
}
function sevClass(s) {
  return { 'text-green-400': s === 'low', 'text-yellow-400': s === 'medium', 'text-orange-400': s === 'high', 'text-red-400': s === 'critical' }
}

watch(filter, (v) => store.fetchLogs(200, v))
onMounted(() => store.fetchLogs(200))
</script>
