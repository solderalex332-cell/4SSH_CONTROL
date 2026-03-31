<template>
  <div class="max-w-[1800px] mx-auto p-6 space-y-6">
    <!-- Stats Grid -->
    <div ref="statsGrid" class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
      <StatCard v-for="(card, i) in statCards" :key="card.label" :label="card.label" :value="card.value" :color="card.color" :style="{ animationDelay: `${i * 80}ms` }" class="animate-fade-in" />
    </div>

    <div class="grid lg:grid-cols-3 gap-6">
      <!-- Live Log Stream -->
      <div class="lg:col-span-2 bg-bastion-800/60 border border-bastion-600/40 rounded-xl overflow-hidden">
        <div class="flex items-center justify-between px-5 py-3 border-b border-bastion-600/40">
          <h2 class="text-sm font-mono font-semibold text-neon-cyan tracking-wider">LIVE COMMAND STREAM</h2>
          <span class="text-xs font-mono text-slate-500">{{ store.recentLogs.length }} записей</span>
        </div>
        <div class="max-h-[500px] overflow-y-auto">
          <table class="w-full text-xs font-mono">
            <thead class="sticky top-0 bg-bastion-800">
              <tr class="text-slate-500 uppercase tracking-wider">
                <th class="px-4 py-2 text-left w-36">Время</th>
                <th class="px-2 py-2 text-left w-20">Вердикт</th>
                <th class="px-2 py-2 text-left w-16">Sev</th>
                <th class="px-2 py-2 text-left">Команда</th>
                <th class="px-4 py-2 text-left">Причина</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="log in store.recentLogs.slice(0, 100)" :key="log.id"
                class="border-b border-bastion-700/30 hover:bg-bastion-700/20 transition-colors log-row">
                <td class="px-4 py-1.5 text-slate-500 whitespace-nowrap">{{ formatTime(log.created_at) }}</td>
                <td class="px-2 py-1.5">
                  <span class="inline-block px-2 py-0.5 rounded-full text-[10px] font-bold"
                    :class="verdictClass(log.verdict)">{{ log.verdict?.toUpperCase() }}</span>
                </td>
                <td class="px-2 py-1.5">
                  <span class="text-[10px]" :class="sevClass(log.severity)">{{ log.severity }}</span>
                </td>
                <td class="px-2 py-1.5 text-slate-300 truncate max-w-[250px]">
                  <code class="bg-bastion-900/50 px-1.5 py-0.5 rounded">{{ log.command }}</code>
                </td>
                <td class="px-4 py-1.5 text-slate-500 truncate max-w-[300px]">{{ log.reason }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="!store.recentLogs.length" class="text-center py-12 text-slate-600 text-sm">
            Ожидание данных...
          </div>
        </div>
      </div>

      <!-- Security Radar (Alerts + VT) -->
      <div class="space-y-6">
        <!-- Alerts Panel -->
        <div class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl overflow-hidden">
          <div class="flex items-center justify-between px-5 py-3 border-b border-bastion-600/40">
            <h2 class="text-sm font-mono font-semibold text-neon-red tracking-wider">SECURITY RADAR</h2>
            <span v-if="unackCount" class="px-2 py-0.5 rounded-full bg-neon-red/20 text-neon-red text-[10px] font-bold animate-pulse">
              {{ unackCount }} NEW
            </span>
          </div>
          <div class="max-h-[240px] overflow-y-auto">
            <div v-for="alert in store.alerts.slice(0, 20)" :key="alert.id"
              class="px-4 py-2.5 border-b border-bastion-700/30 hover:bg-bastion-700/20 transition-colors"
              :class="!alert.acknowledged ? 'border-l-2 border-l-neon-red' : ''">
              <div class="flex items-center gap-2 mb-1">
                <span class="w-1.5 h-1.5 rounded-full" :class="sevDot(alert.severity)"></span>
                <span class="text-xs font-mono font-semibold" :class="sevClass(alert.severity)">{{ alert.alert_type }}</span>
                <span class="ml-auto text-[10px] text-slate-600">{{ formatTime(alert.created_at) }}</span>
              </div>
              <p class="text-xs text-slate-400 truncate">{{ alert.title }}</p>
            </div>
            <div v-if="!store.alerts.length" class="text-center py-8 text-slate-600 text-xs">
              Нет алертов
            </div>
          </div>
        </div>

        <!-- VT Scans Panel -->
        <div class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl overflow-hidden">
          <div class="px-5 py-3 border-b border-bastion-600/40">
            <h2 class="text-sm font-mono font-semibold text-neon-purple tracking-wider">VIRUSTOTAL SCANS</h2>
          </div>
          <div class="max-h-[200px] overflow-y-auto">
            <div v-for="scan in store.vtScans.slice(0, 10)" :key="scan.id"
              class="px-4 py-2 border-b border-bastion-700/30 flex items-center gap-3">
              <span class="w-2 h-2 rounded-full" :class="{
                'bg-neon-green': scan.scan_status === 'clean',
                'bg-neon-red animate-pulse': scan.scan_status === 'malicious',
                'bg-neon-yellow': scan.scan_status === 'suspicious',
                'bg-slate-500': scan.scan_status === 'pending',
              }"></span>
              <span class="text-xs font-mono text-slate-300 truncate flex-1">{{ scan.file_name }}</span>
              <span class="text-[10px] font-mono" :class="scan.scan_status === 'malicious' ? 'text-neon-red' : 'text-slate-500'">
                {{ scan.detection_count }}/{{ scan.total_engines }}
              </span>
            </div>
            <div v-if="!store.vtScans.length" class="text-center py-8 text-slate-600 text-xs">
              Нет сканов
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard.js'
import StatCard from '../components/StatCard.vue'

const store = useDashboardStore()

const statCards = computed(() => [
  { label: 'Сессий', value: store.stats.total_sessions ?? 0, color: 'cyan' },
  { label: 'Активных', value: store.stats.active_sessions ?? 0, color: 'green' },
  { label: 'Команд', value: store.stats.total_commands ?? 0, color: 'cyan' },
  { label: 'Заблокировано', value: store.stats.total_denied ?? 0, color: 'red' },
  { label: 'Эскалаций', value: store.stats.total_escalated ?? 0, color: 'yellow' },
  { label: 'Алертов', value: store.stats.unack_alerts ?? 0, color: 'red' },
  { label: 'VT Threats', value: store.stats.vt_malicious ?? 0, color: 'purple' },
])

const unackCount = computed(() => store.stats.unack_alerts ?? 0)

function formatTime(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function verdictClass(v) {
  return {
    'bg-green-500/20 text-green-400': v === 'allow',
    'bg-red-500/20 text-red-400': v === 'deny',
    'bg-yellow-500/20 text-yellow-400': v === 'escalate',
  }
}

function sevClass(s) {
  return {
    'text-green-400': s === 'low',
    'text-yellow-400': s === 'medium',
    'text-orange-400': s === 'high',
    'text-red-400': s === 'critical',
  }
}

function sevDot(s) {
  return {
    'bg-green-400': s === 'low',
    'bg-yellow-400': s === 'medium',
    'bg-orange-400': s === 'high',
    'bg-red-400 animate-pulse': s === 'critical',
  }
}

onMounted(async () => {
  await Promise.all([
    store.fetchStats(),
    store.fetchLogs(),
    store.fetchAlerts(),
    store.fetchVTScans(),
  ])
  setInterval(() => store.fetchStats(), 10000)
})
</script>

<style scoped>
@keyframes fade-in {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}
.animate-fade-in {
  animation: fade-in 0.5s ease-out both;
}
.log-row {
  animation: fade-in 0.3s ease-out;
}
</style>
