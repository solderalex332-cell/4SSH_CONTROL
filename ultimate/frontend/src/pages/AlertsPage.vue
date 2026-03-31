<template>
  <div class="max-w-[1800px] mx-auto p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-lg font-mono font-bold text-neon-red tracking-wider">SECURITY ALERTS</h1>
      <button @click="toggleFilter"
        class="px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
        :class="onlyUnack ? 'bg-neon-red/10 text-neon-red border border-neon-red/30' : 'text-slate-500 hover:text-slate-300'">
        {{ onlyUnack ? 'Только новые' : 'Все алерты' }}
      </button>
    </div>

    <div class="space-y-3">
      <div v-for="alert in store.alerts" :key="alert.id"
        class="bg-bastion-800/60 border rounded-xl p-5 transition-all"
        :class="alert.acknowledged ? 'border-bastion-600/40' : 'border-neon-red/30 glow-red'">
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-3">
            <span class="w-2.5 h-2.5 rounded-full" :class="sevDot(alert.severity)"></span>
            <div>
              <div class="flex items-center gap-2">
                <span class="font-mono text-sm font-semibold" :class="sevClass(alert.severity)">{{ alert.alert_type }}</span>
                <span class="px-2 py-0.5 rounded text-[10px] font-mono"
                  :class="alert.severity === 'critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'">
                  {{ alert.severity.toUpperCase() }}
                </span>
              </div>
              <p class="text-sm text-slate-300 mt-1">{{ alert.title }}</p>
              <p v-if="alert.detail" class="text-xs text-slate-500 mt-1">{{ alert.detail }}</p>
            </div>
          </div>
          <div class="text-right">
            <div class="text-[10px] text-slate-600 font-mono">{{ formatTime(alert.created_at) }}</div>
            <button v-if="!alert.acknowledged" @click="ack(alert.id)"
              class="mt-2 px-3 py-1 rounded text-[10px] font-mono bg-neon-green/10 text-neon-green border border-neon-green/30 hover:bg-neon-green/20 transition-all">
              ACK
            </button>
            <span v-else class="text-[10px] text-slate-600 font-mono">✓</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="!store.alerts.length" class="text-center py-20 text-slate-600 font-mono text-sm">
      Нет алертов
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard.js'

const store = useDashboardStore()
const onlyUnack = ref(false)

function toggleFilter() {
  onlyUnack.value = !onlyUnack.value
  store.fetchAlerts(onlyUnack.value)
}

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('ru-RU')
}

function sevClass(s) {
  return { 'text-green-400': s === 'low', 'text-yellow-400': s === 'medium', 'text-orange-400': s === 'high', 'text-red-400': s === 'critical' }
}
function sevDot(s) {
  return { 'bg-green-400': s === 'low', 'bg-yellow-400': s === 'medium', 'bg-orange-400': s === 'high', 'bg-red-400 animate-pulse': s === 'critical' }
}

async function ack(id) {
  await store.acknowledgeAlert(id)
}

onMounted(() => store.fetchAlerts())
</script>
