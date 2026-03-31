<template>
  <div class="max-w-[1800px] mx-auto p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-lg font-mono font-bold text-neon-cyan tracking-wider">LIVE SESSIONS</h1>
      <div class="flex gap-2">
        <button v-for="f in filters" :key="f.value"
          @click="activeFilter = f.value"
          class="px-3 py-1 rounded-lg text-xs font-mono transition-all"
          :class="activeFilter === f.value ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/30' : 'text-slate-500 hover:text-slate-300'">
          {{ f.label }}
        </button>
      </div>
    </div>

    <div class="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
      <div v-for="(session, i) in filteredSessions" :key="session.id"
        class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl p-5 hover:border-neon-cyan/30 transition-all cursor-pointer group"
        :style="{ animationDelay: `${i * 60}ms` }"
        class.animate="animate-fade-in"
        @click="$router.push(`/sessions/${session.id}`)">
        <div class="flex items-center justify-between mb-3">
          <span class="font-mono text-sm font-semibold text-slate-200">{{ session.username }}</span>
          <span class="px-2 py-0.5 rounded-full text-[10px] font-bold"
            :class="statusClass(session.status)">{{ session.status.toUpperCase() }}</span>
        </div>
        <div class="space-y-1.5 text-xs font-mono text-slate-500">
          <div class="flex justify-between">
            <span>Профиль:</span>
            <span class="text-neon-cyan">{{ session.server_vendor || session.server_profile }}</span>
          </div>
          <div class="flex justify-between">
            <span>Команд:</span>
            <span class="text-slate-300">{{ session.command_count }}</span>
          </div>
          <div class="flex justify-between">
            <span>Threat Score:</span>
            <span :class="session.threat_score > 5 ? 'text-neon-red' : session.threat_score > 2 ? 'text-neon-yellow' : 'text-neon-green'">
              {{ session.threat_score.toFixed(1) }}
            </span>
          </div>
          <div class="flex justify-between">
            <span>Начало:</span>
            <span>{{ formatTime(session.started_at) }}</span>
          </div>
        </div>

        <div v-if="session.status === 'active'" class="flex gap-2 mt-4 opacity-0 group-hover:opacity-100 transition-opacity">
          <button @click.stop="controlSession(session.id, 'KILL')"
            class="flex-1 py-1.5 rounded-lg text-[10px] font-mono font-bold bg-neon-red/10 text-neon-red border border-neon-red/30 hover:bg-neon-red/20 transition-all">
            KILL
          </button>
          <button @click.stop="controlSession(session.id, 'FREEZE')"
            class="flex-1 py-1.5 rounded-lg text-[10px] font-mono font-bold bg-neon-yellow/10 text-neon-yellow border border-neon-yellow/30 hover:bg-neon-yellow/20 transition-all">
            FREEZE
          </button>
          <button @click.stop="controlSession(session.id, 'WARNING')"
            class="flex-1 py-1.5 rounded-lg text-[10px] font-mono font-bold bg-neon-blue/10 text-neon-blue border border-neon-blue/30 hover:bg-neon-blue/20 transition-all">
            WARN
          </button>
        </div>
      </div>
    </div>

    <div v-if="!filteredSessions.length" class="text-center py-20 text-slate-600 font-mono text-sm">
      Нет сессий
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard.js'

const store = useDashboardStore()
const activeFilter = ref(null)

const filters = [
  { label: 'Все', value: null },
  { label: 'Активные', value: 'active' },
  { label: 'Завершённые', value: 'completed' },
  { label: 'Убитые', value: 'killed' },
]

const filteredSessions = computed(() => {
  if (!activeFilter.value) return store.sessions
  return store.sessions.filter(s => s.status === activeFilter.value)
})

function statusClass(s) {
  return {
    'bg-green-500/20 text-green-400': s === 'active',
    'bg-slate-500/20 text-slate-400': s === 'completed',
    'bg-red-500/20 text-red-400': s === 'killed',
    'bg-yellow-500/20 text-yellow-400': s === 'frozen',
  }
}

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('ru-RU', { hour: '2-digit', minute: '2-digit', second: '2-digit', day: '2-digit', month: '2-digit' })
}

async function controlSession(id, action) {
  if (!confirm(`${action} сессию ${id.slice(0, 8)}?`)) return
  await store.controlSession(id, action, `Manual ${action} by admin`)
  await store.fetchSessions()
}

onMounted(() => store.fetchSessions())
</script>
