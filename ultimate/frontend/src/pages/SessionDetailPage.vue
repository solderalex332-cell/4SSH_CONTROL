<template>
  <div class="max-w-[1800px] mx-auto p-6 space-y-6">
    <div class="flex items-center gap-4">
      <router-link to="/sessions" class="text-slate-500 hover:text-neon-cyan transition-colors text-sm font-mono">← Сессии</router-link>
      <h1 class="text-lg font-mono font-bold text-neon-cyan tracking-wider">Сессия {{ sessionId?.slice(0, 8) }}</h1>
    </div>

    <!-- Xterm Terminal Mirror -->
    <div class="bg-bastion-900 border border-bastion-600/40 rounded-xl overflow-hidden">
      <div class="flex items-center justify-between px-5 py-2.5 bg-bastion-800/80 border-b border-bastion-600/40">
        <span class="text-xs font-mono text-neon-cyan">TERMINAL MIRROR</span>
        <div class="flex gap-2">
          <button @click="controlSession('KILL')" class="px-3 py-1 rounded text-[10px] font-mono font-bold bg-neon-red/10 text-neon-red border border-neon-red/30 hover:bg-neon-red/20 glow-red transition-all">
            KILL
          </button>
          <button @click="controlSession('FREEZE')" class="px-3 py-1 rounded text-[10px] font-mono font-bold bg-neon-yellow/10 text-neon-yellow border border-neon-yellow/30 hover:bg-neon-yellow/20 transition-all">
            FREEZE
          </button>
        </div>
      </div>
      <div ref="terminalEl" class="h-[400px]"></div>
    </div>

    <!-- Session Logs -->
    <div class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl overflow-hidden">
      <div class="px-5 py-3 border-b border-bastion-600/40">
        <h2 class="text-sm font-mono font-semibold text-slate-300">COMMAND HISTORY</h2>
      </div>
      <div class="max-h-[400px] overflow-y-auto">
        <table class="w-full text-xs font-mono">
          <thead class="sticky top-0 bg-bastion-800">
            <tr class="text-slate-500">
              <th class="px-4 py-2 text-left">Время</th>
              <th class="px-2 py-2 text-left">Вердикт</th>
              <th class="px-2 py-2 text-left">Команда</th>
              <th class="px-2 py-2 text-left">Причина</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="log in sessionLogs" :key="log.id" class="border-b border-bastion-700/30">
              <td class="px-4 py-1.5 text-slate-500 whitespace-nowrap">{{ formatTime(log.created_at) }}</td>
              <td class="px-2 py-1.5">
                <span class="px-2 py-0.5 rounded-full text-[10px] font-bold"
                  :class="verdictClass(log.verdict)">{{ log.verdict?.toUpperCase() }}</span>
              </td>
              <td class="px-2 py-1.5 text-slate-300"><code>{{ log.command }}</code></td>
              <td class="px-2 py-1.5 text-slate-500">{{ log.reason }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import api from '../composables/api.js'
import { useDashboardStore } from '../stores/dashboard.js'

const route = useRoute()
const store = useDashboardStore()
const sessionId = route.params.id
const terminalEl = ref(null)
const sessionLogs = ref([])

let term = null
let fitAddon = null

function formatTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleTimeString('ru-RU')
}

function verdictClass(v) {
  return {
    'bg-green-500/20 text-green-400': v === 'allow',
    'bg-red-500/20 text-red-400': v === 'deny',
    'bg-yellow-500/20 text-yellow-400': v === 'escalate',
  }
}

async function controlSession(action) {
  if (!confirm(`${action} сессию?`)) return
  await store.controlSession(sessionId, action, `Dashboard ${action}`)
}

onMounted(async () => {
  term = new Terminal({
    theme: {
      background: '#070b14',
      foreground: '#e2e8f0',
      cursor: '#00e5ff',
      selectionBackground: '#38bdf833',
      black: '#0c1322',
      red: '#ff1744',
      green: '#39ff14',
      yellow: '#ffd600',
      blue: '#2979ff',
      magenta: '#d500f9',
      cyan: '#00e5ff',
      white: '#e2e8f0',
    },
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: 13,
    cursorBlink: true,
    disableStdin: true,
  })
  fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(terminalEl.value)
  fitAddon.fit()

  term.writeln('\x1b[96m[4SSH-Ultimate] Terminal mirror for session ' + sessionId.slice(0, 8) + '\x1b[0m')
  term.writeln('\x1b[90mRead-only view of command activity\x1b[0m\r\n')

  const { data } = await api.get('/api/logs', { params: { session_id: sessionId, limit: 200 } })
  sessionLogs.value = data.reverse()

  for (const log of sessionLogs.value) {
    const color = log.verdict === 'allow' ? '92' : log.verdict === 'deny' ? '91' : '93'
    term.writeln(`\x1b[90m${formatTime(log.created_at)}\x1b[0m \x1b[${color}m[${log.verdict.toUpperCase()}]\x1b[0m ${log.command}`)
  }
})

onUnmounted(() => {
  if (term) term.dispose()
})
</script>
