<template>
  <div class="max-w-[1800px] mx-auto p-6">
    <div class="flex items-center justify-between mb-6">
      <h1 class="text-lg font-mono font-bold text-neon-cyan tracking-wider">SERVER INVENTORY</h1>
    </div>

    <div class="grid md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-4">
      <div v-for="(server, i) in servers" :key="server.id"
        class="bg-bastion-800/60 border border-bastion-600/40 rounded-xl p-5 hover:border-neon-cyan/30 transition-all"
        :style="{ animationDelay: `${i * 60}ms` }">
        <div class="flex items-center justify-between mb-3">
          <span class="font-mono text-sm font-semibold text-slate-200">{{ server.hostname }}</span>
          <span class="w-2 h-2 rounded-full" :class="server.health_status === 'healthy' ? 'bg-neon-green' : server.health_status === 'unhealthy' ? 'bg-neon-red' : 'bg-slate-500'"></span>
        </div>
        <div class="space-y-1.5 text-xs font-mono text-slate-500">
          <div class="flex justify-between"><span>IP:</span><span class="text-slate-300">{{ server.ip_address }}:{{ server.port }}</span></div>
          <div class="flex justify-between"><span>Тип:</span><span class="text-neon-cyan">{{ server.server_type }}</span></div>
          <div class="flex justify-between"><span>Vendor:</span><span class="text-slate-300">{{ server.vendor || '—' }}</span></div>
        </div>
        <div v-if="server.tags?.length" class="mt-3 flex flex-wrap gap-1">
          <span v-for="tag in server.tags" :key="tag" class="px-2 py-0.5 rounded bg-bastion-700/50 text-[10px] text-slate-400">{{ tag }}</span>
        </div>
      </div>
    </div>

    <div v-if="!servers.length" class="text-center py-20 text-slate-600 font-mono text-sm">
      Нет серверов
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../composables/api.js'

const servers = ref([])

onMounted(async () => {
  const { data } = await api.get('/api/servers')
  servers.value = data
})
</script>
