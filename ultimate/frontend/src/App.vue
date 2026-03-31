<template>
  <div class="min-h-screen">
    <nav v-if="auth.isAuthenticated" class="fixed top-0 left-0 right-0 z-50 bg-bastion-800/90 backdrop-blur-md border-b border-bastion-600/50">
      <div class="max-w-[1800px] mx-auto px-6 h-14 flex items-center justify-between">
        <div class="flex items-center gap-6">
          <router-link to="/" class="flex items-center gap-2 text-neon-cyan font-mono font-bold text-lg tracking-wider">
            <span class="inline-block w-2 h-2 rounded-full bg-neon-cyan animate-pulse"></span>
            4SSH-ULTIMATE
          </router-link>
          <div class="flex gap-1">
            <router-link v-for="link in navLinks" :key="link.to" :to="link.to"
              class="px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200"
              :class="$route.path === link.to ? 'bg-neon-cyan/10 text-neon-cyan' : 'text-slate-400 hover:text-slate-200 hover:bg-bastion-700'">
              {{ link.label }}
            </router-link>
          </div>
        </div>
        <div class="flex items-center gap-4">
          <span class="inline-flex items-center gap-1.5 text-xs font-mono">
            <span class="w-1.5 h-1.5 rounded-full" :class="wsConnected ? 'bg-neon-green' : 'bg-neon-red animate-pulse'"></span>
            {{ wsConnected ? 'LIVE' : 'OFFLINE' }}
          </span>
          <span class="text-xs text-slate-500 font-mono">{{ auth.username }} / {{ auth.role }}</span>
          <button @click="handleLogout" class="text-xs text-slate-500 hover:text-neon-red transition-colors">Выход</button>
        </div>
      </div>
    </nav>
    <main :class="auth.isAuthenticated ? 'pt-14' : ''">
      <router-view v-slot="{ Component }">
        <transition name="page" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from './stores/auth.js'
import { useWebSocket } from './composables/useWebSocket.js'

const auth = useAuthStore()
const router = useRouter()
const { connected: wsConnected } = useWebSocket()

const navLinks = [
  { to: '/', label: 'Дашборд' },
  { to: '/sessions', label: 'Сессии' },
  { to: '/logs', label: 'Логи' },
  { to: '/servers', label: 'Серверы' },
  { to: '/alerts', label: 'Алерты' },
]

function handleLogout() {
  auth.logout()
  router.push('/login')
}
</script>

<style>
.page-enter-active, .page-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.page-enter-from {
  opacity: 0;
  transform: translateY(8px);
}
.page-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
