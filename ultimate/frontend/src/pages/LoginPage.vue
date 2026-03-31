<template>
  <div class="relative min-h-screen flex items-center justify-center overflow-hidden">
    <!-- Digital Rain Canvas -->
    <canvas ref="rainCanvas" class="absolute inset-0 z-0"></canvas>

    <!-- Login Card -->
    <div ref="loginCard" class="relative z-10 w-full max-w-md mx-4 opacity-0">
      <div class="bg-bastion-800/80 backdrop-blur-xl border border-bastion-600/50 rounded-2xl p-8 glow-cyan">
        <div class="text-center mb-8">
          <h1 class="text-2xl font-mono font-bold text-neon-cyan tracking-widest mb-2">4SSH-ULTIMATE</h1>
          <p class="text-sm text-slate-500">Multi-Agent AI Defense System</p>
        </div>

        <form @submit.prevent="handleLogin" class="space-y-5">
          <div>
            <label class="block text-xs font-mono text-slate-500 uppercase tracking-wider mb-1.5">Пользователь</label>
            <input v-model="username" type="text" autocomplete="username"
              class="w-full bg-bastion-900/70 border border-bastion-500/50 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-neon-cyan/50 focus:ring-1 focus:ring-neon-cyan/20 transition-all placeholder-slate-600"
              placeholder="admin" />
          </div>
          <div>
            <label class="block text-xs font-mono text-slate-500 uppercase tracking-wider mb-1.5">Пароль</label>
            <input v-model="password" type="password" autocomplete="current-password"
              class="w-full bg-bastion-900/70 border border-bastion-500/50 rounded-lg px-4 py-2.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-neon-cyan/50 focus:ring-1 focus:ring-neon-cyan/20 transition-all placeholder-slate-600"
              placeholder="••••••••" />
          </div>

          <p v-if="error" class="text-neon-red text-xs font-mono">{{ error }}</p>

          <button type="submit" :disabled="loading"
            class="w-full py-2.5 rounded-lg font-mono font-semibold text-sm transition-all duration-300"
            :class="loading ? 'bg-bastion-600 text-slate-500 cursor-wait' : 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/30 hover:bg-neon-cyan/20 hover:glow-cyan'">
            {{ loading ? 'AUTHENTICATING...' : 'ВОЙТИ В СИСТЕМУ' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth.js'
import anime from 'animejs'

const router = useRouter()
const auth = useAuthStore()

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const rainCanvas = ref(null)
const loginCard = ref(null)
let animFrame = null

async function handleLogin() {
  error.value = ''
  loading.value = true
  try {
    await auth.login(username.value, password.value)
    anime({
      targets: loginCard.value,
      opacity: [1, 0],
      scale: [1, 0.95],
      duration: 400,
      easing: 'easeInQuad',
      complete: () => router.push('/'),
    })
  } catch (e) {
    error.value = e.response?.data?.detail || 'Ошибка авторизации'
    anime({
      targets: loginCard.value,
      translateX: [0, -10, 10, -6, 6, 0],
      duration: 500,
      easing: 'easeInOutQuad',
    })
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  anime({
    targets: loginCard.value,
    opacity: [0, 1],
    translateY: [30, 0],
    duration: 800,
    easing: 'easeOutExpo',
    delay: 300,
  })

  const canvas = rainCanvas.value
  if (!canvas) return
  const ctx = canvas.getContext('2d')
  canvas.width = window.innerWidth
  canvas.height = window.innerHeight

  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZабвгдежзиклмнопрстуфхцчшщэюя0123456789@#$%^&*░▒▓│─┼╔╗╚╝█'.split('')
  const fontSize = 14
  const columns = Math.floor(canvas.width / fontSize)
  const drops = new Array(columns).fill(1)

  function draw() {
    ctx.fillStyle = 'rgba(7, 11, 20, 0.05)'
    ctx.fillRect(0, 0, canvas.width, canvas.height)
    ctx.fillStyle = 'rgba(0, 229, 255, 0.35)'
    ctx.font = `${fontSize}px 'JetBrains Mono', monospace`

    for (let i = 0; i < drops.length; i++) {
      const ch = chars[Math.floor(Math.random() * chars.length)]
      ctx.fillText(ch, i * fontSize, drops[i] * fontSize)
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0
      }
      drops[i]++
    }
    animFrame = requestAnimationFrame(draw)
  }
  draw()

  window.addEventListener('resize', () => {
    canvas.width = window.innerWidth
    canvas.height = window.innerHeight
  })
})

onUnmounted(() => {
  if (animFrame) cancelAnimationFrame(animFrame)
})
</script>
