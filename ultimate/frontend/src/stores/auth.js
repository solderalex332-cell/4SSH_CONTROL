import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../composables/api.js'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || '')
  const username = ref(localStorage.getItem('username') || '')
  const role = ref(localStorage.getItem('role') || '')
  const isAdmin = ref(localStorage.getItem('isAdmin') === 'true')

  const isAuthenticated = computed(() => !!token.value)

  async function login(user, password) {
    const { data } = await api.post('/api/auth/login', { username: user, password })
    token.value = data.access_token
    username.value = data.username
    role.value = data.role
    isAdmin.value = data.is_admin
    localStorage.setItem('token', data.access_token)
    localStorage.setItem('username', data.username)
    localStorage.setItem('role', data.role)
    localStorage.setItem('isAdmin', String(data.is_admin))
    api.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`
  }

  function logout() {
    token.value = ''
    username.value = ''
    role.value = ''
    isAdmin.value = false
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    localStorage.removeItem('role')
    localStorage.removeItem('isAdmin')
    delete api.defaults.headers.common['Authorization']
  }

  if (token.value) {
    api.defaults.headers.common['Authorization'] = `Bearer ${token.value}`
  }

  return { token, username, role, isAdmin, isAuthenticated, login, logout }
})
