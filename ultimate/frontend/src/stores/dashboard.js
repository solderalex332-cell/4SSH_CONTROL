import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../composables/api.js'

export const useDashboardStore = defineStore('dashboard', () => {
  const stats = ref({})
  const sessions = ref([])
  const recentLogs = ref([])
  const alerts = ref([])
  const vtScans = ref([])

  async function fetchStats() {
    const { data } = await api.get('/api/stats')
    stats.value = data
  }

  async function fetchSessions(statusFilter = null) {
    const params = statusFilter ? { status: statusFilter } : {}
    const { data } = await api.get('/api/sessions', { params })
    sessions.value = data
  }

  async function fetchLogs(limit = 100, verdict = null) {
    const params = { limit }
    if (verdict) params.verdict = verdict
    const { data } = await api.get('/api/logs', { params })
    recentLogs.value = data
  }

  async function fetchAlerts(unacknowledged = false) {
    const { data } = await api.get('/api/alerts', { params: { unacknowledged } })
    alerts.value = data
  }

  async function fetchVTScans() {
    const { data } = await api.get('/api/vt-scans')
    vtScans.value = data
  }

  async function controlSession(sessionId, action, reason = '') {
    await api.post(`/api/sessions/${sessionId}/control`, { action, reason })
  }

  async function acknowledgeAlert(alertId) {
    await api.post(`/api/alerts/${alertId}/acknowledge`)
    await fetchAlerts()
  }

  function addRealtimeLog(entry) {
    recentLogs.value.unshift(entry)
    if (recentLogs.value.length > 200) recentLogs.value.pop()
  }

  function addRealtimeAlert(alert) {
    alerts.value.unshift(alert)
  }

  function updateSession(sessionData) {
    const idx = sessions.value.findIndex(s => s.id === sessionData.id || s.id === sessionData.session_id)
    if (idx >= 0) {
      Object.assign(sessions.value[idx], sessionData)
    }
  }

  return {
    stats, sessions, recentLogs, alerts, vtScans,
    fetchStats, fetchSessions, fetchLogs, fetchAlerts, fetchVTScans,
    controlSession, acknowledgeAlert,
    addRealtimeLog, addRealtimeAlert, updateSession,
  }
})
