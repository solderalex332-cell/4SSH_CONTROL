import { ref, onMounted, onUnmounted } from 'vue'
import { useDashboardStore } from '../stores/dashboard.js'

export function useWebSocket() {
  const connected = ref(false)
  let ws = null
  let reconnectTimer = null

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    ws = new WebSocket(`${proto}://${location.host}/ws/events`)

    ws.onopen = () => {
      connected.value = true
      if (reconnectTimer) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
      }
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        handleEvent(msg)
      } catch {}
    }

    ws.onclose = () => {
      connected.value = false
      reconnectTimer = setTimeout(connect, 3000)
    }

    ws.onerror = () => {
      ws.close()
    }
  }

  function handleEvent(msg) {
    const store = useDashboardStore()
    const { event, data } = msg

    switch (event) {
      case 'command_verdict':
        store.addRealtimeLog({
          id: Date.now(),
          session_id: data.session_id,
          command: data.command,
          verdict: data.verdict,
          reason: data.reason,
          severity: data.severity,
          category: data.category || 'unknown',
          created_at: new Date().toISOString(),
          username: data.username || '',
          role: '',
          is_escalated: data.verdict === 'escalate',
          server_profile: '',
          server_vendor: '',
          elapsed_ms: data.elapsed_ms || 0,
        })
        break

      case 'session_control':
        store.updateSession(data)
        break

      case 'alert':
        store.addRealtimeAlert(data)
        break

      case 'vt_scan':
        store.fetchVTScans()
        break
    }
  }

  function send(data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? data : JSON.stringify(data))
    }
  }

  onMounted(connect)
  onUnmounted(() => {
    if (ws) ws.close()
    if (reconnectTimer) clearTimeout(reconnectTimer)
  })

  return { connected, send }
}
