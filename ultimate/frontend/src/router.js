import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from './stores/auth.js'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('./pages/LoginPage.vue'),
    meta: { guest: true },
  },
  {
    path: '/',
    name: 'Dashboard',
    component: () => import('./pages/DashboardPage.vue'),
    meta: { auth: true },
  },
  {
    path: '/sessions',
    name: 'Sessions',
    component: () => import('./pages/SessionsPage.vue'),
    meta: { auth: true },
  },
  {
    path: '/sessions/:id',
    name: 'SessionDetail',
    component: () => import('./pages/SessionDetailPage.vue'),
    meta: { auth: true },
  },
  {
    path: '/logs',
    name: 'Logs',
    component: () => import('./pages/LogsPage.vue'),
    meta: { auth: true },
  },
  {
    path: '/servers',
    name: 'Servers',
    component: () => import('./pages/ServersPage.vue'),
    meta: { auth: true },
  },
  {
    path: '/alerts',
    name: 'Alerts',
    component: () => import('./pages/AlertsPage.vue'),
    meta: { auth: true },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.meta.auth && !auth.isAuthenticated) return { name: 'Login' }
  if (to.meta.guest && auth.isAuthenticated) return { name: 'Dashboard' }
})

export default router
