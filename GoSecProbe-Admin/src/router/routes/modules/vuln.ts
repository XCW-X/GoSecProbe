import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const VULN: AppRouteRecordRaw = {
  path: '/vuln',
  name: 'vuln',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.vuln',
    icon: 'icon-bug',
    requiresAuth: true,
    order: 2,
  },
  children: [
    {
      path: 'pocs',
      name: 'pocs',
      component: () => import('@/views/vuln/info/index.vue'),
      meta: {
        locale: 'menu.vuln.pocs',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'verify',
      name: 'verify',
      component: () => import('@/views/vuln/verify/index.vue'),
      meta: {
        locale: 'menu.vuln.verify',
        requiresAuth: true,
        roles: ['*'],
      },
    },
  ],
}

export default VULN
