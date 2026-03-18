import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const SETTINGS: AppRouteRecordRaw = {
  path: '/setting',
  name: 'setting',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.settings',
    icon: 'icon-settings',
    requiresAuth: true,
    order: 6,
    hideInMenu: true,
  },
  children: [
    {
      path: 'engine',
      name: 'EngineSettings',
      component: () => import('@/views/setting/index.vue'),
      meta: {
        locale: 'menu.settings.engine',
        requiresAuth: true,
        roles: ['admin'],
        hideInMenu: true,
      },
    },
  ],
}

export default SETTINGS
