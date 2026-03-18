import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const PLUGIN: AppRouteRecordRaw = {
  path: '/plugin',
  name: 'plugin',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.plugin',
    requiresAuth: true,
    icon: 'icon-apps',
    order: 4,
  },
  children: [
    {
      path: 'list',
      name: 'PluginList',
      component: () => import('@/views/plugin/list/index.vue'),
      meta: {
        locale: 'menu.plugin.list',
        requiresAuth: true,
        roles: ['*'],
      },
    },
  ],
}

export default PLUGIN
