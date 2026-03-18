import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const TOOLS: AppRouteRecordRaw = {
  path: '/tools',
  name: 'tools',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.tools',
    icon: 'icon-tool',
    requiresAuth: true,
    order: 5,
  },
  children: [
    {
      path: 'dict',
      name: 'DictManager',
      component: () => import('@/views/tools/dict/index.vue'),
      meta: {
        locale: 'menu.tools.dict',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'search-engine',
      name: 'SearchEngine',
      component: () => import('@/views/tools/search-engine/index.vue'),
      meta: {
        locale: 'menu.tools.searchEngine',
        requiresAuth: true,
        roles: ['*'],
      },
    },
  ],
}

export default TOOLS
