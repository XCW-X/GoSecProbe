import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const TASK: AppRouteRecordRaw = {
  path: '/task',
  name: 'task',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.task',
    icon: 'icon-check-circle',
    requiresAuth: true,
    order: 1,
  },
  children: [
    {
      path: 'list',
      name: 'TaskList',
      component: () => import('@/views/task/list/index.vue'),
      meta: {
        locale: 'menu.task.list',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'create',
      name: 'TaskCreate',
      component: () => import('@/views/task/create/index.vue'),
      meta: {
        locale: 'menu.task.create',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'result',
      name: 'ScanResult',
      component: () => import('@/views/task/result/index.vue'),
      meta: {
        locale: 'menu.task.result',
        requiresAuth: true,
        roles: ['*'],
        hideInMenu: true,
        activeMenu: 'TaskList',
        ignoreCache: true,
      },
    },
  ],
}

export default TASK
