import { DEFAULT_LAYOUT } from '../base'
import { AppRouteRecordRaw } from '../types'

const REPORT: AppRouteRecordRaw = {
  path: '/report',
  name: 'report',
  component: DEFAULT_LAYOUT,
  meta: {
    locale: 'menu.report',
    requiresAuth: true,
    icon: 'icon-file',
    order: 3,
  },
  children: [
    {
      path: 'list',
      name: 'ReportList',
      component: () => import('@/views/report/list/index.vue'),
      meta: {
        locale: 'menu.report.list',
        requiresAuth: true,
        roles: ['*'],
      },
    },
    {
      path: 'detail',
      name: 'ReportDetail',
      component: () => import('@/views/report/basic/index.vue'),
      meta: {
        locale: 'menu.report.detail',
        requiresAuth: true,
        roles: ['*'],
        hideInMenu: true,
        activeMenu: 'ReportList',
      },
    },
  ],
}

export default REPORT
