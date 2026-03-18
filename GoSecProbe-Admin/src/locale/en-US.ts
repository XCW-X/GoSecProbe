import localeMessageBox from '@/components/message-box/locale/en-US'
import localeLogin from '@/views/login/locale/en-US'
import localeWorkplace from '@/views/dashboard/workplace/locale/en-US'
import localeBasicProfile from '@/views/report/basic/locale/en-US'
import localeError from '@/views/result/error/locale/en-US'
import localeSuccess from '@/views/result/success/locale/en-US'
import locale403 from '@/views/exception/403/locale/en-US'
import locale404 from '@/views/exception/404/locale/en-US'
import locale500 from '@/views/exception/500/locale/en-US'
import localeUserSetting from '@/views/user/setting/locale/en-US'
import localeSettings from './en-US/settings'

export default {
  'menu.dashboard': 'Dashboard',
  'menu.server.dashboard': 'Dashboard-Server',
  'menu.server.workplace': 'Workplace-Server',
  'menu.server.monitor': 'Monitor-Server',
  'menu.result': 'Result',
  'menu.exception': 'Exception',
  'menu.report': 'Report Manage',
  'menu.report.detail': 'Task Report Detail',
  'menu.settings': 'Settings',
  'menu.settings.engine': 'Engine Settings',
  'menu.task': 'Vuln Scan',
  'workplace.vulnTrend': 'Vulnerability Trend',
  'menu.task.create': 'Create Task',
  'menu.task.list': 'Task List',
  'menu.task.result': 'Scan Result',
  'task.status.pending': 'Pending',
  'task.status.running': 'Running',
  'task.status.finished': 'Finished',
  'task.status.completed': 'Completed',
  'task.status.paused': 'Paused',
  'task.status.stopped': 'Stopped',
  'task.status.error': 'Error',
  'task.status.failed': 'Failed',
  'task.type.alive': 'Host Discovery',
  'task.type.port': 'Port Scan & Service Detection',
  'task.type.web': 'Web Fingerprinting',
  'task.type.full': 'Full Scan',
  'menu.vuln': 'Vuln Manage',
  'menu.vuln.pocs': 'POC Manage',
  'menu.vuln.verify': 'POC Verify',
  'menu.plugin': 'Plugin Manage',
  'menu.plugin.list': 'Plugin List',
  'menu.tools': 'Common Tools',
  'menu.tools.dict': 'Dict Manage',
  'menu.tools.searchEngine': 'Search Engine',
  'menu.user': 'User Center',
  'menu.arcoWebsite': 'Arco Design',
  'menu.faq': 'FAQ',
  'navbar.docs': 'Docs',
  'navbar.action.locale': 'Switch to English',
  ...localeSettings,
  ...localeMessageBox,
  ...localeLogin,
  ...localeWorkplace,
  ...localeBasicProfile,

  ...localeSuccess,
  ...localeError,
  ...locale403,
  ...locale404,
  ...locale500,

  ...localeUserSetting,
  /** simple end */
}
