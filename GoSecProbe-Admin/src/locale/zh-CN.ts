import localeMessageBox from '@/components/message-box/locale/zh-CN'
import localeLogin from '@/views/login/locale/zh-CN'
import localeWorkplace from '@/views/dashboard/workplace/locale/zh-CN'
import localeBasicProfile from '@/views/report/basic/locale/zh-CN'
import localeError from '@/views/result/error/locale/zh-CN'
import localeSuccess from '@/views/result/success/locale/zh-CN'
import locale403 from '@/views/exception/403/locale/zh-CN'
import locale404 from '@/views/exception/404/locale/zh-CN'
import locale500 from '@/views/exception/500/locale/zh-CN'
import localeUserSetting from '@/views/user/setting/locale/zh-CN'
import localeSettings from './zh-CN/settings'

export default {
  'menu.dashboard': '仪表盘',
  'menu.server.dashboard': '仪表盘-服务端',
  'menu.server.workplace': '工作台-服务端',
  'menu.result': '结果页',
  'menu.exception': '异常页',
  'menu.report': '报告管理',
  'menu.report.list': '报告列表',
  'menu.report.detail': '报告详情',
  'menu.settings': '系统设置',
  'menu.settings.engine': '系统配置',
  'menu.user': '个人中心',
  'menu.faq': '常见问题',
  'menu.task': '漏洞扫描',
  'workplace.vulnTrend': '漏洞趋势',
  'menu.task.create': '创建任务',
  'menu.task.list': '任务列表',
  'menu.task.result': '扫描结果',
  'task.status.pending': '待处理',
  'task.status.running': '运行中',
  'task.status.finished': '已完成',
  'task.status.completed': '已完成',
  'task.status.paused': '已暂停',
  'task.status.stopped': '已停止',
  'task.status.error': '错误',
  'task.status.failed': '失败',
  'task.type.alive': '主机存活性扫描',
  'task.type.port': '端口扫描与服务识别',
  'task.type.web': 'Web 指纹识别',
  'task.type.full': '全量扫描',
  'menu.vuln': '漏洞管理',
  'menu.vuln.pocs': 'POC 管理',
  'menu.vuln.verify': 'POC 验证',
  'menu.plugin': '插件管理',
  'menu.plugin.list': '插件列表',
  'menu.tools': '常用工具',
  'menu.tools.dict': '字典管理',
  'menu.tools.searchEngine': '空间测绘',
  'navbar.docs': '文档中心',
  'navbar.action.locale': '切换为中文',
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
