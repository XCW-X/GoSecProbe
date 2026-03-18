import axios from 'axios'

export interface VulnNotificationSummary {
  has_vuln: boolean // 是否有漏洞（红点）
  high_count: number // 高危及以上漏洞数（数字徽标）
  unread_count: number // 未读总数
}

export interface NotificationItem {
  id: number
  vuln_id: number
  task_id: number
  task_name: string
  title: string
  content: string
  severity: string
  target: string
  is_read: boolean
  discovered_at: string
}

/** 获取未读通知摘要（Navbar Badge 用）
 *  拦截器已将 response.data（即 {code,msg,data}）作为返回值，
 *  所以调用结果类型直接是 { code, msg, data }，取 .data 即业务数据。
 */
export function getNotificationSummary() {
  return axios.get<VulnNotificationSummary>('/api/notification/unread')
}

/** 获取通知列表 */
export function getNotificationList(pageSize = 20) {
  return axios.get<NotificationItem[]>('/api/notification/list', {
    params: { pageSize },
  })
}

/** 一键已读 */
export function markAllRead() {
  return axios.post('/api/notification/read-all')
}

/** 清空通知 */
export function clearNotifications() {
  return axios.delete('/api/notification/clear')
}
