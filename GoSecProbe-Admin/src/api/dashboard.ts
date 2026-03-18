import axios from 'axios'

// 总览统计
export function getDashboardOverview() {
  return axios.get('/api/dashboard/overview')
}

// 漏洞趋势（近7天，每天各级别数量）
export function getVulnTrend() {
  return axios.get('/api/dashboard/vuln-trend')
}

// 漏洞级别分布（全局）
export function getVulnSeverity() {
  return axios.get('/api/dashboard/vuln-severity')
}

// 最新添加漏洞列表（按时间降序）
export function getLatestVulns() {
  return axios.get('/api/dashboard/latest-vulns')
}

// 最近任务扫描状态
export function getRecentTasks() {
  return axios.get('/api/dashboard/recent-tasks')
}

// 风险提醒（高危漏洞，按级别优先）
export function getRiskAlerts() {
  return axios.get('/api/dashboard/risk-alerts')
}
