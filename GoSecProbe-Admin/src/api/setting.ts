import axios from 'axios'

export interface SystemSettings {
  id?: number
  network_card: string
  concurrency: number
  timeout: number
  retries: number
  proxy_type: string
  proxy_url: string
  // 反连设置
  reverse_dnslog_domain: string
  reverse_rmi_server: string
  reverse_ldap_server: string
  reverse_http_server: string
  created_at?: string
  updated_at?: string
}

export interface NetworkInterface {
  name: string
  ips: string[]
  is_up: boolean
  is_default: boolean
}

export function getSystemSettings() {
  return axios.get('/api/setting')
}

export function updateSystemSettings(data: SystemSettings) {
  return axios.post('/api/setting', data)
}

export function getNetworkInterfaces() {
  return axios.get('/api/setting/interfaces')
}
