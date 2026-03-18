import axios from 'axios'

export function getPluginList(params: { name?: string; type?: string }) {
  return axios.get('/api/plugin/list', { params })
}

export function updatePluginStatus(id: number, enabled: boolean) {
  return axios.post('/api/plugin/status', { id, enabled })
}

export function syncPlugins() {
  return axios.post('/api/plugin/sync')
}

export function updatePluginConfig(id: number, config: string) {
  return axios.post('/api/plugin/config', { id, config })
}
