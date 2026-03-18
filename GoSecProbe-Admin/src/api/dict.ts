import axios from 'axios'

export function getDictList(params?: any) {
  return axios.get('/api/dict/list', { params })
}

export function syncDicts() {
  return axios.post('/api/dict/sync')
}

export function viewDict(id: number) {
  return axios.get('/api/dict/view', { params: { id } })
}

export function downloadDict(id: number) {
  return axios.get('/api/dict/download', {
    params: { id },
    responseType: 'blob',
  })
}

export function deleteDict(id: number) {
  return axios.delete(`/api/dict/delete/${id}`)
}

export function generateSocialDict(data: any) {
  return axios.post('/api/dict/generate/social', data)
}

export function generateComboDict(data: any) {
  return axios.post('/api/dict/generate/combo', data)
}
