import axios from 'axios'

export interface SearchEngineResult {
  url: string
  ip: string
  port: number
  protocol: string
  location: string
  title: string
  icp?: string
}

export interface SearchEngineQuery {
  engine: string
  query: string
  size: number
}

export function searchEngine(params: SearchEngineQuery) {
  return axios.get<SearchEngineResult[]>('/api/tools/search-engine', {
    params: {
      engine: params.engine,
      query: params.query,
      size: params.size,
    },
  }) as any
}

export function getSearchEngineCache(engine: string) {
  return axios.get<SearchEngineResult[]>('/api/tools/search-engine/cache', {
    params: {
      engine,
    },
  }) as any
}

export interface ToolConfigItem {
  api_key: string
  api_email?: string
}

export interface ToolConfigsResponse {
  hunter?: ToolConfigItem
  fofa?: ToolConfigItem
  quake?: ToolConfigItem
}

export interface ToolConfigsUpdateRequest {
  hunter_key: string
  fofa_key: string
  fofa_email: string
  quake_key: string
}

export function getToolConfigs() {
  return axios.get<ToolConfigsResponse>('/api/tools/configs') as any
}

export function updateToolConfigs(data: ToolConfigsUpdateRequest) {
  return axios.post('/api/tools/configs', data) as any
}
