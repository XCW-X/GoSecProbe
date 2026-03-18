import { UserState } from '@/store/modules/user/types'
import axios from 'axios'
import type { RouteRecordNormalized } from 'vue-router'

export interface LoginData {
  username: string
  password: string
}

export interface LoginRes {
  token: string
}
export function login(data: LoginData) {
  return axios.post<LoginRes>('/api/user/login', data)
}

export function logout() {
  return axios.post<LoginRes>('/api/user/logout')
}

export function getUserInfo() {
  return axios.post<UserState>('/api/user/info')
}

export function getMenuList() {
  return axios.post<RouteRecordNormalized[]>('/api/user/menu')
}

export interface ChangePasswordData {
  old_password: string
  new_password: string
}

export function changePassword(data: ChangePasswordData) {
  return axios.post('/api/user/password', data)
}

export interface RegisterData {
  username: string
  password: string
}

export function register(data: RegisterData) {
  return axios.post<LoginRes>('/api/user/register', data)
}
