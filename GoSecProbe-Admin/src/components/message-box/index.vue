<template>
  <div class="notification-box">
    <!-- 顶部标题栏 -->
    <div class="notif-header">
      <span class="notif-title">
        <icon-notification style="margin-right: 6px; font-size: 15px" />
        漏洞通知
        <a-badge
          v-if="summary.unread_count > 0"
          :count="summary.unread_count"
          :max-count="99"
          style="margin-left: 6px"
        />
      </span>
      <a-space :size="4">
        <a-button type="text" size="small" :disabled="summary.unread_count === 0" @click="handleMarkAllRead">
          <template #icon><icon-check /></template>
          全部已读
        </a-button>
        <a-button type="text" size="small" status="danger" :disabled="list.length === 0" @click="handleClear">
          <template #icon><icon-delete /></template>
          清空
        </a-button>
      </a-space>
    </div>

    <!-- 列表内容 -->
    <a-spin :loading="loading" style="display: block">
      <div class="notif-list-wrap">
        <!-- 空状态 -->
        <div v-if="!loading && list.length === 0" class="empty-wrap">
          <icon-check-circle-fill style="font-size: 40px; color: var(--color-success-light-4)" />
          <p style="margin-top: 8px; color: var(--color-text-3)">暂无漏洞通知</p>
        </div>

        <!-- 通知列表 -->
        <div v-for="item in list" :key="item.id" class="notif-item" @click="handleRead(item)">
          <div class="notif-item-left">
            <a-tag :color="severityColor(item.severity)" size="small" style="margin-bottom: 4px">
              {{ severityLabel(item.severity) }}
            </a-tag>
            <div class="notif-item-title">{{ item.title }}</div>
            <div class="notif-item-sub">
              <span>{{ item.task_name }}</span>
              <span class="notif-sep">·</span>
              <span>{{ item.target }}</span>
            </div>
            <div class="notif-item-time">{{ item.discovered_at }}</div>
          </div>
          <div v-if="!item.is_read" class="unread-dot" />
        </div>
      </div>
    </a-spin>
  </div>
</template>

<script lang="ts" setup>
import {
  getNotificationList,
  getNotificationSummary,
  markAllRead,
  clearNotifications,
  type NotificationItem,
  type VulnNotificationSummary,
} from '@/api/notification'
import { Message } from '@arco-design/web-vue'
import { onMounted, ref } from 'vue'

const loading = ref(false)
const list = ref<NotificationItem[]>([])
const summary = ref<VulnNotificationSummary>({ has_vuln: false, high_count: 0, unread_count: 0 })

const severityColor = (s: string) => {
  const m: Record<string, string> = {
    critical: 'red',
    high: 'orangered',
    medium: 'orange',
    low: 'blue',
    info: 'gray',
  }
  return m[s?.toLowerCase()] ?? 'gray'
}

const severityLabel = (s: string) => {
  const m: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return m[s?.toLowerCase()] ?? s
}

async function refresh() {
  loading.value = true
  try {
    const [listRes, sumRes] = await Promise.all([getNotificationList(30), getNotificationSummary()])
    // 拦截器平擺化后： res.data === 业务数据（即 NotificationItem[] / VulnNotificationSummary）
    list.value = (listRes.data ?? []).map((item: NotificationItem) => ({
      ...item,
      is_read: false,
    }))
    summary.value = sumRes.data ?? { has_vuln: false, high_count: 0, unread_count: 0 }
  } catch {
    // ignore
  } finally {
    loading.value = false
  }
}

async function handleMarkAllRead() {
  try {
    await markAllRead()
    list.value = list.value.map((i) => ({ ...i, is_read: true }))
    summary.value = { ...summary.value, unread_count: 0, has_vuln: summary.value.has_vuln }
    Message.success('已全部标记为已读')
  } catch {
    Message.error('操作失败')
  }
}

async function handleClear() {
  try {
    await clearNotifications()
    list.value = []
    summary.value = { has_vuln: false, high_count: 0, unread_count: 0 }
    Message.success('通知已清空')
  } catch {
    Message.error('操作失败')
  }
}
function handleRead(item: NotificationItem) {
  item.is_read = true
}
onMounted(refresh)

// 暴露 refresh 供 navbar 调用
defineExpose({ refresh, summary })
</script>

<style scoped lang="less">
.notification-box {
  width: 380px;
  background: var(--color-bg-2);
  border-radius: 8px;
  overflow: hidden;
}

.notif-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-neutral-3);
  background: var(--color-bg-2);
}

.notif-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--color-text-1);
  display: flex;
  align-items: center;
}

.notif-list-wrap {
  max-height: 420px;
  overflow-y: auto;
}

.empty-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 0;
  color: var(--color-text-3);
}

.notif-item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  padding: 12px 16px;
  border-bottom: 1px solid var(--color-neutral-2);
  cursor: default;
  transition: background 0.15s;

  &:last-child {
    border-bottom: none;
  }

  &:hover {
    background: var(--color-fill-1);
  }

}

.notif-item-left {
  flex: 1;
  min-width: 0;
}

.notif-item-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--color-text-1);
  margin-top: 2px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.notif-item-sub {
  font-size: 12px;
  color: var(--color-text-3);
  margin-top: 2px;

  .notif-sep {
    margin: 0 4px;
  }
}

.notif-item-time {
  font-size: 11px;
  color: var(--color-text-4);
  margin-top: 4px;
}

.unread-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: rgb(var(--danger-6));
  margin-top: 4px;
  margin-left: 8px;
  flex-shrink: 0;
}
</style>
