<template>
  <a-card
    class="general-card"
    :title="$t('workplace.riskReminder')"
    :header-style="{ paddingBottom: '0' }"
    :body-style="{ padding: '15px 20px' }"
  >
    <a-list :bordered="false">
      <a-list-item v-for="(item, index) in risks" :key="index" style="padding: 12px 0">
        <div class="risk-item">
          <div class="risk-header">
            <a-tag :color="getSeverityColor(item.severity)" size="small">
              {{ getSeverityText(item.severity) }}
            </a-tag>
            <span class="risk-title">{{ item.name }}</span>
          </div>
          <div class="risk-footer">
            <span class="risk-target">{{ item.target }}</span>
            <span class="risk-time">{{ formatRelativeTime(item.discovered_at) }}</span>
          </div>
        </div>
      </a-list-item>
      <div v-if="risks.length === 0" class="empty-status">
        <a-empty description="暂无风险提醒" />
      </div>
    </a-list>
  </a-card>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { getRiskAlerts } from '@/api/dashboard'

const risks = ref<any[]>([])

async function fetchAlerts() {
  try {
    const { data } = await getRiskAlerts()
    risks.value = data ?? []
  } catch (e) {
    console.error('[RiskReminders] fetchAlerts failed', e)
  }
}

const getSeverityColor = (s: string) => {
  const m: Record<string, string> = {
    critical: 'red',
    high: 'orangered',
    medium: 'gold',
    low: 'arcoblue',
    info: 'gray',
  }
  return m[s] ?? 'gray'
}

const getSeverityText = (s: string) => {
  const m: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return m[s] ?? s
}

function formatRelativeTime(iso: string): string {
  if (!iso) return '-'
  const diff = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diff / 60000)
  if (minutes < 60) return `${minutes}分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}小时前`
  const days = Math.floor(hours / 24)
  return `${days}天前`
}

onMounted(fetchAlerts)
</script>

<style scoped lang="less">
.risk-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.risk-header {
  display: flex;
  align-items: center;
  gap: 8px;
}
.risk-title {
  font-weight: 500;
  color: var(--color-text-1);
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 180px;
}
.risk-footer {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
  color: var(--color-text-3);
}
.empty-status {
  padding: 20px 0;
  text-align: center;
}
</style>
