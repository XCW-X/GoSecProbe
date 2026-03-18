<template>
  <a-card
    class="general-card"
    :title="$t('workplace.scanStatus')"
    :header-style="{ paddingBottom: '0' }"
    :body-style="{ padding: '15px 20px 20px 20px' }"
  >
    <template #extra>
      <a-link @click="$router.push({ name: 'TaskList' })">{{ $t('workplace.viewMore') }}</a-link>
    </template>
    <a-list :bordered="false">
      <a-list-item v-for="(item, index) in scanTasks" :key="index" style="padding: 10px 0">
        <a-list-item-meta :title="item.name">
          <template #description>
            <div class="task-info">
              <a-progress :percent="item.progress / 100" size="mini" :status="getProgressStatus(item.status)" style="margin-top: 5px" />
              <div class="task-footer">
                <span class="status-text">{{ getStatusText(item.status) }}</span>
                <span class="percent-text">{{ item.progress }}%</span>
              </div>
            </div>
          </template>
        </a-list-item-meta>
      </a-list-item>
      <div v-if="scanTasks.length === 0" class="empty-status">
        <a-empty description="暂无任务记录" />
      </div>
    </a-list>
  </a-card>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import { getRecentTasks } from '@/api/dashboard'

const scanTasks = ref<any[]>([])

async function fetchTasks() {
  try {
    const { data } = await getRecentTasks()
    scanTasks.value = data ?? []
  } catch (e) {
    console.error('[ScanStatus] fetchTasks failed', e)
  }
}

const getStatusText = (status: string) => {
  const map: Record<string, string> = {
    running: '正在扫描',
    completed: '扫描完成',
    failed: '任务失败',
    stopped: '已停止',
    pending: '等待中',
    paused: '已暂停',
  }
  return map[status] || status
}

const getProgressStatus = (status: string): 'normal' | 'success' | 'warning' | 'danger' => {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'stopped') return 'warning'
  return 'normal'
}

onMounted(fetchTasks)
</script>

<style scoped lang="less">
.task-info {
  width: 100%;
}
.task-footer {
  display: flex;
  justify-content: space-between;
  margin-top: 4px;
  font-size: 12px;
  color: var(--color-text-3);
}
.empty-status {
  padding: 20px 0;
  text-align: center;
}
</style>
