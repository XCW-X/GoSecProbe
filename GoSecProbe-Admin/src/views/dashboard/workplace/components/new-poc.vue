<template>
  <a-spin :loading="loading" style="width: 100%">
    <a-card class="general-card" :header-style="{ paddingBottom: '0' }" :body-style="{ padding: '17px 20px 21px 20px' }">
      <template #title>
        {{ $t('workplace.popularContent') }}
      </template>
      <template #extra>
        <a-link @click="$router.push({ name: 'TaskList' })">{{ $t('workplace.viewMore') }}</a-link>
      </template>
      <a-empty v-if="list.length === 0" description="暂无漏洞数据" style="margin: 40px 0" />
      <a-space v-else direction="vertical" :size="10" fill>
        <a-table :data="list" :pagination="false" :bordered="false" :scroll="{ x: '100%', y: '264px' }">
          <template #columns>
            <a-table-column title="漏洞名称">
              <template #cell="{ record }">
                <a-typography-paragraph :ellipsis="{ rows: 1 }">
                  {{ record.name }}
                </a-typography-paragraph>
              </template>
            </a-table-column>
            <a-table-column title="等级" :width="80">
              <template #cell="{ record }">
                <a-tag :color="getSeverityColor(record.severity)" size="small">{{ getSeverityText(record.severity) }}</a-tag>
              </template>
            </a-table-column>
            <a-table-column title="发现时间" :width="100">
              <template #cell="{ record }">
                <span style="font-size: 12px; color: var(--color-text-3)">{{ formatTime(record.discovered_at) }}</span>
              </template>
            </a-table-column>
          </template>
        </a-table>
      </a-space>
    </a-card>
  </a-spin>
</template>

<script lang="ts" setup>
import { ref, onMounted } from 'vue'
import useLoading from '@/hooks/loading'
import { getLatestVulns } from '@/api/dashboard'

const { loading, setLoading } = useLoading()
const list = ref<any[]>([])

async function fetchLatestVulns() {
  setLoading(true)
  try {
    const { data } = await getLatestVulns()
    list.value = data ?? []
  } catch (e) {
    console.error('[NewPoc] fetchLatestVulns failed', e)
  } finally {
    setLoading(false)
  }
}

function getSeverityColor(s: string) {
  const m: Record<string, string> = {
    critical: 'red',
    high: 'orangered',
    medium: 'gold',
    low: 'arcoblue',
    info: 'gray',
  }
  return m[s] ?? 'gray'
}

function getSeverityText(s: string) {
  const m: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }
  return m[s] ?? s
}

function formatTime(iso: string) {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

onMounted(fetchLatestVulns)
</script>

<style scoped lang="less">
.general-card {
  min-height: 395px;
}
:deep(.arco-table-tr) {
  height: 44px;
  .arco-typography {
    margin-bottom: 0;
  }
}
</style>
