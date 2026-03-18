<template>
  <a-spin :loading="loading" style="width: 100%">
    <a-card class="general-card" :header-style="{ paddingBottom: '0' }" :body-style="{ padding: '20px' }">
      <template #title>
        {{ $t('workplace.categoriesPercent') }}
      </template>
      <Chart height="310px" :option="chartOption" />
    </a-card>
  </a-spin>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted } from 'vue'
import type { EChartsOption } from 'echarts'
import useLoading from '@/hooks/loading'
import { getVulnSeverity } from '@/api/dashboard'

const { loading, setLoading } = useLoading()

const severityData = ref({ total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 })

async function fetchSeverity() {
  setLoading(true)
  try {
    const { data } = await getVulnSeverity()
    if (data) {
      severityData.value = data
    }
  } catch (e) {
    console.error('[VulnerabilitiesPercent] fetch failed', e)
  } finally {
    setLoading(false)
  }
}

const chartOption = computed<EChartsOption>(() => {
  const isDark = document.documentElement.getAttribute('arco-theme') === 'dark'
  const s = severityData.value
  return {
    legend: {
      left: 'center',
      data: ['严重', '高危', '中危', '低危', '信息'],
      bottom: 0,
      icon: 'circle',
      itemWidth: 8,
      textStyle: {
        color: isDark ? 'rgba(255,255,255,0.7)' : '#4E5969',
      },
      itemStyle: { borderWidth: 0 },
    },
    tooltip: { show: true, trigger: 'item' },
    graphic: {
      elements: [
        {
          type: 'text',
          left: 'center',
          top: '40%',
          style: {
            text: '漏洞总数',
            textAlign: 'center',
            fill: isDark ? '#ffffffb3' : '#4E5969',
            fontSize: 14,
          },
        },
        {
          type: 'text',
          left: 'center',
          top: '50%',
          style: {
            text: String(s.total),
            textAlign: 'center',
            fill: isDark ? '#ffffffb3' : '#1D2129',
            fontSize: 16,
            fontWeight: 500,
          },
        },
      ],
    },
    series: [
      {
        type: 'pie',
        radius: ['50%', '70%'],
        center: ['50%', '50%'],
        label: {
          formatter: '{d}%',
          fontSize: 14,
          color: isDark ? 'rgba(255,255,255,0.7)' : '#4E5969',
        },
        itemStyle: {
          borderColor: isDark ? '#232324' : '#fff',
          borderWidth: 1,
        },
        data: [
          { value: s.critical || 0, name: '严重', itemStyle: { color: '#8E0000' } },
          { value: s.high || 0, name: '高危', itemStyle: { color: '#F53F3F' } },
          { value: s.medium || 0, name: '中危', itemStyle: { color: '#F7BA1E' } },
          { value: s.low || 0, name: '低危', itemStyle: { color: '#3491FA' } },
          { value: s.info || 0, name: '信息', itemStyle: { color: '#86909C' } },
        ],
      },
    ],
  }
})

onMounted(fetchSeverity)
</script>

<style scoped lang="less"></style>
