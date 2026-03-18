<template>
  <div class="search-engine-interface">
    <div class="search-header">
      <a-input-search
        v-model="query"
        class="search-input"
        :placeholder="`请输入${engine} 查询语句`"
        button-text="搜索"
        search-button
        size="large"
        @search="handleSearch"
      />
    </div>

    <div class="search-options" style="margin-top: 15px; display: flex; justify-content: space-between; align-items: center">
      <a-space size="large">
        <a-checkbox v-if="showSelection" :model-value="isAllSelected" @change="toggleSelectAll">全选</a-checkbox>
        <a-select v-model="options.size" style="width: 120px" placeholder="搜索数量" @change="handlePresetChange">
          <a-option :value="10">10 条</a-option>
          <a-option :value="100">100 条</a-option>
          <a-option :value="500">500 条</a-option>
          <a-option value="custom">自定义</a-option>
        </a-select>
        <a-input-number
          v-if="options.size === 'custom'"
          v-model="customSize"
          :min="minSize"
          :max="1000"
          style="width: 140px"
          placeholder="输入数量"
        />
      </a-space>

      <a-button type="primary" @click="exportToExcel" :disabled="results.length === 0">
        <template #icon>
          <icon-download />
        </template>
        导出 XLSX
      </a-button>
    </div>

    <a-divider />

    <a-table :data="results" :loading="loading" style="margin-top: 20px">
      <template #columns>
        <a-table-column v-if="showSelection" title="" :width="48">
          <template #cell="{ rowIndex }">
            <a-checkbox :model-value="isRowSelected(rowIndex)" @change="(value: boolean) => toggleRow(rowIndex, value)" />
          </template>
        </a-table-column>
        <a-table-column title="目标" data-index="url" />
        <a-table-column title="IP" data-index="ip" />
        <a-table-column title="端口" data-index="port" />
        <a-table-column title="协议" data-index="protocol" />
        <a-table-column title="标题" data-index="title" />
        <a-table-column title="ICP 备案" data-index="icp" />
        <a-table-column title="操作">
          <template #cell="{ record }">
            <a-button type="text" @click="handleVisit(record)">访问</a-button>
          </template>
        </a-table-column>
      </template>
    </a-table>

    <a-modal v-model:visible="configVisible" title="配置API" :confirm-loading="configSaving" @ok="handleSaveConfig">
      <a-form layout="vertical">
        <a-form-item label="Hunter API Key">
          <a-input v-model="configForm.hunter_key" placeholder="请输入 Hunter API Key" />
        </a-form-item>
        <a-form-item label="FOFA Email">
          <a-input v-model="configForm.fofa_email" placeholder="请输入 FOFA Email" />
        </a-form-item>
        <a-form-item label="FOFA API Key">
          <a-input v-model="configForm.fofa_key" placeholder="请输入 FOFA API Key" />
        </a-form-item>
        <a-form-item label="Quake API Key">
          <a-input v-model="configForm.quake_key" placeholder="请输入 Quake API Key" />
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal v-model:visible="syntaxVisible" title="查询语法示意" :footer="false" :width="1500">
      <a-table :data="syntaxRows" :pagination="false" :scroll="{ x: 1400 }">
        <template #columns>
          <a-table-column title="引擎" data-index="engine" />
          <a-table-column title="IP" data-index="ip" />
          <a-table-column title="Domain" data-index="domain" />
          <a-table-column title="Port" data-index="port" />
          <a-table-column title="Title" data-index="title" />
          <a-table-column title="Body" data-index="body" />
          <a-table-column title="OS" data-index="os" />
          <a-table-column title="App" data-index="app" />
          <a-table-column title="Protocol" data-index="protocol" />
          <a-table-column title="ICP" data-index="icp" />
          <a-table-column title="Country" data-index="country" />
          <a-table-column title="Region" data-index="region" />
          <a-table-column title="City" data-index="city" />
          <a-table-column title="Icon" data-index="icon" />
        </template>
      </a-table>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { Message } from '@arco-design/web-vue'
import { computed, onMounted, ref, reactive } from 'vue'
import { useRouter } from 'vue-router'
import { searchEngine, getSearchEngineCache, getToolConfigs, updateToolConfigs, type SearchEngineResult } from '@/api/search-engine'
import * as XLSX from 'xlsx'

const { engine } = defineProps<{
  engine: string
}>()

const router = useRouter()
const TASK_TARGETS_KEY = 'GoSecProbe_task_targets'
const POC_TARGETS_KEY = 'GoSecProbe_poc_targets'

const query = ref('')
const loading = ref(false)
const options = reactive<{ size: number | 'custom' }>({
  size: 10,
})
const customSize = ref<number | null>(null)

const results = ref<SearchEngineResult[]>([])
const showSelection = ref(false)
const selectedRows = ref<number[]>([])

const configVisible = ref(false)
const configSaving = ref(false)
const configForm = reactive({
  hunter_key: '',
  fofa_email: '',
  fofa_key: '',
  quake_key: '',
})

const syntaxVisible = ref(false)
const syntaxRows = [
  {
    engine: 'Hunter',
    ip: 'ip="1.1.1.1"',
    domain: 'domain="tidesec.com"',
    port: 'ip.port="80"',
    title: 'web.title="标题"',
    body: 'web.body="内容"',
    os: 'ip.os="centos"',
    app: 'app.name="Nginx"',
    protocol: 'protocol="http"',
    icp: 'icp.number="备案号"',
    country: 'ip.country="中国"',
    region: 'ip.province="山东"',
    city: 'ip.city="济南"',
    icon: 'web.icon="MD5"',
  },
  {
    engine: 'FOFA',
    ip: 'ip="1.1.1.1"',
    domain: 'domain="tidesec.com"',
    port: 'port="80"',
    title: 'title="标题"',
    body: 'body="内容"',
    os: 'os="centos"',
    app: 'app="Nginx"',
    protocol: 'protocol="http"',
    icp: 'icp="备案号"',
    country: 'country="中国"',
    region: 'region="山东"',
    city: 'city="济南"',
    icon: 'icon_hash="mmh3"',
  },
  {
    engine: 'Quake',
    ip: 'ip:"1.1.1.1"',
    domain: 'domain:"tidesec.com"',
    port: 'port:"80"',
    title: 'title:"标题"',
    body: 'response:"内容"',
    os: 'os:"centos"',
    app: 'app:"Nginx"',
    protocol: 'service:"ssh"',
    icp: 'icp:"备案号"',
    country: 'country_cn:"中国"',
    region: 'province:"山东"',
    city: 'city:"济南"',
    icon: 'favicon:"MD5"',
  },
]

const minSize = computed(() => {
  const key = engine.toLowerCase()
  if (key === 'hunter') {
    return 10
  }
  return 1
})

const resolvedSize = computed(() => {
  if (options.size === 'custom') {
    return customSize.value || 0
  }
  return options.size
})

const isAllSelected = computed(() => {
  return showSelection.value && results.value.length > 0 && selectedRows.value.length === results.value.length
})

const handlePresetChange = () => {
  if (options.size !== 'custom') {
    customSize.value = null
  }
}

const toggleBatch = () => {
  showSelection.value = !showSelection.value
  selectedRows.value = []
}

const isRowSelected = (rowIndex: number) => {
  return selectedRows.value.includes(rowIndex)
}

const toggleRow = (rowIndex: number, checked: boolean) => {
  if (!showSelection.value) {
    return
  }
  if (checked) {
    if (!selectedRows.value.includes(rowIndex)) {
      selectedRows.value = [...selectedRows.value, rowIndex]
    }
    return
  }
  selectedRows.value = selectedRows.value.filter((index) => index !== rowIndex)
}

const toggleSelectAll = (checked: boolean) => {
  if (!showSelection.value) {
    return
  }
  if (checked) {
    selectedRows.value = results.value.map((_, index) => index)
    return
  }
  selectedRows.value = []
}

const getSelectedTargets = () => {
  if (!showSelection.value) {
    return []
  }
  const targets = selectedRows.value
    .map((index) => results.value[index])
    .filter(Boolean)
    .map((item) => (item.url || item.ip || '').trim())
    .filter((value) => value)
  return Array.from(new Set(targets))
}

const handleQuickCreateTask = () => {
  const uniqueTargets = getSelectedTargets()
  if (uniqueTargets.length === 0) {
    Message.warning('请选择资产')
    return
  }

  sessionStorage.setItem(TASK_TARGETS_KEY, uniqueTargets.join('\n'))
  router.push('/task/create')
}

const handleQuickPocVerify = () => {
  const uniqueTargets = getSelectedTargets()
  if (uniqueTargets.length === 0) {
    Message.warning('请选择资产')
    return
  }

  sessionStorage.setItem(POC_TARGETS_KEY, uniqueTargets.join('\n'))
  router.push('/vuln/verify')
}

const openConfig = async () => {
  configVisible.value = true
  try {
    const res = await getToolConfigs()
    const data = res?.data || {}
    configForm.hunter_key = data.hunter?.api_key || ''
    configForm.fofa_email = data.fofa?.api_email || ''
    configForm.fofa_key = data.fofa?.api_key || ''
    configForm.quake_key = data.quake?.api_key || ''
  } catch (error: any) {
    Message.error(error?.message || '获取配置失败')
  }
}

const openSyntax = () => {
  syntaxVisible.value = true
}

const handleSaveConfig = async () => {
  configSaving.value = true
  try {
    await updateToolConfigs({
      hunter_key: configForm.hunter_key,
      fofa_email: configForm.fofa_email,
      fofa_key: configForm.fofa_key,
      quake_key: configForm.quake_key,
    })
    Message.success('保存成功')
    configVisible.value = false
  } finally {
    configSaving.value = false
  }
}

const loadCachedResults = async () => {
  try {
    const res = await getSearchEngineCache(engine)
    results.value = (res?.data || []) as SearchEngineResult[]
    selectedRows.value = []
  } catch {
    // ignore cache errors
  }
}

const handleSearch = async () => {
  const keyword = query.value.trim()
  if (!keyword) {
    Message.warning('请输入查询语句')
    return
  }
  if (resolvedSize.value <= 0) {
    Message.warning('请输入搜索数量')
    return
  }
  if (resolvedSize.value < minSize.value) {
    Message.warning(`最小搜索条数为 ${minSize.value}`)
    return
  }
  loading.value = true
  try {
    const res = await searchEngine({
      engine,
      query: keyword,
      size: resolvedSize.value,
    })
    results.value = (res?.data || []) as SearchEngineResult[]
    selectedRows.value = []
  } finally {
    loading.value = false
  }
}

const normalizeUrl = (value: string) => {
  const trimmed = value.trim()
  if (!trimmed) {
    return ''
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }
  return `http://${trimmed}`
}

const handleVisit = (record: SearchEngineResult) => {
  const raw = record.url || ''
  const target = normalizeUrl(raw)
  if (!target) {
    Message.warning('未找到可访问的 URL')
    return
  }
  window.open(target, '_blank')
}

const exportToExcel = () => {
  if (results.value.length === 0) {
    Message.warning('没有可导出的数据')
    return
  }

  // Format data for excel sheet
  const exportData = results.value.map((item) => ({
    '目标 URL': item.url || '',
    'IP 地址': item.ip || '',
    端口: item.port || '',
    协议: item.protocol || '',
    网站标题: item.title || '',
    'ICP 备案': item.icp || '',
    地理位置: item.location || '',
  }))

  const worksheet = XLSX.utils.json_to_sheet(exportData)

  worksheet['!cols'] = [
    { wch: 30 }, // URL
    { wch: 15 }, // IP
    { wch: 8 }, // Port
    { wch: 10 }, // Protocol
    { wch: 40 }, // Title
    { wch: 20 }, // ICP
    { wch: 25 }, // Location
  ]

  const workbook = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(workbook, worksheet, engine || 'Search Results')

  const fileName = `${engine}_查询结果_${new Date().getTime()}.xlsx`
  XLSX.writeFile(workbook, fileName)
  Message.success(`成功导出 ${results.value.length} 条记录`)
}

onMounted(() => {
  loadCachedResults()
})

defineExpose({
  openConfig,
  openSyntax,
  toggleBatch,
  handleQuickCreateTask,
  handleQuickPocVerify,
  showSelection,
  selectedRows,
})
</script>

<style scoped>
.search-header {
  display: flex;
  align-items: flex-start;
  gap: 12px;
}

.search-input {
  flex: 1;
}

.search-options {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
</style>
