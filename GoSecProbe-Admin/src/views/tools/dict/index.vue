<template>
  <div class="container">
    <Breadcrumb :items="['menu.tools', 'menu.tools.dict']" />
    <a-card class="general-card" :title="$t('menu.tools.dict')">
      <a-tabs v-model:active-key="activeTab" @change="onTabChange">
        <!-- ————— Tab 1: 字典管理 ————— -->
        <a-tab-pane key="1" title="字典管理">
          <div class="tab-content">
            <a-space style="margin-bottom: 16px">
              <a-button type="primary" @click="fetchData">
                <template #icon><icon-refresh /></template>
                刷新列表
              </a-button>
            </a-space>
            <a-table :data="dictData" :loading="loading" row-key="id" :pagination="{ pageSize: 15 }">
              <template #columns>
                <a-table-column title="字典名称" data-index="name" :width="220" ellipsis tooltip />
                <a-table-column title="类型" data-index="type" :width="90">
                  <template #cell="{ record }">
                    <a-tag :color="typeColor(record.type)">{{ typeLabel(record.type) }}</a-tag>
                  </template>
                </a-table-column>
                <a-table-column title="分类" data-index="category" :width="110" />
                <a-table-column title="大小" data-index="size" :width="90">
                  <template #cell="{ record }">{{ formatSize(record.size) }}</template>
                </a-table-column>
                <a-table-column title="行数" data-index="lines_cnt" :width="90" />
                <a-table-column title="创建时间" data-index="created_at" :width="160" />
                <a-table-column title="操作" :width="150">
                  <template #cell="{ record }">
                    <a-space>
                      <a-button type="text" size="small" @click="handleView(record)">查看</a-button>
                      <a-button type="text" size="small" @click="handleDownload(record)">导出</a-button>
                      <a-button type="text" size="small" status="danger" @click="handleDelete(record)">删除</a-button>
                    </a-space>
                  </template>
                </a-table-column>
              </template>
            </a-table>
          </div>
        </a-tab-pane>

        <!-- ————— Tab 2: 导入字典 ————— -->
        <a-tab-pane key="2" title="导入字典">
          <div class="tab-content">
            <a-upload
              draggable
              :action="uploadUrl"
              :headers="uploadHeaders"
              tip="点击或拖拽文件到此处上传（支持 .txt .dic 格式）"
              style="margin-bottom: 20px"
              @success="handleUploadSuccess"
              @error="handleUploadError"
            />
          </div>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 浏览字典弹窗 -->
    <a-modal v-model:visible="viewVisible" :title="`查看字典 - ${currentDictName}`" :footer="false" width="620px">
      <a-spin :loading="viewLoading" style="width: 100%">
        <a-textarea v-model="currentViewContent" readonly :auto-size="{ minRows: 15, maxRows: 22 }" style="font-family: monospace; font-size: 12px" />
      </a-spin>
    </a-modal>
  </div>
</template>

<script lang="ts" setup>
import { ref, reactive, onMounted } from 'vue'
import { Message, Modal } from '@arco-design/web-vue'
import {
  getDictList,
  syncDicts,
  viewDict,
  downloadDict,
  deleteDict,
} from '@/api/dict'
import { getToken } from '@/utils/auth'

const uploadUrl = `${import.meta.env.VITE_API_BASE_URL || ''}/api/dict/upload`
const uploadHeaders = { Authorization: `Bearer ${getToken()}` }

const activeTab = ref('1')
const loading = ref(false)
const dictData = ref<any[]>([])

const viewVisible = ref(false)
const viewLoading = ref(false)
const currentDictName = ref('')
const currentViewContent = ref('')

const formatSize = (bytes: number) => {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`
}

const typeLabel = (t: string) => {
  const m: Record<string, string> = { preset: '预设', custom: '自定义', generated: '生成' }
  return m[t] || t
}

const typeColor = (t: string) => {
  const m: Record<string, string> = { preset: 'blue', custom: 'green', generated: 'purple' }
  return m[t] || 'gray'
}

const fetchData = async () => {
  loading.value = true
  try {
    const res = await getDictList()
    dictData.value = res.data || []
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '获取字典列表失败')
  } finally {
    loading.value = false
  }
}

const onTabChange = (key: string | number) => {
  if (key === '1') fetchData()
}

const handleView = async (record: any) => {
  currentDictName.value = record.name
  viewVisible.value = true
  viewLoading.value = true
  currentViewContent.value = ''
  try {
    const res = await viewDict(record.id)
    currentViewContent.value = res.data || '（内容为空）'
  } catch (err: any) {
    Message.error(err.response?.data?.msg || '加载字典失败')
    currentViewContent.value = '加载失败'
  } finally {
    viewLoading.value = false
  }
}

const handleDownload = async (record: any) => {
  Message.info(`正在准备下载 ${record.name}...`)
  try {
    const res = await downloadDict(record.id)
    const blob = new Blob([res.data], { type: 'application/octet-stream' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.style.display = 'none'
    link.href = url
    link.setAttribute('download', record.name)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  } catch {
    Message.error('下载失败')
  }
}

const handleDelete = (record: any) => {
  Modal.warning({
    title: '确认删除',
    content: `确定要删除字典 "${record.name}" 吗？`,
    hideCancel: false,
    onOk: async () => {
      try {
        await deleteDict(record.id)
        Message.success('删除成功')
        fetchData()
      } catch (err: any) {
        Message.error(err.response?.data?.msg || '删除失败')
      }
    },
  })
}

const handleUploadSuccess = () => {
  Message.success('导入文件完成')
  syncDicts().then(() => fetchData())
}

const handleUploadError = () => {
  Message.error('文件导入失败')
}

onMounted(() => {
  fetchData()
})
</script>

<style scoped lang="less">
.container {
  padding: 20px;
}

.tab-content {
  padding-top: 20px;
}
</style>
