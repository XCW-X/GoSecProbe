<template>
  <div class="container">
    <Breadcrumb :items="['menu.tools', 'menu.tools.searchEngine']" />
    <a-card class="general-card" :title="$t('menu.tools.searchEngine')">
      <template #extra>
        <a-space>
          <template v-if="!batchMode">
            <a-button type="outline" @click="openConfig">配置API</a-button>
            <a-button @click="openSyntax">查询语法</a-button>
            <a-button @click="toggleBatch">批量操作</a-button>
          </template>
          <template v-else>
            <a-tag color="blue">已选择 {{ selectedCount }} 条</a-tag>
            <a-button type="primary" :disabled="selectedCount === 0" @click="handleQuickCreateTask">快速新建任务</a-button>
            <a-button type="outline" :disabled="selectedCount === 0" @click="handleQuickPocVerify">快速POC验证</a-button>
            <a-button @click="toggleBatch">取消</a-button>
          </template>
        </a-space>
      </template>

      <a-tabs v-model:active-key="activeKey">
        <a-tab-pane key="hunter" title="Hunter">
          <div class="tab-content">
            <SearchEngineInterface ref="hunterRef" engine="Hunter" />
          </div>
        </a-tab-pane>
        <a-tab-pane key="fofa" title="FOFA">
          <div class="tab-content">
            <SearchEngineInterface ref="fofaRef" engine="FOFA" />
          </div>
        </a-tab-pane>
        <a-tab-pane key="quake" title="Quake">
          <div class="tab-content">
            <SearchEngineInterface ref="quakeRef" engine="Quake" />
          </div>
        </a-tab-pane>
      </a-tabs>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
import { computed, ref } from 'vue'
import SearchEngineInterface from './components/SearchEngineInterface.vue'

type SearchEngineExpose = {
  openConfig: () => void
  openSyntax: () => void
  toggleBatch: () => void
  handleQuickCreateTask: () => void
  handleQuickPocVerify: () => void
  showSelection: boolean
  selectedRows: number[]
}

const activeKey = ref('hunter')
const hunterRef = ref<SearchEngineExpose | null>(null)
const fofaRef = ref<SearchEngineExpose | null>(null)
const quakeRef = ref<SearchEngineExpose | null>(null)

const currentRef = computed(() => {
  if (activeKey.value === 'fofa') {
    return fofaRef.value
  }
  if (activeKey.value === 'quake') {
    return quakeRef.value
  }
  return hunterRef.value
})

const batchMode = computed(() => currentRef.value?.showSelection ?? false)
const selectedCount = computed(() => currentRef.value?.selectedRows?.length ?? 0)

const openConfig = () => {
  currentRef.value?.openConfig()
}

const openSyntax = () => {
  currentRef.value?.openSyntax()
}

const toggleBatch = () => {
  currentRef.value?.toggleBatch()
}

const handleQuickCreateTask = () => {
  currentRef.value?.handleQuickCreateTask()
}

const handleQuickPocVerify = () => {
  currentRef.value?.handleQuickPocVerify()
}
</script>

<style scoped lang="less">
.container {
  padding: 20px;
}
.tab-content {
  padding-top: 20px;
}
</style>
