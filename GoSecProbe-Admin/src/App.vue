<template>
  <a-config-provider :locale="locale">
    <router-view />
  </a-config-provider>
</template>

<script lang="ts" setup>
import { computed, watch } from 'vue'
import zhCN from '@arco-design/web-vue/es/locale/lang/zh-cn'
import enUS from '@arco-design/web-vue/es/locale/lang/en-us'
import useLocale from '@/hooks/locale'
import { useAppStore } from '@/store'

const { currentLocale } = useLocale()
const appStore = useAppStore()

const locale = computed(() => {
  switch (currentLocale.value) {
    case 'zh-CN':
      return zhCN
    case 'en-US':
      return enUS
    default:
      return enUS
  }
})

// 监听主题变化
watch(
  () => appStore.theme,
  (val) => {
    if (val === 'dark') {
      document.body.setAttribute('arco-theme', 'dark')
    } else {
      document.body.removeAttribute('arco-theme')
    }
  },
  { immediate: true }
)
</script>
