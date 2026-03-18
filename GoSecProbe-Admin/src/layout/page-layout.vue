<template>
  <router-view v-slot="{ Component, route }">
    <transition name="fade" mode="out-in" appear>
      <div :key="route.name">
        <keep-alive :include="cacheList">
          <component :is="Component" :key="route.fullPath" />
        </keep-alive>
      </div>
    </transition>
  </router-view>
</template>

<script lang="ts" setup>
import { useTabBarStore } from '@/store'
import { computed } from 'vue'

const tabBarStore = useTabBarStore()

const cacheList = computed(() => tabBarStore.getCacheList)
</script>

<style scoped lang="less"></style>
