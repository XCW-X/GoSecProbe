<template>
  <a-layout class="layout" :class="{ mobile: appStore.hideMenu }">
    <div v-if="navbar" class="layout-navbar">
      <NavBar />
    </div>
    <a-layout>
      <a-layout>
        <a-layout-sider
          v-if="renderMenu"
          v-show="!hideMenu"
          class="layout-sider"
          :breakpoint="'xl'"
          :collapsible="true"
          :width="menuWidth"
          :style="{ paddingTop: navbar ? '60px' : '' }"
          :hide-trigger="true"
          @collapse="setCollapsed"
        >
          <div class="menu-wrapper">
            <div class="left-side">
              <div class="logo-container">
                <span class="logo-bracket">[</span>
                <span class="logo-text">GSP</span>
                <span class="logo-bracket">]</span>
              </div>
            </div>
            <Menu />
          </div>
        </a-layout-sider>
        <a-drawer
          v-if="hideMenu"
          :visible="drawerVisible"
          placement="left"
          :footer="false"
          mask-closable
          :closable="false"
          @cancel="drawerCancel"
        >
          <Menu />
        </a-drawer>
        <a-layout class="layout-content" :style="paddingStyle">
          <TabBar v-if="appStore.tabBar" />
          <a-layout-content>
            <PageLayout />
          </a-layout-content>
          <Footer v-if="footer" />
        </a-layout>
      </a-layout>
    </a-layout>
  </a-layout>
</template>

<script lang="ts" setup>
import Footer from '@/components/footer/index.vue'
import Menu from '@/components/menu/index.vue'
import NavBar from '@/components/navbar/index.vue'
import TabBar from '@/components/tab-bar/index.vue'
import usePermission from '@/hooks/permission'
import useResponsive from '@/hooks/responsive'
import { useAppStore, useUserStore } from '@/store'
import { computed, onMounted, provide, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageLayout from './page-layout.vue'

const isInit = ref(false)
const appStore = useAppStore()
const userStore = useUserStore()
const router = useRouter()
const route = useRoute()
const permission = usePermission()
useResponsive(true)
const navbarHeight = `60px`
const navbar = computed(() => appStore.navbar)
const renderMenu = computed(() => appStore.menu && !appStore.topMenu)
const hideMenu = computed(() => appStore.hideMenu)
const footer = computed(() => appStore.footer)
const menuWidth = computed(() => {
  return appStore.menuCollapse ? 48 : appStore.menuWidth
})
const paddingStyle = computed(() => {
  const paddingLeft = renderMenu.value && !hideMenu.value ? { paddingLeft: `${menuWidth.value}px` } : {}
  const paddingTop = navbar.value ? { paddingTop: navbarHeight } : {}
  return { ...paddingLeft, ...paddingTop }
})
const setCollapsed = (val: boolean) => {
  if (!isInit.value) return // for page initialization menu state problem
  appStore.updateSettings({ menuCollapse: val })
}
watch(
  () => userStore.role,
  (roleValue) => {
    if (roleValue && !permission.accessRouter(route)) router.push({ name: 'notFound' })
  }
)
const drawerVisible = ref(false)
const drawerCancel = () => {
  drawerVisible.value = false
}
provide('toggleDrawerMenu', () => {
  drawerVisible.value = !drawerVisible.value
})
onMounted(() => {
  isInit.value = true
})
</script>

<style scoped lang="less">
@nav-size-height: 60px;
@layout-max-width: 1100px;

.layout {
  width: 100%;
  height: 100%;
  background-color: var(--bg-primary);

  .layout-sider {
    background: var(--bg-secondary) !important;
    position: fixed;
    top: 0;
    left: 0;
    z-index: 99;
    height: 100%;
    padding-top: 0 !important;
    border-right: 1px solid var(--border-color);

    .left-side {
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg-secondary);
      height: 60px;
      border-bottom: 1px solid var(--border-color);
    }

    .logo-container {
      display: flex;
      align-items: center;
      gap: 4px;
      font-family: 'JetBrains Mono', 'Consolas', monospace;
    }

    .logo-bracket {
      font-size: 24px;
      font-weight: 700;
      color: var(--primary-color);
      text-shadow: 0 0 10px var(--primary-color);
    }

    .logo-text {
      font-size: 20px;
      font-weight: 800;
      color: var(--primary-color);
      letter-spacing: 3px;
      text-shadow: 0 0 15px var(--primary-color);
    }

    > :deep(.arco-layout-sider-children) {
      overflow-y: hidden;
      top: 0;
    }

    .menu-wrapper {
      height: 100%;
      overflow: auto;
      overflow-x: hidden;

      :deep(.arco-menu) {
        height: calc(100% - 60px) !important;
        background-color: var(--bg-secondary) !important;

        ::-webkit-scrollbar {
          width: 8px;
          height: 4px;
        }

        ::-webkit-scrollbar-thumb {
          border: 2px solid transparent;
          background-clip: padding-box;
          border-radius: 4px;
          background-color: var(--border-color);
        }

        ::-webkit-scrollbar-thumb:hover {
          background-color: var(--border-color-light);
        }

        .arco-menu-item,
        .arco-menu-pop-header,
        .arco-menu-inline-header {
          color: var(--text-secondary) !important;
          font-family: 'JetBrains Mono', 'Consolas', monospace;
          font-size: 13px;
          transition: all 0.2s ease;

          &:hover {
            color: var(--primary-color) !important;
            background-color: var(--bg-tertiary) !important;
          }

          &.arco-menu-selected {
            color: var(--primary-color) !important;
            background-color: rgba(0, 255, 136, 0.05) !important;
            border-right: 2px solid var(--primary-color);
          }
        }

        .arco-menu-icon {
          color: var(--text-muted) !important;
          margin-right: 10px;
          transition: color 0.2s ease;

          &:hover,
          .arco-menu-item:hover &,
          .arco-menu-selected & {
            color: var(--primary-color) !important;
          }
        }
      }
    }
  }

  .layout-content {
    min-width: @layout-max-width;
    min-height: 100vh;
    overflow-y: hidden;
    background-color: var(--bg-primary);
    transition: all 0.2s cubic-bezier(0.34, 0.69, 0.1, 1);

    .layout-navbar {
      transition: all 0.2s cubic-bezier(0.34, 0.69, 0.1, 1);
      position: fixed;
      top: 0;
      left: 250px;
      z-index: 100;
      width: 100%;
      min-width: @layout-max-width;
      height: @nav-size-height;
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border-color);
    }
  }

  .arco-layout-sider-collapsed {
    .left-side {
      width: 48px;

      .logo-container {
        .logo-text {
          display: none;
        }
      }
    }

    + .layout-content {
      .layout-navbar {
        left: 48px !important;

        .navbar {
          width: calc(100% - 48px) !important;
        }
      }
    }
  }
}
</style>
