<template>
  <div class="navbar">
    <div class="left-side">
      <a-space>
        <icon-menu-fold
          v-if="!topMenu && appStore.device === 'mobile'"
          style="font-size: 22px; cursor: pointer"
          @click="toggleDrawerMenu"
        />
      </a-space>
    </div>
    <ul class="right-side">
      <!-- 语言切换 -->
      <li>
        <a-tooltip :content="$t('settings.language')">
          <a-button class="nav-btn" type="outline" :shape="'circle'" @click="setDropDownVisible">
            <template #icon>
              <icon-language />
            </template>
          </a-button>
        </a-tooltip>
        <a-dropdown trigger="click" @select="changeLocale as any">
          <div ref="triggerBtn" class="trigger-btn"></div>
          <template #content>
            <a-doption v-for="item in locales" :key="item.value" :value="item.value">
              <template #icon>
                <icon-check v-show="item.value === currentLocale" />
              </template>
              {{ item.label }}
            </a-doption>
          </template>
        </a-dropdown>
      </li>

      <!-- 主题切换 -->
      <li>
        <a-tooltip
          :content="
            theme === 'light' ? $t('settings.navbar.theme.toDark') : $t('settings.navbar.theme.toLight')
          "
        >
          <a-button class="nav-btn" type="outline" :shape="'circle'" @click="handleToggleTheme">
            <template #icon>
              <icon-moon-fill v-if="theme === 'dark'" />
              <icon-sun-fill v-else />
            </template>
          </a-button>
        </a-tooltip>
      </li>

      <!-- 消息通知（动态红点/数字） -->
      <li>
        <a-tooltip :content="$t('settings.navbar.alerts')">
          <div class="message-box-trigger" @click="handleOpenNotification">
            <!-- 高危及以上：显示数字徽标 -->
            <a-badge v-if="notifSummary.high_count > 0" :count="notifSummary.high_count" :max-count="99">
              <a-button class="nav-btn" type="outline" :shape="'circle'">
                <icon-notification />
              </a-button>
            </a-badge>
            <!-- 有漏洞但无高危：仅显示红点 -->
            <a-badge v-else-if="notifSummary.has_vuln" dot>
              <a-button class="nav-btn" type="outline" :shape="'circle'">
                <icon-notification />
              </a-button>
            </a-badge>
            <!-- 无漏洞：无徽标 -->
            <a-button v-else class="nav-btn" type="outline" :shape="'circle'">
              <icon-notification />
            </a-button>
          </div>
        </a-tooltip>
        <a-popover
          trigger="click"
          :arrow-style="{ display: 'none' }"
          :content-style="{ padding: 0, minWidth: '380px' }"
          content-class="message-popover"
        >
          <div ref="refBtn" class="ref-btn"></div>
          <template #content>
            <MessageBox ref="messageBoxRef" />
          </template>
        </a-popover>
      </li>

      <!-- 全屏 -->
      <li>
        <a-tooltip
          :content="
            isFullscreen ? t('settings.navbar.screen.toExit') : t('settings.navbar.screen.toFull')
          "
        >
          <a-button class="nav-btn" type="outline" :shape="'circle'" @click="toggleFullScreen">
            <template #icon>
              <icon-fullscreen-exit v-if="isFullscreen" />
              <icon-fullscreen v-else />
            </template>
          </a-button>
        </a-tooltip>
      </li>

      <!-- 用户头像 / 退出 -->
      <li>
        <a-dropdown trigger="click">
          <a-avatar :size="32" :style="{ marginRight: '8px' }">
            <img alt="avatar" :src="avatar" />
          </a-avatar>
          <template #content>
            <a-doption>
              <a-space @click="handleLogout">
                <icon-export />
                <span>
                  {{ t('messageBox.logout') }}
                </span>
              </a-space>
            </a-doption>
          </template>
        </a-dropdown>
      </li>
    </ul>
  </div>
</template>

<script lang="ts" setup>
import { getNotificationSummary, type VulnNotificationSummary } from '@/api/notification'
import useLocale from '@/hooks/locale'
import useUser from '@/hooks/user'
import { LOCALE_OPTIONS } from '@/locale'
import { useAppStore, useUserStore } from '@/store'
import { useDark, useFullscreen, useToggle } from '@vueuse/core'
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import MessageBox from '../message-box/index.vue'

const { t } = useI18n()
const appStore = useAppStore()
const userStore = useUserStore()
const { logout } = useUser()
const { changeLocale, currentLocale }: any = useLocale()
const { isFullscreen, toggle: toggleFullScreen } = useFullscreen()
const locales = [...LOCALE_OPTIONS]
const avatar = computed(() => userStore.avatar)
const theme = computed(() => appStore.theme)
const topMenu = computed(() => appStore.topMenu && appStore.menu)

const isDark = useDark({
  selector: 'body',
  attribute: 'arco-theme',
  valueDark: 'dark',
  valueLight: 'light',
  storageKey: 'arco-theme',
  onChanged(dark: boolean) {
    appStore.toggleTheme(dark)
  },
})
const toggleTheme = useToggle(isDark)
const handleToggleTheme = () => toggleTheme()

const refBtn = ref()
const triggerBtn = ref()
const messageBoxRef = ref()

// ── 通知 Badge 数据 ──
const notifSummary = ref<VulnNotificationSummary>({
  has_vuln: false,
  high_count: 0,
  unread_count: 0,
})

async function refreshNotifSummary() {
  try {
    const res = await getNotificationSummary()
    // 拦截器 return res（即 HTTP body: {code,msg,data}）
    // axios 泛型 <VulnNotificationSummary> 对应 .data 字段
    if (res.data) {
      notifSummary.value = res.data
    }
  } catch {
    /* ignore */
  }
}

// 轮询：每 30 秒刷新一次通知摘要
let pollTimer: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  refreshNotifSummary()
  pollTimer = setInterval(refreshNotifSummary, 30000)
})
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})

// 点击铃铛按钮：展开弹出层，同时刷新通知列表
const handleOpenNotification = () => {
  const event = new MouseEvent('click', { view: window, bubbles: true, cancelable: true })
  refBtn.value?.dispatchEvent(event)
  setTimeout(() => {
    messageBoxRef.value?.refresh?.()
    refreshNotifSummary()
  }, 50)
}

const handleLogout = () => logout()

const setDropDownVisible = () => {
  const event = new MouseEvent('click', { view: window, bubbles: true, cancelable: true })
  triggerBtn.value?.dispatchEvent(event)
}

const toggleDrawerMenu = inject('toggleDrawerMenu') as () => void
</script>

<style scoped lang="less">
.navbar {
  display: flex;
  justify-content: space-between;
  height: 100%;
  background-color: var(--color-bg-2);
  border-bottom: 1px solid var(--color-border);
  position: fixed;
  top: 0;
  right: 0;
  left: 0;
  height: 60px;
  z-index: 99;
}

.left-side {
  display: flex;
  align-items: center;
  padding-left: 20px;
}

.right-side {
  display: flex;
  padding-right: 20px;
  list-style: none;

  :deep(.locale-select) {
    border-radius: 20px;
  }

  li {
    display: flex;
    align-items: center;
    padding: 0 10px;
  }

  a {
    color: var(--color-text-1);
    text-decoration: none;
  }

  .nav-btn {
    border-color: rgb(var(--gray-2));
    color: rgb(var(--gray-8));
    font-size: 16px;
  }

  .trigger-btn,
  .ref-btn {
    position: absolute;
    bottom: 14px;
  }

  .trigger-btn {
    margin-left: 14px;
  }
}
</style>

<style lang="less">
.message-popover {
  .arco-popover-content {
    margin-top: 0;
  }
}

.arco-dropdown-list-wrapper {
  max-height: 100vh !important;
}
</style>
