<template>
  <a-col class="banner">
    <div class="banner-content">
      <div class="terminal-line">
        <span class="prefix">[SYSTEM]</span>
        <span class="text">Welcome back, Operator</span>
        <span class="cursor"></span>
      </div>
      <div class="status-indicators">
        <span class="status-item">
          <span class="dot online"></span>
          <span class="label">ONLINE</span>
        </span>
        <span class="status-item">
          <span class="dot ready"></span>
          <span class="label">READY</span>
        </span>
      </div>
    </div>
    <a-divider class="panel-border" />
  </a-col>
</template>

<script lang="ts" setup>
import { computed } from 'vue'
import { useUserStore } from '@/store'

const userStore = useUserStore()
const userInfo = computed(() => {
  return {
    name: userStore.name,
  }
})
</script>

<style scoped lang="less">
.banner {
  width: 100%;
  padding: 24px 24px 0 24px;
  background-color: var(--bg-card);
  border-radius: 8px 8px 0 0;
  border: 1px solid var(--border-color);
  border-bottom: none;
}

.banner-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.terminal-line {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
}

.prefix {
  color: var(--primary-color);
  font-weight: 700;
  font-size: 12px;
}

.text {
  color: var(--text-primary);
  font-size: 14px;
}

.cursor {
  width: 8px;
  height: 16px;
  background: var(--primary-color);
  animation: cursorBlink 1s step-end infinite;
}

@keyframes cursorBlink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0; }
}

.status-indicators {
  display: flex;
  gap: 24px;
}

.status-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 11px;
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;

  &.online {
    background: var(--secondary-color);
    box-shadow: 0 0 10px var(--secondary-color);
    animation: pulse 2s ease-in-out infinite;
  }

  &.ready {
    background: var(--primary-color);
    box-shadow: 0 0 10px var(--primary-color);
    animation: pulse 2s ease-in-out infinite 0.5s;
  }
}

@keyframes pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.5; transform: scale(0.8); }
}

.label {
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 1px;
}

:deep(.panel-border) {
  border-color: var(--border-color);
}
</style>
