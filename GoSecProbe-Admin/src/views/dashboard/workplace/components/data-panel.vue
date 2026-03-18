<template>
  <a-grid :cols="24" :row-gap="16" class="panel">
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <div class="stat-card">
        <div class="stat-icon assets-icon">
          <icon-storage />
        </div>
        <div class="stat-content">
          <div class="stat-label">ASSETS</div>
          <div class="stat-value">{{ stats.assets }}</div>
        </div>
      </div>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <div class="stat-card">
        <div class="stat-icon fingerprints-icon">
          <icon-find-replace />
        </div>
        <div class="stat-content">
          <div class="stat-label">FINGERPRINTS</div>
          <div class="stat-value">{{ stats.fingerprints }}</div>
        </div>
      </div>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <div class="stat-card">
        <div class="stat-icon vulnerabilities-icon">
          <icon-bug />
        </div>
        <div class="stat-content">
          <div class="stat-label">VULNERABILITIES</div>
          <div class="stat-value danger">{{ stats.vulnerabilities }}</div>
        </div>
      </div>
    </a-grid-item>
    <a-grid-item class="panel-col" :span="{ xs: 12, sm: 12, md: 12, lg: 12, xl: 12, xxl: 6 }">
      <div class="stat-card">
        <div class="stat-icon tasks-icon">
          <icon-check-circle />
        </div>
        <div class="stat-content">
          <div class="stat-label">TASKS</div>
          <div class="stat-value">{{ stats.tasks }}</div>
        </div>
      </div>
    </a-grid-item>
    <a-grid-item :span="24">
      <a-divider class="panel-border" />
    </a-grid-item>
  </a-grid>
</template>

<script lang="ts" setup>
import { reactive, onMounted } from 'vue'
import { getDashboardOverview } from '@/api/dashboard'

const stats = reactive({
  assets: 0,
  vulnerabilities: 0,
  tasks: 0,
  fingerprints: 0,
})

async function fetchOverview() {
  try {
    const { data } = await getDashboardOverview()
    if (data) {
      stats.assets = data.assets ?? 0
      stats.vulnerabilities = data.vulnerabilities ?? 0
      stats.tasks = data.tasks ?? 0
      stats.fingerprints = data.fingerprints ?? 0
    }
  } catch (e) {
    console.error('[DataPanel] fetchOverview failed', e)
  }
}

onMounted(fetchOverview)
</script>

<style lang="less" scoped>
.arco-grid.panel {
  margin-bottom: 0;
  padding: 20px 24px 0 24px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-top: none;
  border-radius: 0 0 8px 8px;
}

.panel-col {
  padding: 0 12px;
}

.stat-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  transition: all 0.3s ease;

  &:hover {
    border-color: var(--border-color-light);
    transform: translateY(-2px);
  }
}

.stat-icon {
  width: 56px;
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  font-size: 24px;

  &.assets-icon {
    background: rgba(0, 255, 136, 0.1);
    color: var(--primary-color);
    border: 1px solid var(--primary-color);
  }

  &.fingerprints-icon {
    background: rgba(0, 204, 255, 0.1);
    color: var(--secondary-color);
    border: 1px solid var(--secondary-color);
  }

  &.vulnerabilities-icon {
    background: rgba(255, 51, 102, 0.1);
    color: var(--danger-color);
    border: 1px solid var(--danger-color);
  }

  &.tasks-icon {
    background: rgba(255, 170, 0, 0.1);
    color: var(--warning-color);
    border: 1px solid var(--warning-color);
  }
}

.stat-content {
  flex: 1;
}

.stat-label {
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 11px;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-bottom: 4px;
}

.stat-value {
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 28px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1;

  &.danger {
    color: var(--danger-color);
    text-shadow: 0 0 10px rgba(255, 51, 102, 0.3);
  }
}

:deep(.panel-border) {
  border-color: var(--border-color);
  margin: 4px 0 0 0;
}
</style>
