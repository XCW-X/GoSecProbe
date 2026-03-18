<template>
  <div class="container">
    <div class="left-side">
      <div class="panel">
        <Banner />
        <DataPanel />
        <VulnerabilityDetectionChart />
      </div>
      <a-grid :cols="24" :col-gap="16" :row-gap="16" style="margin-top: 16px">
        <a-grid-item :span="{ xs: 24, sm: 24, md: 24, lg: 12, xl: 12, xxl: 12 }">
          <NewPoc />
        </a-grid-item>
        <a-grid-item :span="{ xs: 24, sm: 24, md: 24, lg: 12, xl: 12, xxl: 12 }">
          <VulnerabilitiesPercent />
        </a-grid-item>
      </a-grid>
    </div>
    <div class="right-side">
      <a-grid :cols="24" :row-gap="16" class="right-grid">
        <a-grid-item class="panel flex-panel" :span="24">
          <ScanStatus class="fill-height-card" />
        </a-grid-item>
        <a-grid-item class="panel flex-panel" :span="24">
          <RiskReminders class="fill-height-card" />
        </a-grid-item>
      </a-grid>
    </div>
  </div>
</template>

<script lang="ts" setup>
import Banner from './components/banner.vue'
import DataPanel from './components/data-panel.vue'
import VulnerabilityDetectionChart from './components/vulnerability-detection-chart.vue'
import NewPoc from './components/new-poc.vue'
import VulnerabilitiesPercent from './components/vulnerabilities-percent.vue'
import ScanStatus from './components/scan-status.vue'
import RiskReminders from './components/risk-reminders.vue'
</script>

<script lang="ts">
export default {
  name: 'Dashboard', // If you want the include property of keep-alive to take effect, you must name the component
}
</script>

<style lang="less" scoped>
.container {
  background-color: var(--bg-primary);
  padding: 16px 20px;
  padding-bottom: 0;
  display: flex;
  height: 100%;
}

.left-side {
  flex: 1;
  overflow: auto;
}

.right-side {
  width: 280px;
  margin-left: 16px;
  display: flex;
  flex-direction: column;
}

.right-grid {
  flex: 1;
  display: flex !important;
  flex-direction: column;
}

.flex-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

:deep(.fill-height-card) {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  
  .arco-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
  }
  
  .arco-card-header {
    background-color: var(--bg-card);
    border-bottom: 1px solid var(--border-color);
    color: var(--text-primary);
    font-family: 'JetBrains Mono', 'Consolas', monospace;
  }
  
  .arco-card-body {
    flex: 1;
    overflow-y: auto;
  }
}

.panel {
  background-color: transparent;
  border-radius: 4px;
}

:deep(.panel-border) {
  margin-bottom: 0;
  border-bottom: 1px solid var(--border-color);
}

.moduler-wrap {
  border-radius: 4px;
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  
  :deep(.text) {
    font-size: 12px;
    text-align: center;
    color: var(--text-secondary);
    font-family: 'JetBrains Mono', 'Consolas', monospace;
  }

  :deep(.wrapper) {
    margin-bottom: 8px;
    text-align: center;
    cursor: pointer;

    &:last-child {
      .text {
        margin-bottom: 0;
      }
    }
    &:hover {
      .icon {
        color: var(--primary-color);
        background-color: rgba(0, 255, 136, 0.1);
      }
      .text {
        color: var(--primary-color);
      }
    }
  }

  :deep(.icon) {
    display: inline-block;
    width: 32px;
    height: 32px;
    margin-bottom: 4px;
    color: var(--text-muted);
    line-height: 32px;
    font-size: 16px;
    text-align: center;
    background-color: var(--bg-tertiary);
    border-radius: 4px;
    border: 1px solid var(--border-color);
    transition: all 0.2s ease;
  }
}
</style>

<style lang="less" scoped>
// responsive
.mobile {
  .container {
    display: block;
  }
  .right-side {
    width: 100%;
    margin-left: 0;
    margin-top: 16px;
  }
}
</style>
