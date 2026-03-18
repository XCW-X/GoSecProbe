<template>
  <div class="container">
    <Breadcrumb :items="['menu.settings', 'menu.settings.engine']" />
    <a-card class="general-card" title="参数配置">
      <a-form :model="form" layout="vertical" @submit="handleSubmit">
        <a-tabs default-active-key="1" type="rounded">
          <a-tab-pane key="1" title="扫描配置">
            <div class="tab-content">
              <a-row :gutter="24">
                <a-col :span="12">
                  <a-form-item field="network_card" label="网卡接口">
                    <a-select v-model="form.network_card" placeholder="选择扫描网卡">
                      <a-option v-for="item in interfaces" :key="item.name" :value="item.name">
                        {{ item.name }} ({{ (item.ips || []).join(', ') }})
                      </a-option>
                    </a-select>
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item field="concurrency" label="并发线程数">
                    <a-input-number v-model="form.concurrency" :min="1" :max="1000" />
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item field="timeout" label="全局超时 (秒)">
                    <a-input-number v-model="form.timeout" :min="1" :max="300" />
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item field="retries" label="重试次数">
                    <a-input-number v-model="form.retries" :min="0" :max="10" />
                  </a-form-item>
                </a-col>
              </a-row>
            </div>
          </a-tab-pane>
          <a-tab-pane key="2" title="代理设置">
            <div class="tab-content">
              <a-row :gutter="24">
                <a-col :span="24">
                  <a-form-item field="proxy_type" label="代理类型">
                    <a-select v-model="form.proxy_type" placeholder="选择代理类型">
                      <a-option value="">不使用代理</a-option>
                      <a-option value="http">HTTP 代理</a-option>
                      <a-option value="socks5">SOCKS5 代理</a-option>
                    </a-select>
                  </a-form-item>
                </a-col>
                <a-col :span="24" v-if="form.proxy_type">
                  <a-form-item field="proxy_url" label="代理地址">
                    <a-input v-model="form.proxy_url" placeholder="例如: http://127.0.0.1:8080 或 socks5://127.0.0.1:1080" />
                  </a-form-item>
                </a-col>
              </a-row>
            </div>
          </a-tab-pane>
          <a-tab-pane key="3" title="反连设置">
            <div class="tab-content">
              <a-row :gutter="24">
                <a-col :span="24">
                  <a-form-item field="reverse_dnslog_domain" label="DnsLog 域名">
                    <a-input v-model="form.reverse_dnslog_domain" placeholder="例如: dnslog.cn" />
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item field="reverse_rmi_server" label="RMI 服务器">
                    <a-input v-model="form.reverse_rmi_server" placeholder="rmi://127.0.0.1:1099" />
                  </a-form-item>
                </a-col>
                <a-col :span="12">
                  <a-form-item field="reverse_ldap_server" label="LDAP 服务器">
                    <a-input v-model="form.reverse_ldap_server" placeholder="ldap://127.0.0.1:1389" />
                  </a-form-item>
                </a-col>
                <a-col :span="24">
                  <a-form-item field="reverse_http_server" label="HTTP 服务器">
                    <a-input v-model="form.reverse_http_server" placeholder="http://127.0.0.1:8080" />
                  </a-form-item>
                </a-col>
              </a-row>
            </div>
          </a-tab-pane>
        </a-tabs>
        <div class="footer">
          <a-button type="primary" html-type="submit" :loading="loading">保存配置</a-button>
        </div>
      </a-form>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, onMounted } from 'vue'
import { Message } from '@arco-design/web-vue'
import { getSystemSettings, updateSystemSettings, getNetworkInterfaces, NetworkInterface, SystemSettings } from '@/api/setting'

const loading = ref(false)
const interfaces = ref<NetworkInterface[]>([])
const form = reactive<SystemSettings>({
  network_card: '',
  concurrency: 10,
  timeout: 10,
  retries: 2,
  proxy_type: '',
  proxy_url: '',
  reverse_dnslog_domain: '',
  reverse_rmi_server: '',
  reverse_ldap_server: '',
  reverse_http_server: '',
})

const fetchData = async () => {
  try {
    const [settingsRes, interfacesRes] = await Promise.all([getSystemSettings(), getNetworkInterfaces()])

    if ((settingsRes as any).data) {
      Object.assign(form, (settingsRes as any).data)
    }

    if ((interfacesRes as any).data) {
      interfaces.value = (interfacesRes as any).data
    }
  } catch (err) {
    Message.error('加载配置失败')
  }
}

onMounted(() => {
  fetchData()
})

const handleSubmit = async () => {
  loading.value = true
  try {
    const data: SystemSettings = {
      network_card: form.network_card,
      concurrency: form.concurrency,
      timeout: form.timeout,
      retries: form.retries,
      proxy_type: form.proxy_type,
      proxy_url: form.proxy_type ? form.proxy_url : '',
      reverse_dnslog_domain: form.reverse_dnslog_domain,
      reverse_rmi_server: form.reverse_rmi_server,
      reverse_ldap_server: form.reverse_ldap_server,
      reverse_http_server: form.reverse_http_server,
    }
    console.log('提交数据:', data)
    await updateSystemSettings(data)
    Message.success('配置已更新')
  } catch (err: any) {
    console.error('保存失败:', err)
    Message.error(err.response?.data?.msg || err.message || '保存失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}
.tab-content {
  padding-top: 20px;
  min-height: 200px;
}
.footer {
  margin-top: 24px;
  display: flex;
  justify-content: flex-end;
}
</style>
