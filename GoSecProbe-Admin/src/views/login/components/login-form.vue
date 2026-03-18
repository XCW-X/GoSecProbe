<template>
  <div class="login-form-wrapper">
    <div class="form-header">
      <div class="terminal-prompt">
        <span class="prompt-symbol">&gt;</span>
        <span class="prompt-text">AUTHENTICATION REQUIRED</span>
      </div>
    </div>
    
    <div class="login-form-error" v-if="errorMessage">
      <span class="error-icon">[!]</span>
      <span class="error-text">{{ errorMessage }}</span>
    </div>
    
    <a-form ref="loginForm" :model="userInfo" class="login-form" layout="vertical" @submit="handleSubmit">
      <a-form-item
        field="username"
        :rules="[{ required: true, message: 'Username is required' }]"
        :validate-trigger="['change', 'blur']"
        hide-label
      >
        <div class="input-wrapper">
          <span class="input-label">USERNAME:</span>
          <a-input v-model="userInfo.username" placeholder="Enter username" class="terminal-input">
          </a-input>
        </div>
      </a-form-item>
      
      <a-form-item
        field="password"
        :rules="[{ required: true, message: 'Password is required' }]"
        :validate-trigger="['change', 'blur']"
        hide-label
      >
        <div class="input-wrapper">
          <span class="input-label">PASSWORD:</span>
          <a-input-password v-model="userInfo.password" placeholder="Enter password" allow-clear class="terminal-input">
          </a-input-password>
        </div>
      </a-form-item>
      
      <div class="form-actions">
        <a-checkbox :model-value="loginConfig.rememberPassword" @change="setRememberPassword as any" class="remember-checkbox">
          <span class="checkbox-label">[X] Remember credentials</span>
        </a-checkbox>
      </div>
      
      <a-button type="primary" html-type="submit" long :loading="loading" class="login-btn">
        <template #icon v-if="!loading">
          <span class="btn-arrow">→</span>
        </template>
        <span class="btn-text">{{ loading ? 'AUTHENTICATING...' : 'INITIATE SCAN' }}</span>
      </a-button>
    </a-form>
    
    <div class="form-footer">
      <div class="terminal-line">
        <span class="line-prefix">$</span>
        <span class="line-text">system initialized</span>
        <span class="terminal-cursor"></span>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import type { LoginData } from '@/api/user'
import useLoading from '@/hooks/loading'
import { useUserStore } from '@/store'
import { Message } from '@arco-design/web-vue'
import { ValidatedError } from '@arco-design/web-vue/es/form/interface'
import { useStorage } from '@vueuse/core'
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const errorMessage = ref('')
const { loading, setLoading } = useLoading()
const userStore = useUserStore()

const loginConfig = useStorage('login-config', {
  rememberPassword: true,
  username: 'admin',
  password: 'Qaz@123#', 
})

const userInfo = reactive({
  username: loginConfig.value.username,
  password: loginConfig.value.password,
})

const handleSubmit = async ({ errors, values }: { errors: Record<string, ValidatedError> | undefined; values: Record<string, any> }) => {
  if (loading.value) return
  if (!errors) {
    setLoading(true)
    errorMessage.value = ''
    try {
      await userStore.login(values as LoginData)
      const { redirect, ...othersQuery } = router.currentRoute.value.query
      router.push({
        name: (redirect as string) || 'Workplace',
        query: {
          ...othersQuery,
        },
      })
      Message.success('Access granted')
      const { rememberPassword } = loginConfig.value
      const { username, password } = values
      loginConfig.value.username = rememberPassword ? username : ''
      loginConfig.value.password = rememberPassword ? password : ''
    } catch (err) {
      errorMessage.value = (err as Error).message || 'Authentication failed'
    } finally {
      setLoading(false)
    }
  }
}

const setRememberPassword = (value: boolean) => {
  loginConfig.value.rememberPassword = value
}
</script>

<style lang="less" scoped>
.login-form-wrapper {
  width: 100%;
}

.form-header {
  margin-bottom: 32px;
}

.terminal-prompt {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
}

.prompt-symbol {
  color: var(--primary-color);
  font-weight: 700;
  font-size: 16px;
}

.prompt-text {
  color: var(--text-primary);
  font-size: 13px;
  letter-spacing: 2px;
  text-transform: uppercase;
}

.login-form-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  margin-bottom: 20px;
  background: rgba(255, 51, 102, 0.1);
  border: 1px solid var(--danger-color);
  border-radius: 6px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 12px;
}

.error-icon {
  color: var(--danger-color);
  font-weight: 700;
}

.error-text {
  color: var(--danger-color);
}

.login-form {
  .input-wrapper {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 20px;
  }

  .input-label {
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 1px;
  }
}

.terminal-input {
  :deep(.arco-input-wrapper),
  :deep(.arco-input) {
    background: var(--bg-tertiary) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 4px !important;
    color: var(--text-primary) !important;
    font-family: 'JetBrains Mono', 'Consolas', monospace !important;
    font-size: 14px !important;
    padding: 12px 16px !important;
    transition: all 0.2s ease;

    &:hover {
      border-color: var(--border-color-light) !important;
    }

    &.arco-input-focus {
      border-color: var(--primary-color) !important;
      box-shadow: 0 0 0 3px rgba(0, 255, 136, 0.1) !important;
    }

    &::placeholder {
      color: var(--text-muted) !important;
    }
  }
}

.form-actions {
  margin-bottom: 24px;
}

.remember-checkbox {
  :deep(.arco-checkbox) {
    .arco-checkbox-text {
      font-family: 'JetBrains Mono', 'Consolas', monospace;
      font-size: 12px;
      color: var(--text-secondary);
    }
  }
}

.checkbox-label {
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 12px;
  color: var(--text-secondary);
}

.login-btn {
  height: 48px !important;
  border-radius: 4px !important;
  font-family: 'JetBrains Mono', 'Consolas', monospace !important;
  font-size: 13px !important;
  font-weight: 700 !important;
  letter-spacing: 2px !important;
  text-transform: uppercase !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  gap: 10px !important;
  transition: all 0.3s ease !important;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 30px rgba(0, 255, 136, 0.3);
  }

  .btn-arrow {
    font-size: 18px;
    font-weight: 700;
  }
}

.form-footer {
  margin-top: 24px;
}

.terminal-line {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 11px;
}

.line-prefix {
  color: var(--primary-color);
  font-weight: 700;
}

.line-text {
  color: var(--text-secondary);
}

.terminal-cursor {
  width: 8px;
  height: 14px;
  background: var(--primary-color);
  animation: cursorBlink 1s step-end infinite;
}

@keyframes cursorBlink {
  0%, 50% { opacity: 1; }
  51%, 100% { opacity: 0; }
}
</style>
