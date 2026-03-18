<template>
  <div class="container">
    <Breadcrumb :items="['menu.user', 'menu.user.setting']" />
    <a-row style="margin-bottom: 16px">
      <a-col :span="24">
        <UserPanel />
      </a-col>
    </a-row>

    <a-card class="general-card">
      <a-tabs default-active-key="password">
        <!-- 修改密码标签页 -->
        <a-tab-pane key="password" title="修改密码">
          <a-form
            ref="formRef"
            :model="formData"
            layout="vertical"
            :style="{ maxWidth: '480px', margin: '0 auto', padding: '20px 0' }"
            @submit="handleConfirm"
          >
            <a-form-item
              field="old_password"
              :label="$t('userSetting.changePassword.oldPassword')"
              :rules="[{ required: true, message: $t('userSetting.changePassword.error.oldPassword') }]"
            >
              <a-input-password
                v-model="formData.old_password"
                :placeholder="$t('userSetting.changePassword.placeholder.oldPassword')"
                allow-clear
              />
            </a-form-item>
            <a-form-item
              field="new_password"
              :label="$t('userSetting.changePassword.newPassword')"
              :rules="[
                { required: true, message: $t('userSetting.changePassword.error.newPassword') },
                { minLength: 6, message: $t('userSetting.changePassword.error.passwordLength') },
              ]"
            >
              <a-input-password
                v-model="formData.new_password"
                :placeholder="$t('userSetting.changePassword.placeholder.newPassword')"
                allow-clear
              />
            </a-form-item>
            <a-form-item
              field="confirm_password"
              :label="$t('userSetting.changePassword.confirmPassword')"
              :rules="[
                { required: true, message: $t('userSetting.changePassword.error.confirmPassword') },
                { validator: validateConfirmPassword },
              ]"
            >
              <a-input-password
                v-model="formData.confirm_password"
                :placeholder="$t('userSetting.changePassword.placeholder.confirmPassword')"
                allow-clear
              />
            </a-form-item>
            <a-form-item>
              <a-button type="primary" html-type="submit" long :loading="loading">
                {{ $t('userSetting.SecuritySettings.button.update') }}
              </a-button>
            </a-form-item>
          </a-form>
        </a-tab-pane>

        <!-- 注册新用户标签页 -->
        <a-tab-pane v-if="isAdmin" key="register" title="注册用户">
          <UserRegister />
        </a-tab-pane>
      </a-tabs>
    </a-card>
  </div>
</template>

<script lang="ts" setup>
import { reactive, ref, computed } from 'vue'
import { Message } from '@arco-design/web-vue'
import { useI18n } from 'vue-i18n'
import { changePassword } from '@/api/user'
import useUserStore from '@/store/modules/user'
import UserPanel from './components/user-panel.vue'
import UserRegister from './components/user-register.vue'

const { t } = useI18n()
const userStore = useUserStore()
const isAdmin = computed(() => userStore.role === 'admin')
const loading = ref(false)
const formRef = ref()

const formData = reactive({
  old_password: '',
  new_password: '',
  confirm_password: '',
})

const validateConfirmPassword = (value: any, callback: any) => {
  if (value !== formData.new_password) {
    callback(t('userSetting.changePassword.error.notMatch'))
  } else {
    callback()
  }
}

const handleConfirm = async ({ errors }: { errors: any }) => {
  if (errors) return

  loading.value = true
  try {
    await changePassword({
      old_password: formData.old_password,
      new_password: formData.new_password,
    })
    Message.success(t('userSetting.changePassword.success'))
    formRef.value.resetFields()
  } catch (err: any) {
    Message.error(err.message || t('userSetting.changePassword.error.failed'))
  } finally {
    loading.value = false
  }
}
</script>

<style scoped lang="less">
.container {
  padding: 0 20px 20px 20px;
}

.general-card {
  border-radius: 4px;
  border: none;
  :deep(.arco-card-header) {
    border-bottom: 1px solid var(--color-neutral-3);
  }
}
</style>
