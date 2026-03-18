<template>
  <a-form
    ref="formRef"
    :model="formData"
    :rules="rules"
    layout="vertical"
    :style="{ maxWidth: '480px', margin: '0 auto', padding: '20px 0' }"
    @submit="handleSubmit"
  >
    <a-form-item field="username" label="用户名">
      <a-input v-model="formData.username" placeholder="请输入用户名（3-20个字符）" allow-clear />
    </a-form-item>

    <a-form-item field="password" label="密码">
      <a-input-password v-model="formData.password" placeholder="请输入密码（至少6位）" allow-clear />
    </a-form-item>

    <a-form-item field="confirmPassword" label="确认密码">
      <a-input-password v-model="formData.confirmPassword" placeholder="请再次输入密码" allow-clear />
    </a-form-item>

    <a-form-item>
      <a-button type="primary" html-type="submit" long :loading="submitting">立即注册</a-button>
    </a-form-item>
  </a-form>
</template>

<script lang="ts" setup>
import { ref, reactive } from 'vue'
import { Message } from '@arco-design/web-vue'
import { register } from '@/api/user'

const submitting = ref(false)
const formRef = ref()

const formData = reactive({
  username: '',
  password: '',
  confirmPassword: '',
})

const rules = {
  username: [
    { required: true, message: '请输入用户名' },
    {
      minLength: 3,
      maxLength: 20,
      message: '用户名长度必须在3-20个字符之间',
    },
  ],
  password: [
    { required: true, message: '请输入密码' },
    { minLength: 6, message: '密码长度至少为6位' },
  ],
  confirmPassword: [
    { required: true, message: '请再次输入密码' },
    {
      validator: (value: string, cb: any) => {
        if (value !== formData.password) {
          cb('两次输入的密码不一致')
        } else {
          cb()
        }
      },
    },
  ],
}

const handleReset = () => {
  formRef.value?.resetFields()
}

const handleSubmit = async ({ errors }: any) => {
  if (errors) return

  submitting.value = true
  try {
    await register({
      username: formData.username,
      password: formData.password,
    })
    Message.success('用户注册成功')
    handleReset()
  } catch (err: any) {
    Message.error(err.response?.data?.msg || err.message || '注册失败')
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped lang="less"></style>
