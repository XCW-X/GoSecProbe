<template>
  <div class="banner">
    <div class="banner-inner">
      <div class="static-banner">
        <img class="banner-image" :src="bannerImage" />
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import bannerImage from '@/assets/images/login-banner.png'
</script>

<style lang="less" scoped>
.banner {
  display: flex;
  align-items: center;
  justify-content: center;

  &-inner {
    flex: 1;
    height: 100%;
  }
}

.static-banner {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
}

.banner-image {
  width: 320px;
}
</style>
