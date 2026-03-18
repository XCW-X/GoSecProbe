<template>
  <div class="login-container">
    <canvas class="matrix-canvas" ref="matrixCanvas"></canvas>
    <div class="login-wrapper">
      <div class="login-card">
        <div class="login-header">
          <div class="logo-section">
            <div class="logo-icon">
              <span class="bracket">[</span>
              <span class="logo-text">GSP</span>
              <span class="bracket">]</span>
            </div>
          </div>
          <div class="title-section">
            <h1 class="main-title">GoSecProbe</h1>
            <p class="subtitle">Network Security Vulnerability Scanner</p>
            <div class="status-line">
              <span class="status-dot"></span>
              <span class="status-text">System Ready</span>
              <span class="terminal-cursor"></span>
            </div>
          </div>
        </div>

        <div class="login-body">
          <LoginForm />
        </div>

        <div class="login-footer">
          <div class="footer-info">
            <span class="info-item">
              <span class="label">VERSION:</span>
              <span class="value">v1.0.0</span>
            </span>
            <span class="info-item">
              <span class="label">BUILD:</span>
              <span class="value">{{ buildTime }}</span>
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref, onMounted, onUnmounted } from 'vue'
import LoginForm from './components/login-form.vue'

export default defineComponent({
  name: 'Login',
  components: {
    LoginForm,
  },
  setup() {
    const matrixCanvas = ref<HTMLCanvasElement | null>(null)
    const buildTime = ref(new Date().toISOString().split('T')[0])

    let animationId: number | null = null
    const drops: number[] = []
    const fontSize = 14
    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'

    const drawMatrix = () => {
      const canvas = matrixCanvas.value
      if (!canvas) return

      const ctx = canvas.getContext('2d')
      if (!ctx) return

      ctx.fillStyle = 'rgba(10, 14, 20, 0.05)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      ctx.fillStyle = '#00ff88'
      ctx.font = `${fontSize}px monospace`

      for (let i = 0; i < drops.length; i += 1) {
        const text = chars[Math.floor(Math.random() * chars.length)]
        ctx.fillText(text, i * fontSize, drops[i] * fontSize)

        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0
        }
        drops[i] += 1
      }

      animationId = requestAnimationFrame(drawMatrix)
    }

    const initCanvas = () => {
      const canvas = matrixCanvas.value
      if (!canvas) return

      canvas.width = window.innerWidth
      canvas.height = window.innerHeight

      const columns = Math.floor(canvas.width / fontSize)
      for (let i = 0; i < columns; i += 1) {
        drops[i] = Math.floor(Math.random() * (canvas.height / fontSize))
      }
    }

    const handleResize = () => {
      initCanvas()
    }

    onMounted(() => {
      initCanvas()
      drawMatrix()
      window.addEventListener('resize', handleResize)
    })

    onUnmounted(() => {
      if (animationId !== null) {
        cancelAnimationFrame(animationId)
      }
      window.removeEventListener('resize', handleResize)
    })

    return {
      matrixCanvas,
      buildTime,
    }
  },
})
</script>

<style lang="less" scoped>
.login-container {
  position: relative;
  width: 100vw;
  height: 100vh;
  background: var(--login-bg-gradient);
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
}

.matrix-canvas {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: 1;
  opacity: 0.15;
}

.login-wrapper {
  position: relative;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
}

.login-card {
  width: 480px;
  background: rgba(26, 33, 41, 0.95);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  box-shadow:
    0 0 40px rgba(0, 255, 136, 0.1),
    0 20px 60px rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(20px);
  overflow: hidden;
  position: relative;

  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--primary-color), var(--secondary-color), var(--danger-color), var(--primary-color));
    background-size: 300% 100%;
    animation: gradientMove 3s ease infinite;
  }
}

@keyframes gradientMove {
  0%,
  100% {
    background-position: 0% 50%;
  }
  50% {
    background-position: 100% 50%;
  }
}

.login-header {
  padding: 40px 40px 30px;
  text-align: center;
  border-bottom: 1px solid var(--border-color);
}

.logo-section {
  margin-bottom: 24px;
}

.logo-icon {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 16px 24px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
}

.bracket {
  font-size: 32px;
  font-weight: 700;
  color: var(--primary-color);
  text-shadow: 0 0 10px var(--primary-color);
}

.logo-text {
  font-size: 28px;
  font-weight: 800;
  color: var(--primary-color);
  letter-spacing: 4px;
  text-shadow: 0 0 20px var(--primary-color);
}

.title-section {
  .main-title {
    margin: 0 0 8px;
    font-size: 28px;
    font-weight: 700;
    color: var(--text-primary);
    font-family: 'JetBrains Mono', 'Consolas', monospace;
    letter-spacing: 2px;
  }

  .subtitle {
    margin: 0 0 20px;
    font-size: 13px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 3px;
  }
}

.status-line {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 12px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--primary-color);
  box-shadow: 0 0 10px var(--primary-color);
  animation: statusPulse 2s ease-in-out infinite;
}

@keyframes statusPulse {
  0%,
  100% {
    opacity: 1;
    transform: scale(1);
  }
  50% {
    opacity: 0.5;
    transform: scale(0.8);
  }
}

.status-text {
  color: var(--primary-color);
}

.terminal-cursor {
  width: 8px;
  height: 16px;
  background: var(--primary-color);
  animation: cursorBlink 1s step-end infinite;
}

@keyframes cursorBlink {
  0%,
  50% {
    opacity: 1;
  }
  51%,
  100% {
    opacity: 0;
  }
}

.login-body {
  padding: 40px;
}

.login-footer {
  padding: 20px 40px;
  border-top: 1px solid var(--border-color);
  background: var(--bg-tertiary);
}

.footer-info {
  display: flex;
  justify-content: space-between;
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 11px;
}

.info-item {
  display: flex;
  align-items: center;
  gap: 6px;

  .label {
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .value {
    color: var(--primary-color);
  }
}
</style>
