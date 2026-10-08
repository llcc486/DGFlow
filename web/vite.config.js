import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: '/',
  server: {
    proxy: {
      // Preserve the browser-facing Host so the control API can check the
      // complete same origin (scheme, hostname and port).
      '/api': { target: 'http://127.0.0.1:8765', changeOrigin: false },
    },
  },
})
