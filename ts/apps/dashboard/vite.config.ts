import tanstackRouter from '@tanstack/router-plugin/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const apiServer = 'http://127.0.0.1:4101'

export default defineConfig({
  server: {
    host: '127.0.0.1',
    port: 4102,
    proxy: {
      '/dashboard.bff.MeService': apiServer,
      '/dashboard.bff.AdminService': apiServer,
      '/dashboard.bff.CertificateService': apiServer,
      '/cert/download': apiServer,
      '/cert/ca': apiServer,
    },
  },
  plugins: [tanstackRouter({ target: 'react', autoCodeSplitting: true }), react()],
  build: {
    outDir: 'dist',
  },
})
