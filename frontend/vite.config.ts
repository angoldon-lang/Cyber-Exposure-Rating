import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      // In sviluppo il frontend parla con l'API senza problemi di CORS.
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  // `preview` serve il bundle di produzione in locale con lo stesso proxy,
  // utile per verifiche end-to-end prima del deploy.
  preview: {
    port: 4173,
    host: true,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: { outDir: 'dist', sourcemap: false, target: 'es2020' },
});
