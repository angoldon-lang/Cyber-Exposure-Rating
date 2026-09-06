import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Momento della compilazione, inserito nel bundle.
//
// L'interfaccia e' compilata dentro la propria immagine: quando qualcuno
// aggiorna e non vede cambiare nulla, la prima cosa da sapere e' se sta
// guardando la build nuova o una copia in cache. Senza un riferimento
// visibile la domanda non ha risposta, e si finisce a ricostruire piu'
// volte la stessa immagine.
const COMPILATO_IL = new Date().toISOString();

export default defineConfig({
  define: { __COMPILATO_IL__: JSON.stringify(COMPILATO_IL) },
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
