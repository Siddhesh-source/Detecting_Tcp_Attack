import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/flows': 'http://localhost:8000',
      '/alerts': 'http://localhost:8000',
      '/stats': 'http://localhost:8000',
      '/metrics': 'http://localhost:8000',
      '/features': 'http://localhost:8000',
      '/layers': 'http://localhost:8000',
      '/capture': 'http://localhost:8000',
      '/upload': 'http://localhost:8000',
      '/export': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
});
