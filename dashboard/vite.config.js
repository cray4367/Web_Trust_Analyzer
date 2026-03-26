import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/monitor/',   // assets load from /monitor/assets/... so Nginx routes them to this container
  server: {
    port: 3000,
    open: true,
  },
});