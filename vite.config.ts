import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// The window title comes from the same build configuration that tools/build.ts bundles.
const config = JSON.parse(readFileSync(process.env.STARRAIL_BUILD_CONFIG ?? 'config/development.json', 'utf8')) as { name: string };
const escaped = config.name.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
export default defineConfig(({ command }) => ({
  plugins: [react(), { name: 'brand-title', transformIndexHtml: html => html.replace('%BRAND_NAME%', escaped).replace('%DEV_CONNECT%', command === 'serve' ? ' ws://127.0.0.1:5173' : '') }], root: 'src/renderer', base: './',
  build: { outDir: '../../desktop/frontend/dist', emptyOutDir: true },
  server: { host: '127.0.0.1', port: 5173, strictPort: true },
}));
