import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const nm = (p: string) => fileURLToPath(new URL(`./node_modules/${p}`, import.meta.url));

// The build goes straight into the Python app's static folder so there is one deployable unit.
export default defineConfig({
  plugins: [react()],
  build: { outDir: '../app/static', emptyOutDir: true },
  server: {
    port: 5173,
    // Local development: the Vite dev server proxies API and sign-in calls to the Python backend (uvicorn).
    proxy: {
      '/api': 'http://localhost:8000',
      '/signin-oidc': 'http://localhost:8000',
      '/signout-callback-oidc': 'http://localhost:8000',
    },
  },
  resolve: {
    // Pin one copy of each library so tests and app share the same React instance.
    alias: {
      '@testing-library/react': nm('@testing-library/react'),
      '@testing-library/user-event': nm('@testing-library/user-event'),
      '@testing-library/jest-dom': nm('@testing-library/jest-dom'),
      'react-router-dom': nm('react-router-dom'),
      'react-dom': nm('react-dom'),
      react: nm('react'),
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.test.{ts,tsx}'],
    setupFiles: ['./test-setup.ts'],
    css: false,
  },
});
