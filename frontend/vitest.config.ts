import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json'],
      include: ['src/**/*.{ts,tsx}'],
      // Pages are tested via E2E (Playwright) in tests/e2e/
      // Constants/trivial files don't need unit tests
      exclude: [
        'node_modules/',
        'src/app/**',  // Next.js pages - covered by E2E
        'src/lib/api-schema.d.ts',  // generated
        'src/lib/constants.ts',  // trivial
      ],
      thresholds: {
        // Thresholds apply to non-excluded code (lib, components, stores)
        // Pages are covered by E2E tests
        lines: 90,
        statements: 90,
        functions: 90,
        branches: 80,
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
