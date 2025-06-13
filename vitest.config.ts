import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.spec.ts', 'test/**/*.e2e-spec.ts'],
    exclude: ['node_modules', 'dist', 'coverage', 'frontend', 'scripts'],
    coverage: {
      reporter: ['text', 'html'],
      provider: 'v8',
    },
  },
});
