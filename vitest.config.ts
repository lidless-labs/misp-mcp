import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/integration.test.ts", "node_modules"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
    },
  },
});
