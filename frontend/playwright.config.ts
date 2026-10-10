import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  use: {
    baseURL: process.env.WORKBENCH_TEST_URL || "http://127.0.0.1:8765",
    viewport: { width: 1440, height: 1000 },
  },
  workers: 1,
  reporter: "list",
  timeout: 45000,
});
