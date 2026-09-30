// End-to-end tests for the in-browser scanner, run against the built site served
// with the production headers from ../vercel.json. Uses an installed browser
// (no download): Chrome by default, e.g. PW_CHANNEL=msedge on Windows.
import { defineConfig } from "@playwright/test";

const port = 4400;
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 180_000,
  expect: { timeout: 120_000 },
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    channel: process.env.PW_CHANNEL || "chrome",
    headless: true,
  },
  webServer: {
    command: `node scripts/serve.mjs ${port}`,
    url: `http://127.0.0.1:${port}/scan/`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
