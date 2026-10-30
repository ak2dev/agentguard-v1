// Static site: no server code, no analytics, no third-party requests.
// Stylesheets are emitted as files (never inlined) so the CSP can forbid
// inline styles; the only script is a same-origin progressive enhancement.
import { defineConfig } from "astro/config";
import { satteri } from "@astrojs/markdown-satteri";
import frames from "./scripts/markdown-frames.mjs";

export default defineConfig({
  site: process.env.AG_SITE_URL ?? "https://agentguard-ak2dev.vercel.app",
  base: process.env.AG_SITE_BASE ?? "/",
  output: "static",
  trailingSlash: "always",
  build: {
    inlineStylesheets: "never",
    assets: "assets",
  },
  devToolbar: { enabled: false },
  // Never inline assets as data: URIs (fonts included); the CSP only allows same-origin files.
  vite: { build: { assetsInlineLimit: 0 } },
  markdown: {
    syntaxHighlight: false,
    // tables and code blocks in the redesign's frames (scripts/markdown-frames.mjs)
    processor: satteri({ hastPlugins: [frames] }),
  },
});
