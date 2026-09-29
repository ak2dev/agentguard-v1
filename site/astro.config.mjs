// Static site: no server code, no analytics, no third-party requests.
// Stylesheets are emitted as files (never inlined) so the CSP can forbid
// inline styles; the only script is a same-origin progressive enhancement.
import { defineConfig } from "astro/config";

export default defineConfig({
  site: process.env.AG_SITE_URL ?? "https://agentguard.github.io",
  base: process.env.AG_SITE_BASE ?? "/",
  output: "static",
  trailingSlash: "always",
  build: {
    inlineStylesheets: "never",
    assets: "assets",
  },
  devToolbar: { enabled: false },
  markdown: {
    syntaxHighlight: false,
  },
});
