// Serves site/dist the way Vercel will: the response headers from ../vercel.json
// (so the real Content-Security-Policy is enforced locally and in CI tests) and
// `trailingSlash: true`. Local development and testing only.
// With AGW_API_URL set (e.g. http://127.0.0.1:8000), /api/* is proxied there,
// as the Vercel rewrite does in production.
// Usage: node scripts/serve.mjs [port]
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const site = fileURLToPath(new URL("..", import.meta.url));
const dist = path.join(site, "dist");
const config = JSON.parse(fs.readFileSync(path.join(site, "..", "vercel.json"), "utf8"));
const rules = config.headers.map((r) => ({ re: new RegExp(`^${r.source}$`), headers: r.headers }));
const port = Number(process.argv[2] || process.env.PORT || 4321);
const TYPES = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8",
  ".wasm": "application/wasm", ".zip": "application/zip", ".whl": "application/zip", ".png": "image/png", ".ico": "image/x-icon",
};

const api = process.env.AGW_API_URL ? new URL(process.env.AGW_API_URL) : null;

http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/api/")) {
    if (!api) { res.writeHead(404, { "Content-Type": "application/json" }); return res.end('{"error":"no API configured"}'); }
    const up = http.request({ hostname: api.hostname, port: api.port, path: req.url, method: req.method,
      headers: { ...req.headers, host: api.host } }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    return req.pipe(up);
  }
  let pathname = decodeURIComponent(url.pathname);
  for (const r of rules) if (r.re.test(pathname)) for (const h of r.headers) res.setHeader(h.key, h.value);
  if (config.trailingSlash && !pathname.endsWith("/") && !path.extname(pathname)) {
    res.writeHead(308, { Location: pathname + "/" + url.search });
    return res.end();
  }
  let file = path.join(dist, pathname);
  if (!file.startsWith(dist)) { res.writeHead(400); return res.end(); }
  if (pathname.endsWith("/")) file = path.join(file, "index.html");
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(fs.existsSync(path.join(dist, "404.html")) ? fs.readFileSync(path.join(dist, "404.html")) : "Not found");
    }
    // A Content-Type from vercel.json (e.g. speculation rules) wins over the extension.
    if (!res.getHeader("Content-Type")) res.setHeader("Content-Type", TYPES[path.extname(file)] || "application/octet-stream");
    res.writeHead(200, { "Cache-Control": "no-cache" });
    res.end(data);
  });
}).listen(port, "127.0.0.1", () => console.log(`serving ${dist} at http://127.0.0.1:${port}/ with vercel.json headers`));
