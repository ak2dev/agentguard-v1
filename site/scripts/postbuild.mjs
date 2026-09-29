// Post-build hardening gate for the static site:
//  * fails on inline <script> code, inline event handlers (on*=), style=""
//    attributes, <style> elements (except the self-contained sample report,
//    which carries its own hash-based CSP), javascript: URLs, and any
//    third-party script/style/font/img origins;
//  * adds Subresource Integrity (sha384) to every same-origin script and
//    stylesheet.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const dist = path.resolve("dist");
const problems = [];
let pages = 0;

function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".html")) check(p);
  }
}

function sri(file) {
  const data = fs.readFileSync(file);
  return "sha384-" + crypto.createHash("sha384").update(data).digest("base64");
}

function resolveAsset(url) {
  const base = (process.env.AG_SITE_BASE ?? "/").replace(/\/$/, "");
  let u = url.split("#")[0].split("?")[0];
  if (base && u.startsWith(base + "/")) u = u.slice(base.length);
  return path.join(dist, decodeURIComponent(u));
}

function check(file) {
  pages++;
  const rel = path.relative(dist, file).replace(/\\/g, "/");
  let html = fs.readFileSync(file, "utf8");
  const standalone = rel === "sample-report.html";
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/.test(m[1]) || m[2].trim()) problems.push(`${rel}: inline <script>`);
  }
  if (/\son[a-z]+\s*=/i.test(html.replace(/<pre[\s\S]*?<\/pre>/gi, ""))) problems.push(`${rel}: inline event handler`);
  if (/\sstyle\s*=/i.test(html.replace(/<pre[\s\S]*?<\/pre>/gi, ""))) problems.push(`${rel}: style attribute`);
  if (!standalone && /<style\b/i.test(html)) problems.push(`${rel}: <style> element`);
  if (/(href|src)\s*=\s*["']\s*javascript:/i.test(html)) problems.push(`${rel}: javascript: URL`);
  for (const m of html.matchAll(/<(script|link|img|iframe)\b[^>]*\b(?:src|href)\s*=\s*["'](https?:)?\/\/([^"'/]+)/gi)) {
    if (m[1].toLowerCase() === "link" && /rel\s*=\s*["']?(?!stylesheet|icon|preload)/i.test(m[0])) continue;
    problems.push(`${rel}: third-party ${m[1]} from ${m[3]}`);
  }
  if (!standalone && !/http-equiv="Content-Security-Policy"/i.test(html)) problems.push(`${rel}: missing CSP meta`);
  // Add SRI to same-origin scripts and stylesheets.
  html = html.replace(/<script\b([^>]*?)\bsrc\s*=\s*"([^"]+)"([^>]*)>/gi, (tag, a, url, b) => {
    if (/integrity=/.test(tag) || /^https?:/.test(url)) return tag;
    const f = resolveAsset(url);
    if (!fs.existsSync(f)) { problems.push(`${rel}: missing script ${url}`); return tag; }
    return `<script${a}src="${url}" integrity="${sri(f)}"${b}>`;
  });
  html = html.replace(/<link\b([^>]*?)\brel="stylesheet"([^>]*?)\bhref\s*=\s*"([^"]+)"([^>]*)>|<link\b([^>]*?)\bhref\s*=\s*"([^"]+)"([^>]*?)\brel="stylesheet"([^>]*)>/gi, (tag) => {
    if (/integrity=/.test(tag)) return tag;
    const url = (tag.match(/href\s*=\s*"([^"]+)"/i) || [])[1];
    if (!url || /^https?:/.test(url)) return tag;
    const f = resolveAsset(url);
    if (!fs.existsSync(f)) { problems.push(`${rel}: missing stylesheet ${url}`); return tag; }
    return tag.replace(/\/?>$/, ` integrity="${sri(f)}">`);
  });
  fs.writeFileSync(file, html);
}

walk(dist);
if (!fs.existsSync(path.join(dist, ".well-known", "security.txt"))) problems.push("missing /.well-known/security.txt");
if (problems.length) {
  console.error(`postbuild: ${problems.length} problem(s)\n` + problems.join("\n"));
  process.exit(1);
}
console.log(`postbuild: ${pages} pages checked (CSP, no inline script/style, same-origin only); SRI added.`);
