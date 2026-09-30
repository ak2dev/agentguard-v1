// Prepares the in-browser scanner's assets before `astro build` (outputs are
// not committed; they are rebuilt from source on every build):
//
//   public/pyodide/             Pyodide runtime from the pinned npm package, plus
//                               only the wheels the engine imports. Wheels are
//                               downloaded once at build time and verified against
//                               the sha256 in pyodide-lock.json; the site then serves
//                               them itself, so visitors never contact a CDN.
//   public/engine/engine.json   the pure-Python engine (agentguard core + webscan)
//                               and the rule pack, mappings and intel feed.
//   src/data/engine.json        build facts the /scan page embeds (versions, sha256).
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const site = fileURLToPath(new URL("..", import.meta.url));
const repo = path.resolve(site, "..");
const pyodideDir = path.dirname(require.resolve("pyodide/package.json"));
const pyodideVersion = JSON.parse(fs.readFileSync(path.join(pyodideDir, "package.json"), "utf8")).version;
const lock = JSON.parse(fs.readFileSync(path.join(pyodideDir, "pyodide-lock.json"), "utf8"));
const REQUIRED = ["pydantic", "regex", "pyyaml"];
const RUNTIME = ["pyodide.mjs", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"];
const CDN = `https://cdn.jsdelivr.net/pyodide/v${pyodideVersion}/full/`;
const cacheDir = path.join(site, ".cache", "pyodide", pyodideVersion);

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const norm = (n) => n.toLowerCase().replace(/_/g, "-");

function closure(names) {
  const byName = new Map(Object.entries(lock.packages).map(([k, v]) => [norm(k), v]));
  const out = new Map();
  const visit = (n) => {
    const pkg = byName.get(norm(n));
    if (!pkg) throw new Error(`package ${n} not in pyodide-lock.json`);
    if (out.has(pkg.name)) return;
    out.set(pkg.name, pkg);
    for (const d of pkg.depends ?? []) visit(d);
  };
  names.forEach(visit);
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
}

async function wheel(pkg) {
  const cached = path.join(cacheDir, pkg.file_name);
  let data = fs.existsSync(cached) ? fs.readFileSync(cached) : null;
  if (!data || sha256(data) !== pkg.sha256) {
    const res = await fetch(CDN + pkg.file_name);
    if (!res.ok) throw new Error(`download ${pkg.file_name}: HTTP ${res.status}`);
    data = Buffer.from(await res.arrayBuffer());
    fs.mkdirSync(cacheDir, { recursive: true });
    fs.writeFileSync(cached, data);
  }
  if (sha256(data) !== pkg.sha256) throw new Error(`${pkg.file_name}: sha256 mismatch with pyodide-lock.json`);
  return data;
}

function collect(dir, prefix, filter, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (e.name === "__pycache__" || e.name.startsWith(".")) continue;
    const p = path.join(dir, e.name);
    const rel = `${prefix}/${e.name}`;
    if (e.isDirectory()) collect(p, rel, filter, out);
    else if (filter(e.name)) out[rel] = fs.readFileSync(p).toString("base64");
  }
}

// 1. Pyodide runtime + verified wheels.
const outPy = path.join(site, "public", "pyodide");
fs.rmSync(path.join(site, "public", "pyodide"), { recursive: true, force: true });
fs.mkdirSync(outPy, { recursive: true });
for (const f of RUNTIME) fs.copyFileSync(path.join(pyodideDir, f), path.join(outPy, f));
const pkgs = closure(REQUIRED);
for (const pkg of pkgs) fs.writeFileSync(path.join(outPy, pkg.file_name), await wheel(pkg));

// 2. Engine bundle: only the pure core, the browser entry points and the bundled data.
const files = {};
const py = (n) => n.endsWith(".py");
for (const f of ["__init__.py", "webscan.py"]) files[`agentguard/${f}`] = fs.readFileSync(path.join(repo, "src", "agentguard", f)).toString("base64");
// Engine code plus the HTML report's embedded fonts (and their OFL licenses).
collect(path.join(repo, "src", "agentguard", "core"), "agentguard/core", (n) => py(n) || n.endsWith(".woff2") || n.endsWith("-OFL.txt"), files);
for (const d of ["rules", "mappings", "intel"]) collect(path.join(repo, d), `agentguard/_data/${d}`, () => true, files);
const engine = Buffer.from(JSON.stringify({ format: "agentguard-web-engine/1", files }));
fs.rmSync(path.join(site, "public", "engine"), { recursive: true, force: true });
fs.mkdirSync(path.join(site, "public", "engine"), { recursive: true });
fs.writeFileSync(path.join(site, "public", "engine", "engine.json"), engine);

// 3. Facts the page embeds so the worker can check what it loads.
const facts = {
  pyodide_version: pyodideVersion,
  packages: pkgs.map((p) => p.name),
  engine_sha256: sha256(engine),
  engine_files: Object.keys(files).length,
};
fs.writeFileSync(path.join(site, "src", "data", "engine.json"), JSON.stringify(facts, null, 2) + "\n");
const mb = (n) => (n / 1048576).toFixed(1);
const total = [...RUNTIME.map((f) => fs.statSync(path.join(outPy, f)).size), ...pkgs.map((p) => fs.statSync(path.join(outPy, p.file_name)).size), engine.length].reduce((a, b) => a + b, 0);
console.log(`prepare-engine: pyodide ${pyodideVersion}, ${pkgs.length} wheels (${pkgs.map((p) => p.name).join(", ")}), engine ${facts.engine_files} files; ${mb(total)} MB total`);
