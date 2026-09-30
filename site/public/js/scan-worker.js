// Agent Guard in-browser scanner: a module Web Worker running the pure-Python
// engine under Pyodide. Nothing scanned here is uploaded anywhere.
//
// Network use (and nothing else):
//  * same-origin static assets: the Pyodide runtime, its wheels, the engine bundle;
//  * only when a GitHub link is scanned: api.github.com (resolve the ref, list files)
//    and raw.githubusercontent.com / gist.githubusercontent.com (file contents),
//    without cookies or referrer.
// Scanned content is data: it is never executed and never evaluated as code.
import { loadPyodide } from "../pyodide/pyodide.mjs";

const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";
const FETCH_CONCURRENCY = 12;
const REQUEST_TIMEOUT_MS = 20000;
const MAX_FILE_BYTES = 2 * 1024 * 1024;

// Keep every request in resource timing (the default buffer holds 250) so tests can audit them.
performance.setResourceTimingBufferSize?.(100000);

let py = null;
let ws = null;
let booting = null;
let lastScanMs = 0;

const post = (msg) => self.postMessage(msg);
const progress = (id, stage, detail = "") => post({ id, type: "progress", stage, detail });

class UserError extends Error {}

async function sha256Hex(buf) {
  const d = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function boot(id, expectedSha) {
  progress(id, "Loading the Python runtime");
  const indexURL = new URL("../pyodide/", import.meta.url).href;
  py = await loadPyodide({ indexURL, fullStdLib: false });
  progress(id, "Loading the engine's packages");
  await py.loadPackage(["pydantic", "regex", "pyyaml"], { messageCallback: () => {}, errorCallback: () => {} });
  progress(id, "Loading the engine and rule pack");
  const res = await fetch(new URL("../engine/engine.json", import.meta.url), { cache: "no-cache" });
  if (!res.ok) throw new Error(`engine bundle: HTTP ${res.status}`);
  const buf = await res.arrayBuffer();
  if (expectedSha && (await sha256Hex(buf)) !== expectedSha) throw new Error("engine bundle failed its integrity check");
  const bundle = JSON.parse(new TextDecoder().decode(buf));
  const root = "/home/pyodide/ag";
  for (const [rel, b64] of Object.entries(bundle.files)) {
    const full = `${root}/${rel}`;
    py.FS.mkdirTree(full.slice(0, full.lastIndexOf("/")));
    py.FS.writeFile(full, Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
  }
  py.runPython(`import sys; sys.path.insert(0, ${JSON.stringify(root)})`);
  ws = py.pyimport("agentguard.webscan");
  return JSON.parse(ws.engine_info());
}

function ready(id, expectedSha) {
  if (!booting) booting = boot(id, expectedSha);
  return booting;
}

// -- GitHub ------------------------------------------------------------------

async function request(url, accept) {
  let res;
  try {
    res = await fetch(url, {
      headers: accept ? { Accept: accept } : {},
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (e) {
    throw new UserError(`Could not reach ${new URL(url).host} (${e.name === "TimeoutError" ? "timed out" : "network error"}).`);
  }
  if ((res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0") {
    const reset = Number(res.headers.get("x-ratelimit-reset"));
    const when = reset ? ` after ${new Date(reset * 1000).toLocaleTimeString()}` : " later";
    throw new UserError(`GitHub's limit for anonymous requests from your network (60 per hour) is used up. Try again${when}.`);
  }
  return res;
}

async function api(path, accept = "application/vnd.github+json") {
  const res = await request(API + path, accept);
  if (res.status === 404 || res.status === 422 || res.status === 409) return null;
  if (!res.ok) throw new UserError(`GitHub returned HTTP ${res.status} for ${path.split("?")[0]}.`);
  return accept === "application/vnd.github.sha" ? (await res.text()).trim() : res.json();
}

const enc = (p) => p.split("/").map(encodeURIComponent).join("/");
const NOT_FOUND = "Not found on GitHub. Only public repositories can be scanned; check the owner, repository, branch and path.";

async function resolveGitHub(id, gh) {
  const repoPath = `/repos/${enc(gh.owner)}/${enc(gh.repo)}`;
  let candidates = gh.candidates;
  if (!candidates.length) {
    progress(id, "Resolving the default branch");
    const repo = await api(repoPath);
    if (!repo) throw new UserError(NOT_FOUND);
    candidates = [{ ref: repo.default_branch, path: "" }];
  }
  const trees = new Map();
  for (const c of candidates) {
    progress(id, "Resolving the commit", c.ref);
    const sha = await api(`${repoPath}/commits/${enc(c.ref)}`, "application/vnd.github.sha");
    if (!sha || !/^[0-9a-f]{40}$/.test(sha)) continue;
    if (gh.mode === "blob" || gh.mode === "raw") {
      return { sha, path: c.path, entries: [{ path: c.path, type: "blob", mode: "100644", size: null }], truncated: false };
    }
    progress(id, "Listing files", `${gh.owner}/${gh.repo}@${sha.slice(0, 7)}`);
    let tree = trees.get(sha);
    if (!tree) {
      tree = await api(`${repoPath}/git/trees/${sha}?recursive=1`);
      if (!tree) continue;
      trees.set(sha, tree);
    }
    const entries = tree.tree.map((e) => ({ path: e.path, type: e.type, mode: e.mode, size: e.size ?? null }));
    if (c.path && !entries.some((e) => e.path === c.path || e.path.startsWith(c.path + "/"))) continue;
    return { sha, path: c.path, entries, truncated: Boolean(tree.truncated) };
  }
  throw new UserError(NOT_FOUND);
}

async function fetchAll(id, urls) {
  const out = new Map();
  const events = [];
  let next = 0;
  let done = 0;
  async function worker() {
    while (next < urls.length) {
      const { path, url } = urls[next++];
      try {
        const res = await request(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.byteLength > MAX_FILE_BYTES) events.push({ kind: "too_large", path, detail: `${buf.byteLength} bytes` });
        else out.set(path, buf);
      } catch (e) {
        events.push({ kind: "fetch_failed", path, detail: e instanceof UserError ? e.message : String(e.message || e) });
      }
      done++;
      if (done % 5 === 0 || done === urls.length) progress(id, "Fetching files", `${done} of ${urls.length}`);
    }
  }
  await Promise.all(Array.from({ length: Math.min(FETCH_CONCURRENCY, urls.length) }, worker));
  return { files: out, events };
}

async function scanGitHub(id, gh) {
  if (gh.mode === "gist") return scanGist(id, gh);
  const { sha, path, entries, truncated } = await resolveGitHub(id, gh);
  const plan = JSON.parse(ws.plan_github(JSON.stringify(entries), path, truncated));
  if (!plan.fetch.length) throw new UserError("Nothing to scan at that location: no skill, instruction, configuration or code files were found.");
  const base = `${RAW}/${enc(gh.owner)}/${enc(gh.repo)}/${sha}/`;
  const t0 = performance.now();
  const { files, events } = await fetchAll(id, plan.fetch.map((e) => ({ path: e.path, url: base + enc(e.path) })));
  const fetchMs = Math.round(performance.now() - t0);
  const source = { kind: "github", locator: `${gh.owner}/${gh.repo}`, subpath: path || null, resolved: sha };
  return { files, events: [...plan.events, ...events], source, meta: { fetched: files.size, not_relevant: plan.not_relevant, sha, path, fetch_ms: fetchMs } };
}

async function scanGist(id, gh) {
  progress(id, "Fetching the gist");
  const gist = await api(`/gists/${enc(gh.gist_id)}${gh.gist_revision ? "/" + gh.gist_revision : ""}`);
  if (!gist) throw new UserError("Gist not found. Only public gists can be scanned.");
  const revision = gh.gist_revision || gist.history?.[0]?.version;
  if (!/^[0-9a-f]{40}$/.test(revision || "")) throw new UserError("Could not determine the gist's revision.");
  const files = new Map();
  const events = [];
  const toFetch = [];
  for (const [name, f] of Object.entries(gist.files || {})) {
    if (f.truncated) {
      const raw = new URL(f.raw_url);
      if (raw.protocol === "https:" && raw.hostname === "gist.githubusercontent.com") toFetch.push({ path: name, url: raw.href });
      else events.push({ kind: "fetch_failed", path: name, detail: "unexpected raw URL host" });
    } else {
      files.set(name, new TextEncoder().encode(f.content ?? ""));
    }
  }
  const fetched = await fetchAll(id, toFetch);
  for (const [k, v] of fetched.files) files.set(k, v);
  const source = { kind: "gist", locator: gh.gist_id, resolved: revision };
  return { files, events: [...events, ...fetched.events], source, meta: { fetched: files.size, not_relevant: 0, sha: revision, path: "" } };
}

// -- scanning ------------------------------------------------------------------

function runScan(id, files, source, events) {
  progress(id, "Scanning", `${files.size} file(s)`);
  const pyFiles = py.toPy(files);
  const t0 = performance.now();
  try {
    return ws.scan_files(pyFiles, source ? JSON.stringify(source) : null, events?.length ? JSON.stringify(events) : null);
  } finally {
    pyFiles.destroy();
    lastScanMs = Math.round(performance.now() - t0);
  }
}

async function handle(msg) {
  const { id, type } = msg;
  if (type === "net-log") {
    // Every request this worker has made, from the browser's own resource timing (used by tests).
    return post({ id, type: "net-log", urls: performance.getEntriesByType("resource").map((e) => e.name) });
  }
  const info = await ready(id, msg.engineSha);
  if (type === "init") return post({ id, type: "ready", info });
  if (type === "scan-text") {
    const name = msg.name || ws.guess_pasted_name(msg.text);
    const report = runScan(id, new Map([[name, new TextEncoder().encode(msg.text)]]), null, []);
    return post({ id, type: "result", report, meta: { name } });
  }
  if (type === "scan-files") {
    const files = new Map(msg.files.map((f) => [f.path, new Uint8Array(f.data)]));
    const report = runScan(id, files, { kind: "pasted", locator: msg.label || "dropped files" }, msg.events || []);
    return post({ id, type: "result", report, meta: { fetched: files.size } });
  }
  if (type === "scan-archive") {
    progress(id, "Scanning", msg.name);
    const bytes = py.toPy(new Uint8Array(msg.data));
    try {
      return post({ id, type: "result", report: ws.scan_archive(bytes, msg.name), meta: { name: msg.name } });
    } finally {
      bytes.destroy();
    }
  }
  if (type === "scan-link") {
    const parsed = JSON.parse(ws.parse_input(msg.url));
    if (!parsed.ok) return post({ id, type: "error", message: parsed.reason, supported: parsed.supported });
    if (!parsed.browser_supported) return post({ id, type: "error", message: parsed.note, supported: parsed.supported, kind: parsed.source.kind });
    const got = await scanGitHub(id, parsed.github);
    const report = runScan(id, got.files, got.source, got.events);
    return post({ id, type: "result", report, meta: { ...got.meta, scan_ms: lastScanMs } });
  }
  if (type === "render") return post({ id, type: "rendered", format: msg.format, text: ws.render_last(msg.format) });
  throw new Error(`unknown request ${type}`);
}

self.onmessage = (ev) => {
  handle(ev.data).catch((e) => {
    const user = e instanceof UserError;
    const pyErr = e && e.type ? `${e.type}: ${String(e.message).trim().split("\n").pop()}` : null;
    post({ id: ev.data.id, type: "error", message: user ? e.message : `The scanner failed: ${pyErr || e.message || e}` });
  });
};
