// Agent Guard /scan page: collects input, talks to the scanner Web Worker, and
// renders the findings JSON. Report content comes from scanned (possibly hostile)
// material, so it is only ever inserted as text nodes — never as HTML — and only
// https: links are created.
const root = document.getElementById("scanner");
if (root) main(root);

function main(root) {
  root.hidden = false;
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const FRAMEWORK_LABEL = {
    "owasp-asi-2026": "OWASP Agentic", "owasp-mcp-2025-beta": "OWASP MCP", "owasp-ast-1.0": "OWASP Skills",
    "owasp-llm-2025": "OWASP LLM", "nsa-csi-mcp-2026-05": "NSA MCP CSI", cwe: "CWE",
  };
  const MAX_FILES = 5000;
  const MAX_FILE_BYTES = 2 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
  const SKIP_DIRS = new Set([".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"]);
  const ARCHIVE = /\.(zip|tgz|tar\.gz|tar)$/i;
  const siteBase = root.dataset.worker.replace(/\/js\/scan-worker\.js$/, "");

  const $ = (id) => document.getElementById(id);
  const status = $("status"), statusText = $("status-text"), errorBox = $("error"), result = $("result");

  // -- worker plumbing ---------------------------------------------------------
  let worker = null;
  let seq = 0;
  const pending = new Map();

  function getWorker() {
    if (worker) return worker;
    worker = new Worker(root.dataset.worker, { type: "module", name: "agentguard-scanner" });
    worker.onmessage = (ev) => {
      const msg = ev.data;
      const p = pending.get(msg.id);
      if (!p) return;
      if (msg.type === "progress") return p.onProgress?.(msg);
      pending.delete(msg.id);
      if (msg.type === "error") p.reject(msg);
      else p.resolve(msg);
    };
    worker.onerror = (ev) => {
      ev.preventDefault();
      failAll({ message: "The scanner could not start in this browser." });
    };
    return worker;
  }

  function call(msg, onProgress, transfer = []) {
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject, onProgress });
      getWorker().postMessage({ ...msg, id, engineSha: root.dataset.engineSha }, transfer);
    });
  }

  // Test hook: lists the worker's network requests (resource timing). Read-only.
  window.agentguardNetLog = () => (worker ? call({ type: "net-log" }).then((r) => r.urls) : Promise.resolve([]));

  function failAll(err) {
    for (const p of pending.values()) p.reject(err);
    pending.clear();
  }

  $("cancel").addEventListener("click", () => {
    if (worker) worker.terminate();
    worker = null;
    failAll({ message: "Cancelled.", cancelled: true });
  });

  // Warm the engine up as soon as someone starts using the form.
  let warmed = false;
  root.addEventListener("focusin", () => {
    if (warmed) return;
    warmed = true;
    call({ type: "init" }).catch(() => { warmed = false; });
  });

  // -- tabs ----------------------------------------------------------------------
  const tabs = [...root.querySelectorAll('[role="tab"]')];
  function selectTab(tab, focus) {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      $(t.getAttribute("aria-controls")).hidden = !on;
    }
    if (focus) tab.focus();
  }
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => selectTab(t, false));
    t.addEventListener("keydown", (e) => {
      const d = { ArrowRight: 1, ArrowLeft: -1, Home: -i, End: tabs.length - 1 - i }[e.key];
      if (d === undefined) return;
      e.preventDefault();
      selectTab(tabs[(i + d + tabs.length) % tabs.length], true);
    });
  });

  // -- running a scan --------------------------------------------------------------
  let busy = false;

  async function run(msg, label, transfer) {
    if (busy) return;
    busy = true;
    errorBox.hidden = true;
    result.hidden = true;
    status.hidden = false;
    statusText.textContent = "Starting the scanner…";
    try {
      const res = await call(msg, (p) => { statusText.textContent = p.detail ? `${p.stage}: ${p.detail}` : `${p.stage}…`; }, transfer);
      renderReport(JSON.parse(res.report), res.meta || {}, label);
    } catch (err) {
      showError(err);
    } finally {
      busy = false;
      status.hidden = true;
    }
  }

  function showError(err) {
    errorBox.replaceChildren(el("p", {}, err.message || String(err)));
    if (err.supported?.length) {
      errorBox.append(el("p", {}, "Supported inputs:"), el("ul", {}, ...err.supported.map((s) => el("li", {}, s))));
    }
    errorBox.hidden = false;
  }

  // Link
  const linkInput = $("link");
  const qs = new URLSearchParams(location.search).get("url");
  if (qs) linkInput.value = qs.slice(0, 2048);
  $("link-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const url = linkInput.value.trim();
    if (!url) return;
    const u = new URL(location.href);
    u.searchParams.set("url", url);
    history.replaceState(null, "", u);
    run({ type: "scan-link", url }, url);
  });

  // Paste
  $("paste-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const text = $("paste-text").value;
    if (!text.trim()) return;
    run({ type: "scan-text", text, name: $("paste-kind").value || undefined }, "Pasted text");
  });

  // Files
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    const entries = [...e.dataTransfer.items].map((it) => it.webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) scanEntries(entries);
    else scanFileList([...e.dataTransfer.files].map((f) => ({ path: f.name, file: f })));
  });
  drop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("pick-files").click(); }
  });
  $("pick-files").addEventListener("change", (e) => scanFileList([...e.target.files].map((f) => ({ path: f.name, file: f }))));
  $("pick-folder").addEventListener("change", (e) => scanFileList([...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f }))));

  async function scanEntries(entries) {
    const list = [];
    const events = [];
    const readDir = (dir) => new Promise((resolve, reject) => {
      const reader = dir.createReader();
      const all = [];
      const next = () => reader.readEntries((batch) => (batch.length ? (all.push(...batch), next()) : resolve(all)), reject);
      next();
    });
    async function walk(entry, depth) {
      if (list.length > MAX_FILES) return;
      if (entry.isFile) {
        list.push({ path: entry.fullPath.replace(/^\//, ""), file: await new Promise((res, rej) => entry.file(res, rej)) });
      } else if (entry.isDirectory && !SKIP_DIRS.has(entry.name) && depth < 32) {
        for (const child of await readDir(entry)) await walk(child, depth + 1);
      }
    }
    try {
      for (const entry of entries) await walk(entry, 0);
    } catch {
      events.push({ kind: "unreadable", path: "(dropped folder)", detail: "the browser could not read part of the folder" });
    }
    scanFileList(list, events);
  }

  async function scanFileList(list, events = []) {
    if (!list.length) return;
    if (list.length === 1 && ARCHIVE.test(list[0].path)) {
      const data = await list[0].file.arrayBuffer();
      return run({ type: "scan-archive", name: list[0].path, data }, list[0].path, [data]);
    }
    const files = [];
    let total = 0;
    for (const { path, file } of list) {
      if (path.split("/").slice(0, -1).some((seg) => SKIP_DIRS.has(seg))) continue;
      if (files.length >= MAX_FILES) { events.push({ kind: "too_many_files", path, detail: `more than ${MAX_FILES} files` }); break; }
      if (file.size > MAX_FILE_BYTES) { events.push({ kind: "too_large", path, detail: `${file.size} bytes` }); continue; }
      if (total + file.size > MAX_TOTAL_BYTES) { events.push({ kind: "total_bytes_exceeded", path }); continue; }
      total += file.size;
      files.push({ path, data: await file.arrayBuffer() });
    }
    const label = list.length === 1 ? list[0].path : `${files.length} dropped file(s)`;
    run({ type: "scan-files", files, events, label }, label, files.map((f) => f.data));
  }

  // -- rendering -------------------------------------------------------------------
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "href") {
        const safe = safeHref(v);
        if (safe) { node.setAttribute("href", safe); if (/^https:/.test(safe)) node.setAttribute("rel", "noopener noreferrer"); }
      } else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
    return node;
  }

  function safeHref(v) {
    try {
      const u = new URL(v, location.href);
      if (u.protocol === "https:" || (u.origin === location.origin && u.protocol === location.protocol)) return u.href;
    } catch { /* not a URL */ }
    return null;
  }

  function sevBadge(sev) { return el("span", { class: `sev ${sev}` }, sev); }

  function locationUrl(target, span) {
    if (!target?.source_url_template || !target.resolved || !span) return null;
    const path = span.path.split("/").map(encodeURIComponent).join("/");
    return target.source_url_template.replace("{resolved}", target.resolved).replace("{path}", path).replace("{line}", String(span.start_line || 1));
  }

  function where(span) { return span ? `${span.path}:${span.start_line}` : ""; }

  function renderTarget(report, meta, label) {
    const t = report.target || {};
    if (t.kind === "github" && t.resolved) {
      const [owner, repo, ...sub] = t.locator.split("/");
      const url = `https://github.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/tree/${t.resolved}/${sub.map(encodeURIComponent).join("/")}`;
      return el("p", {}, "Scanned ", el("a", { href: url }, `${owner}/${repo}${sub.length ? "/" + sub.join("/") : ""}`),
        " at commit ", el("code", {}, t.resolved.slice(0, 12)), ".");
    }
    if (t.kind === "gist" && t.resolved) {
      return el("p", {}, "Scanned gist ", el("a", { href: `https://gist.github.com/${encodeURIComponent(t.locator)}/${t.resolved}` }, t.locator), " at revision ", el("code", {}, t.resolved.slice(0, 12)), ".");
    }
    return el("p", {}, "Scanned ", meta.name ? el("code", {}, meta.name) : label, ".");
  }

  function renderReport(report, meta, label) {
    const findings = report.findings || [];
    const pack = report.rule_pack || {};
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
    const atOrAbove = findings.filter((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(report.fail_on || "high")).length;
    const parts = [el("h2", { id: "result-title", tabindex: "-1" }, "Report"), renderTarget(report, meta, label)];

    if (!findings.length) {
      parts.push(el("p", { class: "summary" }, `No findings from ${report.stats?.rules_evaluated ?? pack.rule_count} rules (rule pack v${pack.version}).`),
        el("p", { class: "muted" }, "That means no rule matched. It does not prove the content is safe: static rules miss paraphrased or novel attacks, and behavior that only appears at run time."));
    } else {
      parts.push(el("p", { class: "summary" }, `${findings.length} finding${findings.length === 1 ? "" : "s"}: `,
        ...SEVERITIES.filter((s) => counts[s]).map((s) => el("span", { class: "count" }, sevBadge(s), ` ${counts[s]}`))));
      parts.push(el("p", {}, atOrAbove
        ? `${atOrAbove} finding${atOrAbove === 1 ? " is" : "s are"} at or above ${(report.fail_on || "high").toUpperCase()}. Review ${atOrAbove === 1 ? "it" : "them"} before installing or enabling this.`
        : `Nothing at or above ${(report.fail_on || "high").toUpperCase()}; the findings below are lower-severity observations.`));
    }
    parts.push(el("p", { class: "muted small" },
      `${report.stats?.files_scanned ?? 0} file(s), ${report.inventory?.length ?? 0} component(s). Rule pack v${pack.version} (${pack.rule_count} rules, digest ${String(pack.digest || "").slice(0, 12)}), engine ${report.engine_version}.`,
      meta.fetch_ms !== undefined ? ` Fetched from GitHub in ${(meta.fetch_ms / 1000).toFixed(1)} s;` : "",
      meta.scan_ms ? ` scanned in ${(meta.scan_ms / 1000).toFixed(1)} s on this device.` : ""));

    parts.push(renderDownloads());

    if (report.flows?.length) {
      const names = Object.fromEntries((report.inventory || []).map((c) => [c.id, c.name]));
      parts.push(el("h3", {}, "Dangerous combinations"),
        el("ul", { class: "flows" }, ...report.flows.map((fl) => el("li", {},
          el("p", {}, fl.nodes.map((n) => names[n] || n).filter((n, i, a) => i === 0 || n !== a[i - 1]).join(" → ")),
          fl.narrative ? el("p", { class: "muted" }, fl.narrative) : null))));
    }

    for (const sev of SEVERITIES) {
      const group = findings.filter((f) => f.severity === sev);
      if (!group.length) continue;
      parts.push(el("h3", {}, sevBadge(sev), ` ${group.length}`), ...group.map((f) => renderFinding(f, report.target)));
    }

    parts.push(renderCoverage(report, meta));
    result.replaceChildren(...parts);
    result.hidden = false;
    result.querySelector("#result-title").focus();
  }

  function renderFinding(f, target) {
    const loc = locationUrl(target, f.primary);
    const mapped = (f.mappings || []).filter((m) => m.id);
    const pendingMaps = (f.mappings || []).filter((m) => !m.id);
    return el("details", { class: `finding ${f.severity}`, open: f.severity === "critical" || f.severity === "high" },
      el("summary", {}, sevBadge(f.severity), " ", el("strong", {}, f.title), f.primary ? el("span", { class: "muted" }, ` — ${where(f.primary)}`) : null),
      el("div", { class: "finding-body" },
        el("p", {}, f.message),
        el("dl", { class: "kv" },
          el("dt", {}, "Rule"), el("dd", {}, el("a", { href: `${siteBase}/rules/${f.rule_id.toLowerCase()}/` }, f.rule_id), ` (v${f.rule_version})`),
          el("dt", {}, "Confidence"), el("dd", {}, f.confidence),
          f.score ? [el("dt", {}, "AIVSS"), el("dd", {}, `${f.score.value} (${f.score.scorer} ${f.score.scorer_version})`)] : null,
          f.primary ? [el("dt", {}, "Location"), el("dd", {}, loc ? el("a", { href: loc }, where(f.primary)) : where(f.primary))] : null),
        f.explanation ? el("p", {}, f.explanation) : null,
        (f.evidence || []).length ? el("div", {}, el("h4", {}, "Evidence"), ...f.evidence.map(renderEvidence)) : null,
        f.remediation ? el("div", {}, el("h4", {}, "How to fix"), el("p", {}, f.remediation)) : null,
        mapped.length || pendingMaps.length ? el("p", { class: "maps" }, el("span", { class: "muted" }, "Standards: "),
          ...mapped.map((m) => el("span", { class: "pill", title: m.title || "" }, `${FRAMEWORK_LABEL[m.framework] || m.framework} ${m.id}`)),
          pendingMaps.length ? el("span", { class: "muted small" }, ` (${pendingMaps.length} mapping(s) pending review)`) : null) : null,
        (f.references || []).length ? el("p", { class: "small" }, "References: ",
          ...f.references.filter(safeHref).flatMap((r, i) => [i ? ", " : "", el("a", { href: r }, r)])) : null));
  }

  function renderEvidence(ev) {
    return el("div", { class: "evidence" },
      el("p", { class: "small" },
        ev.location ? el("code", {}, where(ev.location)) : null,
        ev.hidden ? el("span", { class: "pill" }, "hidden content") : null,
        ev.decode_path?.length ? el("span", { class: "pill" }, `decoded: ${ev.decode_path.join(" → ")}`) : null,
        ev.detail ? ` ${ev.detail}` : null),
      ev.snippet ? el("pre", {}, el("code", {}, ev.snippet)) : null);
  }

  function renderCoverage(report, meta) {
    const skipped = (report.analyzers || []).filter((a) => a.status !== "ran");
    const events = report.stats?.limit_events || [];
    const items = [];
    if (meta.not_relevant) items.push(el("li", {}, `${meta.not_relevant} file(s) not fetched because no rule reads them (images, lockfiles and similar).`));
    for (const a of skipped) items.push(el("li", {}, el("code", {}, a.id), ` ${a.status}: ${a.reason}`));
    for (const e of events.slice(0, 50)) items.push(el("li", {}, el("code", {}, e.kind), ` ${e.path}${e.detail ? " — " + e.detail : ""}`));
    if (events.length > 50) items.push(el("li", {}, `…and ${events.length - 50} more (see the JSON report).`));
    items.push(el("li", {}, "The scanned project's own .agentguard.yaml is ignored, so it cannot suppress its own findings."));
    return el("details", { class: "coverage" }, el("summary", {}, "What was not scanned"), el("ul", {}, ...items));
  }

  function renderDownloads() {
    const formats = [["json", "JSON", "application/json", "json"], ["sarif", "SARIF", "application/sarif+json", "sarif"],
      ["html", "HTML report", "text/html", "html"], ["markdown", "Markdown", "text/markdown", "md"], ["cyclonedx", "CycloneDX", "application/vnd.cyclonedx+json", "cdx.json"]];
    const row = el("p", { class: "downloads" }, el("span", { class: "muted" }, "Download: "));
    for (const [fmt, name, type, ext] of formats) {
      const btn = el("button", { type: "button", class: "btn secondary small" }, name);
      btn.addEventListener("click", async () => {
        try {
          const res = await call({ type: "render", format: fmt });
          const url = URL.createObjectURL(new Blob([res.text], { type }));
          const a = el("a", {});
          a.href = url;
          a.download = `agentguard-report.${ext}`;
          document.body.append(a);
          a.click();
          a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
        } catch (err) {
          showError(err);
        }
      });
      row.append(btn, " ");
    }
    return row;
  }
}
