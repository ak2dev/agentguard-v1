// Runs the pure-Python Agent Guard core under Pyodide (the Milestone 2
// in-browser path) and checks every offline rule fixture behaves as labelled.
// Usage: node tests/pyodide/run_core.mjs [repoRoot]
import { loadPyodide } from "pyodide";
import fs from "node:fs";
import path from "node:path";

const repo = path.resolve(process.argv[2] ?? ".");
const py = await loadPyodide();
await py.loadPackage(["pydantic", "regex", "pyyaml"]);

function mirror(localDir, target) {
  for (const entry of fs.readdirSync(localDir, { withFileTypes: true })) {
    if (entry.name === "__pycache__") continue;
    const src = path.join(localDir, entry.name);
    const dst = `${target}/${entry.name}`;
    if (entry.isDirectory()) {
      py.FS.mkdirTree(dst);
      mirror(src, dst);
    } else {
      py.FS.writeFile(dst, fs.readFileSync(src));
    }
  }
}

// Only the pure core (plus the bundled data) is mounted: no cli, io or net.
py.FS.mkdirTree("/app/agentguard");
for (const f of ["__init__.py"]) py.FS.writeFile(`/app/agentguard/${f}`, fs.readFileSync(path.join(repo, "src/agentguard", f)));
py.FS.mkdirTree("/app/agentguard/core");
mirror(path.join(repo, "src/agentguard/core"), "/app/agentguard/core");
for (const d of ["rules", "mappings", "intel"]) {
  py.FS.mkdirTree(`/app/agentguard/_data/${d}`);
  mirror(path.join(repo, d), `/app/agentguard/_data/${d}`);
}

// Collect offline fixtures (skip ones that need the lockfile/intel/policy/network harness or archives).
const fixturesRoot = path.join(repo, "fixtures/rules");
const cases = [];
for (const rule of fs.readdirSync(fixturesRoot).sort()) {
  for (const side of ["positive", "negative"]) {
    const sideDir = path.join(fixturesRoot, rule, side);
    if (!fs.existsSync(sideDir)) continue;
    for (const c of fs.readdirSync(sideDir).sort()) {
      const dir = path.join(sideDir, c);
      const files = {};
      let skip = false;
      const walk = (d, rel) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const r = rel ? `${rel}/${e.name}` : e.name;
          if (e.isDirectory()) walk(path.join(d, e.name), r);
          else if (["_case.yaml", "_archive.zip", "agentguard.lock"].includes(r)) skip = true;
          else files[r] = fs.readFileSync(path.join(d, e.name)).toString("base64");
        }
      };
      walk(dir, "");
      if (!skip) cases.push({ rule, side, name: c, files });
    }
  }
}
py.globals.set("CASES_JSON", JSON.stringify(cases));

const result = await py.runPythonAsync(`
import sys, json, base64
sys.path.insert(0, "/app")
from agentguard import ArtifactTree, ScanOptions, scan, render_json
from agentguard.core.rules.pack import RulePack
pack = RulePack.default()
cases = json.loads(CASES_JSON)
failures = []
for c in cases:
    tree = ArtifactTree.from_mapping({k: base64.b64decode(v) for k, v in c["files"].items()})
    report = scan(tree, ScanOptions(), pack)
    fired = {f.rule_id for f in report.findings}
    ok = (c["rule"] in fired) if c["side"] == "positive" else (c["rule"] not in fired)
    if not ok:
        failures.append(f'{c["rule"]}/{c["side"]}/{c["name"]}')
# determinism across runs inside Pyodide
t = ArtifactTree.from_mapping({k: base64.b64decode(v) for k, v in cases[0]["files"].items()})
assert render_json(scan(t, ScanOptions(), pack)) == render_json(scan(t, ScanOptions(), pack))
json.dumps({"python": sys.version.split()[0], "rules": len(pack.rules), "cases": len(cases), "failures": failures})
`);
const out = JSON.parse(result);
console.log(`Pyodide Python ${out.python}: ${out.cases} fixture cases, ${out.rules} rules, ${out.failures.length} failures`);
if (out.failures.length) {
  console.log(out.failures.join("\n"));
  process.exit(1);
}
