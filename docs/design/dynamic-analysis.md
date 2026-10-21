# Sandboxed dynamic analysis — Design Proposal (for approval)

Status: **DRAFT, awaiting approval** · 2026-10-21 · Engine 0.1.x · Nothing here is built

Agent Guard is static today. It never runs what it scans: the CLI installs a process-creation
audit hook (`io/guard.py`), and the web server's scanner container runs only Agent Guard's own
engine (`web/src/agentguard_web/sandbox.py`). The README and `docs/threat-model.md` list
"runtime behavior of servers" as out of scope, with a sandboxed dynamic mode planned. This
document designs that mode. It covers (1) what it observes and why, (2) a threat model for
running hostile code, (3) isolation options and their cost on this project's AWS plan, (4) a
fake network, (5) how to drive an MCP server or a skill, (6) determinism, (7) rules,
(8) how it fits the CLI and the web dispatcher, and (9) a phased plan with a minimal first
slice. Section 10 lists the decisions that need your call. Every external claim is in
[Sources](#sources), which uses the format of `docs/sources.md`.

## 0. Findings from verification that change the brief

1. **KVM no longer requires bare metal on EC2.** Since 2026-02-16, EC2 supports nested
   virtualization on virtual instances, and the 2026-06-18 expansion added C7i, M7i and
   their **flex** variants. `c7i-flex.large` and `m7i-flex.large` are free-tier eligible on
   accounts created after 2025-07-15. So a microVM backend (Firecracker or Kata) may be
   possible without a `.metal` instance. Three caveats. Firecracker's own guide still says
   "EC2 only supports KVM on `.metal` instance types" and does not test nested virtualization.
   The EC2 API reference for `NestedVirtualization` names only 8th-generation instances,
   while the User Guide lists C7i-flex. AWS also recommends bare metal for
   performance-sensitive work. This needs a check in ap-southeast-2 before we rely on it
   (Section 3.3).
2. **The credits are already spoken for.** The current t4g.small stack costs about $20/month
   (`deploy/aws/README.md`), and the plan has $120 until 2027-04-18. That covers one
   always-on instance for those six months and little else. A second always-on host doesn't
   fit. Bare metal costs $2.84/hour in Sydney (c6g.metal), so $120 buys about 42 hours. Any
   dynamic worker has to run on demand.
3. **The MCP spec turns rug pulls into an observable protocol violation.** For 2026-07-28,
   the `tools/list` set "MUST NOT vary per-connection or as a side effect of other requests
   on the connection". A server whose tools change after a `tools/call` (without
   `listChanged`) breaks a MUST. That is a precise runtime rule, and Agent Guard can't see
   it statically (today only AG-MCP-META-020 hints at it, at low confidence).
4. **gVisor already records what we need.** gVisor's runtime monitoring streams trace points
   (for example `syscall/openat/enter`, `syscall/execve/enter`, `sentry/clone`,
   `container/start`) to a remote sink over a Unix socket. The sink is a process outside the
   sandbox, and the session is set with `--pod-init-config`. That gives syscall-level
   telemetry from the layer the attacker doesn't control, with no agent inside the sandbox.
   `deploy/aws/bootstrap.sh` already installs `runsc`.
5. **Docker `--internal` networks are not airtight by themselves.** Containers on one "can
   still reach the gateway IP, so host services configured for that address remain
   reachable". The fake network needs an explicit host firewall rule (Section 4).

---

## 1. Goals, non-goals and invariants

**Goals.** Start an untrusted MCP server (STDIO npm packages first, then PyPI) or a skill's
executable parts inside a strong sandbox. Drive it the way a client would. Record what it
does: DNS and egress attempts, file reads and writes (credential paths especially), process
spawns, and tool-definition changes after connection. Map those observations to findings with
evidence, in the same report as the static findings.

**Non-goals (v1 of this mode).** Proving a component safe; remote (HTTP) servers, which keep
the read-only probe; reaching real third-party services; TLS interception; GPU or native GUI
workloads; Windows or macOS hosts for the observed run.

**Invariants, carried over from the static design:**

- **Opt-in.** The mode is off by default, listed in the report header when used, and never
  silently replaces a static result.
- **The engine stays pure.** The engine never runs anything. A host-side runner produces a
  `RuntimeTrace` (data), and the engine turns it into findings, the same way `RemoteProbe`
  works today (`core/models/network.py`). A recorded trace doubles as a test fixture, so
  every dynamic rule is testable offline, in CI and in Pyodide.
- **No fallback to weaker isolation.** If the required runtime isn't there, the mode refuses
  to run. It never falls back to `runc` or to the host.
- **Record, don't forward.** No byte the target sends leaves the sandbox network.
- **Findings, not verdicts.** Behavior that wasn't observed isn't evidence of absence. The
  report states the observation window, the steps that ran and the coverage.

## 2. Threat model for running hostile code

This extends `docs/threat-model.md` (TM-01…TM-15) and `web/threat-model.md`. The change
in kind: the static design never runs target code, but this mode runs it on purpose, so the
sandbox becomes the primary control, not defense in depth.

### Assets

| # | Asset | Why it matters here |
|---|---|---|
| D1 | The host: kernel, Docker daemon, the dispatcher's Docker socket | A sandbox escape on the web instance reaches Postgres, Redis, `.env` secrets and the socket (root-equivalent) |
| D2 | The AWS project: instance role, IMDS, spend | Instance credentials or a cryptominer burning credits |
| D3 | Third parties on the internet | Target used as an attack or spam launchpad from our IP |
| D4 | Other jobs | Cross-job contamination of results or data |
| D5 | Telemetry integrity | A target that can forge or suppress its own trace gets a clean report |
| D6 | Report consumers | Hostile strings (paths, argv, DNS names, tool output) end up in reports |
| D7 | Our sandbox's fingerprint | Detailed public reports teach attackers how to detect and evade us |

### Adversaries

- **T1** (existing) Author of the malicious server or skill. They control the code, its
  dependencies and their install scripts, and will try to escape, detect the sandbox, stay
  dormant, poison telemetry or exhaust resources.
- **T6** (new) A web visitor who submits packages to use the service as free compute
  (mining, fork bombs) or as an evasion-testing oracle against our sandbox.

### Threats and mitigations

| # | Threat | Mitigation (designed) |
|---|---|---|
| DM-01 | Escape to the host kernel | gVisor (`runsc`): the Sentry implements Linux in user space, so target syscalls never reach the host kernel directly. Plus all `DockerSandbox` flags except `--read-only` root (a writable overlay is needed), and a dedicated worker host from Phase 3 on. Optional microVM backend (Section 3) |
| DM-02 | Escape on the web instance reaches D1 | Dynamic runs never share a Docker daemon with Postgres/Redis/API once exposed publicly (Phase 3). Phase 1 runs only operator-chosen targets |
| DM-03 | Egress / launchpad (D3) | Per-job `--internal` network with only the target and the fake-network sidecar; host firewall drops the job subnet to anything but the sidecar, including the gateway IP and 169.254.169.254; the sidecar never forwards. A `check-dynamic-sandbox` self-test must show no egress before the worker starts (like `check-sandbox` today) |
| DM-04 | IMDS / AWS credentials (D2) | No route (above); IMDSv2 hop limit 1 (already set); the worker instance has no instance role beyond Session Manager |
| DM-05 | Resource abuse (D2, T6) | Memory, CPU, PID, file-descriptor and disk quotas; a wall-clock limit for each phase; one dynamic job at a time; stricter PoW and per-client quotas on the web |
| DM-06 | Cross-job contamination (D4) | Fresh container, fresh network, fresh canary values per job; everything force-removed (create → start → always `rm -f`, as `DockerSandbox.run` does) |
| DM-07 | Telemetry tampering (D5) | Evidence comes only from outside the target's control: gVisor trace points (emitted by the Sentry), the sidecar's network log, and a post-run filesystem diff (`docker diff`). Nothing from an in-sandbox agent. Trace loss (sink errors, dropped events) is recorded and reported as reduced coverage |
| DM-08 | Sandbox detection and dormancy | Realistic `HOME`, user, hostname and env; canaries in real formats. Accepted limitation: delays longer than the window, time bombs, and checks for gVisor-specific behavior. The report says so. AG-CODE-027 (static anti-analysis gating) stays the complement |
| DM-09 | Attacks on our parsers (sidecar, trace collector) | The fake-network sidecar runs under `runsc` with no egress and caps on every record. The collector reads gVisor's protobuf stream, but the strings are target-controlled, so it caps sizes and writes JSON. The trace is then parsed by the engine only inside the existing static scanner sandbox |
| DM-10 | Hostile strings in reports (D6) | Same as TM-09/TM-10: `RedactedText`, control-character rendering, escaping. Canary values are always replaced with `<canary:kind>` |
| DM-11 | Oracle for evasion (D7, T6) | The web shows findings and a short summary, not the full raw trace; the raw trace stays CLI-only. Accepted: any public dynamic service is somewhat an oracle |
| DM-12 | Fail-open (TM-06 analogue) | A crash, timeout or missing dependency gives a coverage finding (AG-SYS-005), never an empty "clean" dynamic section |

## 3. Isolation options

### 3.1 Options

| Option | Isolation boundary | Telemetry | Needs | Fits t4g.small (arm64, 2 GB)? | Verdict |
|---|---|---|---|---|---|
| Docker + `runc` | Shared host kernel (namespaces, seccomp) | eBPF/auditd on the host | Nothing | Yes | **Rejected.** One kernel LPE and the target owns the host |
| **Docker + gVisor (`runsc`, systrap)** | User-space kernel (Sentry) + seccomp on the Sentry | Trace points to a remote sink (from outside the target) | `runsc` (already installed by `bootstrap.sh`); no KVM | Yes, at about one job at a time | **Recommended for Phases 1–3** |
| Kata Containers (QEMU/Cloud Hypervisor/Firecracker) | Hardware VM per container | Network from outside the VM; process/file telemetry needs an in-guest agent the target can reach after a guest-kernel exploit | KVM: "requires nested virtualization or bare metal"; containerd shim | No (Graviton t4g has no nested virtualization) | Phase 4 option |
| Firecracker directly | Hardware VM + minimal VMM + jailer | As Kata; more custom work (rootfs, networking, agent) | KVM (`/dev/kvm`); project tests only `.metal` | No | Phase 4 option if Kata doesn't fit |
| Instance-per-batch (throwaway EC2 + gVisor inside) | Nitro boundary around the whole batch, gVisor inside | gVisor trace points | `ec2:RunInstances` for whoever launches it | n/a (separate instance) | Good blast radius. It widens IAM if the dispatcher launches it, so operator-launched only |

Why gVisor first. It's already on the instance. It needs no KVM. It works on the arm64
t4g.small. Its trace points are telemetry the target can't reach, which a microVM only gets
with an in-guest agent. A microVM gives a stronger boundary (hardware virtualization instead
of a user-space kernel) but weaker telemetry for the same effort. For a scanner whose output
is evidence, the telemetry matters as much as the boundary. The two compose: in Phase 4, the
microVM is the outer wall and the network evidence comes from its tap device, outside the
guest.

Architecture note. Graviton is arm64. npm/PyPI packages that ship x86-only native binaries
won't run there. The runner reports `exec format error` as reduced coverage (AG-SYS-005), not
as a finding. An x86 worker (`c7i-flex`) removes that gap.

### 3.2 Cost (ap-southeast-2, Linux on-demand, AWS Price List effective 2026-10-01)

| Instance | vCPU / RAM | $/hour | 24/7 month (730 h) | Hours per $120 | Free-tier eligible | Nested virtualization |
|---|---|---|---|---|---|---|
| t4g.small (current) | 2 / 2 GiB, arm64 | 0.0212 | 15.48 | ≈ 5,660 | Yes | No |
| c7i-flex.large | 2 / 4 GiB, x86_64 | 0.1107 | 80.83 | ≈ 1,084 | Yes | Yes (User Guide) |
| m7i-flex.large | 2 / 8 GiB, x86_64 | 0.1197 | 87.38 | ≈ 1,003 | Yes | Yes (User Guide) |
| c6g.metal | 64 / 128 GiB, arm64 | 2.8416 | 2,074 | ≈ 42 | No | n/a (bare metal) |
| c7g.metal | 64 / 128 GiB, arm64 | 3.0195 | 2,204 | ≈ 40 | No | n/a |
| c5.metal | 96 / 192 GiB, x86_64 | 5.328 | 3,889 | ≈ 22.5 | No | n/a |

Instance hours only. EBS, the public IPv4 address and data transfer are extra (the README puts
disk plus idle Elastic IP at about $5/month).

What this means:

- **Phase 1–2 cost nothing extra** if they run on the existing t4g.small (operator-only),
  or a few dollars if they run on an on-demand `c7i-flex.large` that is started for a batch
  and stopped afterwards. One hour a day comes to about $3.40/month.
- **Bare metal doesn't fit the free plan.** It isn't free-tier eligible, and the Billing
  guide says free plans exclude features "that could possibly deplete your credits". Even on
  the paid plan, an always-on metal host costs about 100× the current stack.
- **A second always-on host doesn't fit the credits** (Section 0.2). Before any dynamic
  worker runs, check the remaining credits with `aws freetier get-account-plan-state` and
  confirm the plan type. If the project upgrades to the paid plan, set a spend limit in AWS
  Settings first.

### 3.3 Before relying on nested virtualization (Phase 4 gate)

1. `aws ec2 describe-instance-types --region ap-southeast-2 --filters
   Name=processor-info.supported-features,Values=nested-virtualization` lists `c7i-flex`
   (the User Guide and the API reference disagree).
2. A free-plan account can launch with `--cpu-options NestedVirtualization=enabled` (a
   `--dry-run` launch answers this).
3. Firecracker (or Kata with Cloud Hypervisor) boots a guest under nested KVM on
   `c7i-flex.large`, and the per-job overhead (boot, memory) fits 4 GiB.

## 4. Fake network: sinkhole DNS, record-don't-forward egress

```
        per-job internal network 10.233.<n>.0/29  (docker network create --internal)
  ┌──────────────────────────────┐             ┌─────────────────────────────────┐
  │ target (runsc-dyn)           │  DNS, TCP   │ fakenet sidecar (runsc)         │
  │ --dns 10.233.n.2             │ ──────────▶ │ DNS: every A → 10.233.n.2       │
  │ no other route               │             │ TCP 80/443/8080/…: accept,      │
  └──────────────────────────────┘             │ record, answer inert, close     │
             │ connect() to any other IP       └─────────────────────────────────┘
             ▼                                            │ JSONL records (capped)
     ENETUNREACH, recorded by the                         ▼
     syscall trace point                              collector → RuntimeTrace
  host firewall (DOCKER-USER and INPUT): drop 10.233.0.0/16 → anything except the sidecar,
  including the gateway IP and 169.254.169.254
```

- **DNS.** The sidecar answers every `A` query with its own address, answers `AAAA` empty and
  other types `NXDOMAIN`, and logs `(qname, qtype)`. It also decodes base32/base64/hex labels
  to look for canaries, so DNS tunnelling of a secret is caught.
- **TCP and HTTP.** The sidecar listens on a fixed port list (80, 443, 8080, 8443, 22, 25,
  53/tcp, 6379, 5432 and others). For HTTP it records method, `Host`, path and redacted
  headers. It keeps the first 64 KiB of each body as a hash plus a canary scan, then answers
  a fixed `200` with an empty body.
- **TLS.** It reads the ClientHello, records SNI and ALPN, then closes. No interception in
  v1, so HTTPS bodies are not seen. Canaries sent over TLS are therefore caught only through
  DNS/SNI or the file-read side. Phase 2 may add an opt-in per-job CA through
  `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE`; certificate pinning
  defeats it.
- **IP literals and other ports.** There's no route, so `connect()` fails. The gVisor
  syscall trace still records the destination. That's the primary egress evidence; the
  sidecar adds layer-7 detail for name-based traffic.
- **Never serve payloads.** Second-stage downloads get empty answers. That's deliberate: we
  never hand the target code. The finding says "second stage not retrieved".
- **Phase 1 needs no sidecar.** The target runs with `--network none`. Egress attempts are
  still visible as `connect`/`sendto` trace points (including UDP to the resolver from
  `/etc/resolv.conf`); only DNS names and layer-7 detail are missing.

## 5. Driving the target

### 5.1 Phases of one dynamic job

1. **Resolve and fetch.** Same as today (`resolve.py`, `fetch.py`): exact version,
   registry integrity (npm SHA-512, PyPI SHA-256) verified.
2. **Install, unobserved and without scripts.** In a separate `runsc` container whose only
   egress is a registry-forwarding proxy in the dispatcher (the Fetcher's allowlist, with
   integrity checks): `npm install --ignore-scripts` from the fetched tarball. For PyPI, use
   `pip install --only-binary=:all:`; an sdist-only package gets AG-SYS-005. No package code
   runs here. The resolved dependency tree (name, version, integrity) is recorded and
   becomes part of the cache key.
3. **Install scripts, observed.** The package's own lifecycle scripts (`preinstall`,
   `install`, `postinstall`), run on the fake network with canaries in place. This is the
   AG-CODE-024 surface, now with behavior.
4. **Server session, observed.** Described next.
5. **Teardown.** Close stdin, `SIGTERM` after a grace period, then `SIGKILL`. Record
   processes that outlive the server (daemonization). Run `docker diff` for the filesystem
   delta, then force-remove everything.

### 5.2 MCP STDIO session script

The runner speaks newline-delimited JSON-RPC over the child's stdio. It reuses the two
handshakes of the read-only remote client (`net/remote.py`): `server/discover` for
2026-07-28, and `initialize` + `notifications/initialized` for 2025-11-25 and 2025-06-18.

| Step | Default | What it observes |
|---|---|---|
| S0 start | on | Startup behavior before any request (import-time payloads run here, before any tool is used) |
| S1 handshake | on | Server info, capabilities, `instructions` |
| S2 `tools/list`, `prompts/list`, `resources/list` (paginated, capped) | on | The baseline definitions; the same metadata rules as the remote probe |
| S3 idle and re-list at +15 s, +45 s, +90 s; `subscriptions/listen` where supported | on | Time-based rug pulls; `notifications/tools/list_changed` |
| S4 fresh process with a different `clientInfo` (e.g. `claude-code` instead of `agentguard`), list again | Phase 2 | Definitions that vary by client identity |
| S5 `tools/call` once per tool, serialized, each in its own time window | **off** (`--dynamic-calls`) | Per-tool behavior: egress, file writes, spawns, output content |
| S6 re-list after the calls | with S5 | Tool changes as a side effect of requests (a MUST NOT in 2026-07-28) |

Synthetic inputs for S5 are generated from each `inputSchema` with a seed derived from the
normalized tool definition, so the same tool always gets the same arguments. Strings carry an
inert per-job marker, `agw-<nonce>`. A path argument points at a planted file under the work
directory, a URL at `http://agw-<nonce>.example.test/`, and a "command"-like parameter gets
the bare marker. If the marker shows up in an `execve` argv, an outbound request or a file
path outside the work directory, that's runtime evidence that the input reaches a sink
(AG-CODE-001/002/005/006). Every call runs inside the sandbox, on the fake network, with fake
credentials, so even destructive tools only harm the throwaway container. S5 stays opt-in
because it multiplies run time and makes reports noisier.

### 5.3 Skills

Skills don't have a protocol, so the runner executes exactly what an agent would: the
`` !`cmd` `` and ```` ```! ```` dynamic-context commands, the `hooks:` commands from the
frontmatter, and each file under `scripts/`, run once with no arguments and once with
`--help`. All of them run in the same observed environment, with the skill directory mounted
read-only at a realistic path (`~/.claude/skills/<name>/`). Commands the static analyzer
already extracts (AG-SKL-EXEC-*) are the run list. This is Phase 2. MCP STDIO comes first
because its entry point is unambiguous.

### 5.4 The observed environment and canaries

- User `dev` (uid 1000), `HOME=/home/dev`, hostname `dev-laptop`, `TZ=UTC`, a fixed `PATH`,
  locale `C.UTF-8`, working directory `/home/dev/project`.
- Planted canary files with realistic formats: `~/.ssh/id_ed25519` and `known_hosts`,
  `~/.aws/credentials` and `~/.aws/config`, `~/.npmrc` (auth token), `~/.pypirc`,
  `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`,
  `project/.env`, `~/.claude.json` and `~/.cursor/mcp.json` with a fake server entry, a
  browser profile stub (`~/.config/google-chrome/Default/Login Data`), and a crypto wallet
  directory stub.
- Canary environment variables: `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`,
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NPM_TOKEN`.
- Values are random per job, never registered with a canary-token service (that would need
  egress and leak data), and recorded only as `<canary:kind>`.
- Agent-instruction targets that a poisoning payload would write to (`CLAUDE.md`,
  `AGENTS.md`, `~/.claude/skills/`, MCP configs) exist and are hashed before and after.

### 5.5 What is recorded

| Source | Events | Notes |
|---|---|---|
| gVisor trace points (remote sink → collector) | `syscall/openat/enter` (path, flags), `syscall/execve/enter` (path, argv), `sentry/clone`, `syscall/fork/enter`, `connect` and `sendto` (by name, or `syscall/sysno/<n>/enter`), `container/start` | The exact point list must be confirmed with `runsc trace metadata` on our build; syscall numbers differ between arm64 and x86_64 |
| Fake-network sidecar | DNS queries, TCP connects, HTTP requests, TLS ClientHello | Capped per job (e.g. 2,000 records) |
| `docker diff` after the run | Added, changed and deleted paths | Persistence and instruction-file writes, independent of the trace |
| Runner | Every JSON-RPC exchange (redacted), tool snapshots per step, notifications, exit status, stderr tail, resource peaks | Tool snapshots are normalized the same way as `agentguard.lock` |

The collector writes all of this into a `RuntimeTrace` (a new
`core/models/runtime.py`, a sibling of `RemoteProbe`). Each event carries the step it belongs
to (S0…S6, install, teardown), so findings can say "while calling `read_file`" rather than
"sometime".

## 6. Determinism

A dynamic run is a sample of behavior, not a proof. These measures keep reports stable
enough to diff, cache and badge:

- **Pinned inputs.** Exact version, registry integrity, a recorded dependency tree, the
  runner image digest, the `runsc` version and a scenario version are all in the report
  header and in the cache key (extending `core/cachekey.py`).
- **Fixed scenario.** Ordered steps with fixed per-step budgets, seeded synthetic inputs, and
  a fixed environment (Section 5.4).
- **Normalization before findings.** Timestamps, PIDs and ports are dropped. Random path
  segments are collapsed (`/tmp/tmp.k3J9x/…` → `/tmp/*/…`, using the same placeholder rules
  for every job). Canary values become `<canary:kind>` and nonces become `<nonce>`. Events
  are deduplicated into sorted sets of `(kind, normalized target, step)` with counts rounded
  to 1, 2–9 or 10+.
- **Set-based rules.** A rule fires when an observation is present. Ordering and timing
  never affect whether a finding exists, only its evidence text.
- **Honest absence.** The report lists the window (for example "observed for 90 s after
  start; 3 re-lists; tool calls not run"), the steps completed, and the AG-SYS-005 reasons
  (timeout, crash, unsupported architecture, sdist-only, trace events dropped). Repeat runs
  (2-of-3 agreement) are deferred; on the web they triple the cost.
- **Fingerprints.** Dynamic findings get a `partialFingerprints` value built from the rule id
  and the normalized target, so SARIF alerts stay stable across reruns.

## 7. Rules

### 7.1 Data model and rule-schema changes

- `EvidenceKind.runtime` (new) for evidence from a trace.
- `rule.v1.json` gains `dynamic: bool` (default `false`), mirroring `network`: the rule only
  evaluates when a `RuntimeTrace` is present.
- `ScanOptions.runtime_traces: list[RuntimeTrace]`, passed in exactly like `remote_probes`.
- Capability labels from observations (egress, exec, file write, credential read) enter the
  capability graph tagged `source: runtime`, so the existing flow correlation (AG-FLOW-*) and
  drift (AG-SC-005) use them without new code paths.

### 7.2 Existing rules that gain runtime evidence

Corroboration adds a `runtime` evidence item and may raise **confidence** one level. It never
raises severity: severity stays the rule's static definition, so a dynamic run doesn't
change the CRITICAL precision budget.

| Rule | Runtime corroboration |
|---|---|
| AG-CODE-020 Reads credential paths | A canary file was opened |
| AG-CODE-022 Hardcoded outbound host | That host was resolved or contacted |
| AG-CODE-024 Install-time hook | The hook ran and did something (network, credential read, spawn): see AG-DYN-008 |
| AG-CODE-025 Runtime fetch of remote code | An outbound fetch followed by an `execve` or `eval`-sized write was observed |
| AG-CODE-026 Persistence writes | `docker diff` shows a write to an rc file, crontab or autostart path |
| AG-CODE-028 Native binary downloaded | An `execve` of a file created during the run |
| AG-CODE-001/002/005/006 Tool parameter to sink | The S5 marker reached `execve` argv, a file path or an outbound URL |
| AG-CODE-040 Undeclared capability | The observed capabilities of a tool exceed what its text and annotations declare |
| AG-MCP-META-011/012 Hint contradicted | Writes or egress observed while calling a tool marked `readOnlyHint: true` or `openWorldHint: false` |
| AG-MCP-META-020 Rug-pull enabler | AG-DYN-006/007 fired for the same server |
| AG-SC-001/003 Lock drift | `agentguard lock --dynamic` can lock the runtime tool list instead of the statically extracted one |
| AG-SC-011 IOC domain/IP | Matched against observed DNS names and connect addresses |
| AG-FLOW-005 Private data → egress | AG-DYN-003 is the runtime proof of this flow |
| AG-SKL-EXEC-001/002 | The dynamic-context or hook command ran and its behavior is attached |

### 7.3 New rules (`AG-DYN-*`, `dynamic: true`)

| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-DYN-001 | Outbound network attempt at run time (DNS or connect); host listed | low (med if not mentioned in code or docs; high if IOC or known exfil sink) | H | ASI02 | MCP10 | — | LLM02 | — |
| AG-DYN-002 | Canary credential file or variable read at run time | med (high if no tool description or config declares that credential's service) | H | ASI03 | MCP01 | AST03 | LLM02 | CWE-522 |
| AG-DYN-003 | Canary value left the process (DNS label, HTTP request, SNI, or a file written outside the work directory) | **crit** | H | ASI02 | MCP10 | AST01 | LLM02 | CWE-200 |
| AG-DYN-004 | Process spawned at run time (shell, interpreter, or a binary written during the run); argv listed | low (high if the binary was downloaded or written during the run) | H | ASI05 | MCP05 | AST06 | — | CWE-78 |
| AG-DYN-005 | Persistence written at run time (shell rc, crontab, autostart, systemd user unit) | high | H | ASI06 | — | AST01 | — | — |
| AG-DYN-006 | Tool definitions changed during a session (over time or after a request) | high | H | ASI04 | MCP03 | AST07 | LLM03 | — |
| AG-DYN-007 | Tool definitions differ by client identity | high | H | ASI04 | MCP03 | AST07 | — | — |
| AG-DYN-008 | Install script did network, credential or spawn activity | high | H | ASI04 | MCP04 | AST02 | LLM03 | CWE-829 |
| AG-DYN-009 | Write to agent instruction, skill or MCP config files at run time (memory or config poisoning) | high | H | ASI06 | MCP10 | AST05 | LLM01 | — |
| AG-DYN-010 | Tool output contains instruction-layer content (the META injection rules applied to S5 results) | high | M | ASI01 | MCP06 | — | LLM01 | — |
| AG-DYN-011 | Process survives server shutdown (daemonization) | med | H | ASI10 | MCP04 | AST01 | — | — |
| AG-SYS-005 | Dynamic run incomplete (timeout, crash, unsupported architecture, sdist-only, trace events dropped); coverage reduced | info | H | — | — | AST08 | — | — |

The mappings follow the conventions of `mappings/`. They're a draft until each rule's
fixture lands, and like every mapping they get checked against the sources in
`docs/sources.md` before they're shipped.

Precision notes:

- **AG-DYN-003 is the only new CRITICAL.** It is a high-specificity conjunction (a random
  per-job secret was read and then emitted), consistent with "CRITICAL = conjunction or
  signature" in the v1 design.
- **AG-DYN-002 is deliberately tempered.** An AWS MCP server legitimately reads
  `~/.aws/credentials`. The rule drops to medium when a tool description or the
  configuration declares the matching service.
- **AG-DYN-001 is low by default.** Many servers do benign update checks or telemetry at
  startup. Policy can raise it (`network: deny` in a policy file escalates every runtime
  egress).

Fixtures: each rule gets positive and negative recorded traces under
`fixtures/rules/AG-DYN-*/`. They are produced once by running small purpose-built local test
packages (never real malware) through the runner. Committed as JSON, they test the engine on
every platform.

## 8. Where it runs: CLI and web

### 8.1 CLI

- `agentguard scan <target> --dynamic` (opt-in, Linux only). It needs Docker and a `runsc-dyn`
  runtime, registered with `runsc install --runtime runsc-dyn -- --pod-init-config=…`, which
  is the mechanism gVisor documents for per-runtime flags. `--dynamic-calls` enables S5;
  `--dynamic-window` caps S3.
- `agentguard dynamic doctor` checks prerequisites and runs the no-egress self-test.
  `agentguard dynamic replay trace.json` evaluates a recorded trace with no Docker (any OS,
  CI, fixtures). `--dynamic-out trace.json` saves the raw trace.
- **Process guard.** The audit hook stays installed. The runner gets an `allow_exact` carve-out
  like the hardened `git` helper: it may start only `docker` with argv it built itself. It
  never starts the target directly, and the target runs only inside `runsc-dyn`. TM-01 is
  re-worded to: "the engine never executes target code; the opt-in dynamic runner starts it
  only inside a gVisor sandbox through an exact-argv Docker invocation".
- macOS and Windows: `replay` only. A local run is refused (Docker Desktop's VM doesn't ship
  `runsc`, and we don't fall back). The GitHub Action stays static. GitHub-hosted runners
  could install `runsc`, but that's not in this proposal.

### 8.2 Web server (`web/src/agentguard_web/`)

The static path stays exactly as it is. `DockerSandbox.flags()` is the static guarantee and
isn't touched. Dynamic work is a separate job kind with its own sandbox class:

```
api ──PoW, stricter quota──▶ queue:dynamic ──▶ dynamic worker
                                               │ resolve + fetch (Fetcher, integrity)
                                               │ install (runsc, registry proxy only)
                                               │ observed run (runsc-dyn, fakenet, collector)
                                               ▼
                                           RuntimeTrace JSON (untrusted)
                                               │
dispatcher ──▶ existing scanner sandbox (network none): archive + trace ──▶ one Report
```

- `dispatcher.py`: `build_pipeline` gains a `DynamicSandbox` (new `dynamic.py`), created only
  when `AGW_DYNAMIC=1` and the `runsc-dyn` runtime is present. `Settings.validate()` refuses
  `AGW_DYNAMIC=1` with any other runtime, in the same way it refuses `inprocess` in
  production. `AGW_DYNAMIC_WORKERS` defaults to 1, separate from `AGW_WORKERS`.
- `pipeline.py`: a `JobKind.dynamic` path runs resolve → fetch → `DynamicSandbox.run(...)` →
  the existing `Sandbox.run` with a new spec mode `archive+runtime`. The trace is passed the
  way `remote_mcp` passes a recorded probe today (`sandbox_entry.py`), so hostile trace
  strings are parsed only inside the static scanner sandbox.
- `sandbox_entry.py`: the new mode reads the archive and the trace from the payload. The
  process-creation guard stays installed.
- Limits: a separate queue cap (5), 1 GiB memory, 1 CPU, 256 PIDs, 10 MiB overlay and
  tmpfs, 30 s install, 90 s session (120 s total), a higher PoW difficulty, 3 dynamic jobs
  per client per day. Results are cached like static reports, keyed as in Section 6.
- Exposure in stages: Phase 2 is operator-only (a CLI on the instance, through Session
  Manager), Phase 3 is public. Public use needs a dedicated worker host whose Docker daemon
  holds nothing else: no Postgres, no `.env`, no socket shared with the API. The worker takes
  jobs from `queue:dynamic` and returns only `RuntimeTrace` JSON. The main dispatcher stays
  the only process that writes reports.
- `web/threat-model.md` gains the DM-* rows as "planned", turning "implemented" one at a time.

## 9. Phased plan

| Phase | Scope | Exit criteria | AWS cost |
|---|---|---|---|
| **1 — minimal slice** | `RuntimeTrace` model and `dynamic` analyzer; AG-DYN-002, -004, -005, -006, -011 and AG-SYS-005; `EvidenceKind.runtime`; `replay`; a CLI runner for **npm STDIO servers only** under `runsc-dyn` with `--network none`; steps S0–S3; canary files and variables; `docker diff`; recorded fixtures from three purpose-built test packages (startup `~/.ssh` read, a tool list that changes at +45 s, a crontab write) | Fixtures pass on Windows, Linux and Pyodide; `dynamic doctor` proves no egress on the t4g.small; one known-benign popular server gives no finding above low | $0 (operator-run on the existing instance, or locally on Linux) |
| 2 — network and inputs | Fakenet sidecar, AG-DYN-001/003; install-script phase, AG-DYN-008; PyPI wheels; opt-in S5 tool calls, AG-DYN-010 and the runtime corroboration in 7.2; S4 client-identity check, AG-DYN-007; skills (Section 5.3), AG-DYN-009; `lock --dynamic` | Adversarial benchmark gains a dynamic split; precision report for AG-DYN-* | $0–5/month (on-demand `c7i-flex.large` for x86 coverage, stopped when idle) |
| 3 — web | `JobKind.dynamic`, `DynamicSandbox`, `archive+runtime` spec mode, quotas, a dedicated worker host, site UI section "Observed at run time" | `check-dynamic-sandbox` gate in `deploy.sh`; abuse tests (fork bomb, miner, egress flood) contained | Depends on the worker host decision; does not fit in the remaining credits as always-on |
| 4 — stronger isolation | Optional microVM backend (Kata or Firecracker) on nested-virtualization Intel, with network evidence from the tap device | Section 3.3 checks pass; per-job overhead measured | As Phase 2, on the same on-demand instance type |

Why this slice first. It needs no new infrastructure, no network component and no change to
the web server, so it can't weaken anything that runs today. It proves the riskiest design
choice: that gVisor trace points plus `docker diff` give stable, normalized evidence.
Everything later builds on the same `RuntimeTrace`. Phase 1 still has to settle the exact
trace-point names on arm64 and the collector's socket permissions (gVisor's remote sink
connects to a Unix socket on the host).

## 10. Open questions (need your call before build)

1. **Where does Phase 1 run?** The existing t4g.small, operator-only (free, arm64, shares a
   host with the live stack), or an on-demand `c7i-flex.large` (about $0.11/hour, x86, a
   separate blast radius, and it also unlocks Phase 4)? Recommendation: the on-demand
   `c7i-flex.large` for any third-party package; the t4g.small only for our own test
   packages.
2. **Public dynamic scans on the web: yes, later or never?** They are the most expensive and
   abuse-prone feature (DM-05, DM-11). The alternative is CLI-only dynamic analysis plus
   publishing dynamic results for a curated list of popular servers.
3. **Should tool calls (S5) ever be on by default?** Recommendation: no.
4. **New rule prefix `AG-DYN-*`** versus folding the rules into the existing families
   (CODE/META/SC). Recommendation: a separate prefix, so a user can tell static evidence
   from observed behavior at a glance.

---

## Sources

Same format as `docs/sources.md`. These rows move there when Phase 1 lands.

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| EC2 nested virtualization (launch) | Since 2026-02-16, KVM or Hyper-V can run on virtual EC2 instances (C8i, M8i, R8i), where before only bare metal was possible | https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual | 2026-10-21 (search summary of the announcement) |
| EC2 nested virtualization (expansion) | 2026-06-18: added C7i, R7i, M7i, C8id, R8id, M8id, C7i-flex, M7i-flex, I7i, C8i-flex, R8i-flex, M8i-flex and X8i, all commercial Regions | https://aws.amazon.com/about-aws/whats-new/2026/06/nested-virtualization-intel-us-gov-cloud/ | 2026-10-21 |
| EC2 nested virtualization (User Guide) | Supported families incl. M7i-flex and C7i-flex; KVM and Hyper-V are the supported L1 hypervisors; no extra cost; `--cpu-options "NestedVirtualization=enabled"` at launch, or `modify-instance-cpu-options` while stopped; `describe-instance-types` filter `processor-info.supported-features=nested-virtualization`; AWS recommends evaluating bare metal for performance-sensitive work | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html | 2026-10-21 (read in full). **Conflict**: the `CpuOptionsRequest` API reference says only 8th-generation types (c8i, m8i, r8i and flex) are supported. TODO: confirm with `describe-instance-types` in ap-southeast-2 |
| EC2 free-tier eligible types | Accounts created on or after 2025-07-15: t3.micro, t3.small, t4g.micro, t4g.small, c7i-flex.large, m7i-flex.large; free tier lasts 6 months or until credits are used; "You can't exceed your Free Tier limits" | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-free-tier-usage.html | 2026-10-21 |
| AWS free plan limits | Free plans don't include services and features "that could possibly deplete your credits"; upgrading to a paid plan removes the limits | https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/free-tier-plans.html · https://aws.amazon.com/free/free-tier-faqs/ | 2026-10-21 (search summary; whether a free-plan account can launch `.metal` or enable nested virtualization is **not verified**, TODO dry-run) |
| EC2 prices, ap-southeast-2 | Linux on-demand per hour, effective 2026-10-01: t4g.small 0.0212, c7i-flex.large 0.11072, m7i-flex.large 0.1197, c7i.large 0.11655, c8i.large 0.12238, c6g.metal 2.8416, c7g.metal 3.0195, m7g.metal 3.264, c5.metal 5.328 | https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/ap-southeast-2/index.csv (AWS Price List bulk file, filtered to Linux, shared tenancy, no pre-installed software, used capacity; lowest OnDemand row per type) | 2026-10-21 |
| Project credits and current cost | Free plan, $120 credits until 2027-04-18; the stack costs about $20/month all-in | `deploy/aws/README.md` | 2026-10-21 (repository; remaining credits not re-checked, since the AWS CLI session had expired) |
| Firecracker host requirements | Needs KVM and read/write access to `/dev/kvm`; x86_64 or aarch64 hosts; "EC2 only supports KVM on `.metal` instance types"; nested virtualization not mentioned | https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md | 2026-10-21 (the guide predates EC2 nested virtualization; untested under it) |
| Kata Containers host requirements | "requires nested virtualization or bare metal" | https://github.com/kata-containers/kata-containers/blob/main/docs/install/README.md | 2026-10-21 (supported hypervisors and Docker vs containerd integration: TODO) |
| gVisor platforms | systrap is the default since mid-2023 (replaced ptrace) and is recommended for VMs and machines without virtualization support; KVM is an alternative platform | https://gvisor.dev/docs/architecture_guide/platforms/ | 2026-10-21 (whether systrap needs nested virtualization is not stated explicitly; arm64 support not stated on the page; `bootstrap.sh` installs the aarch64 build) |
| gVisor networking | `--network=sandbox` (netstack, default), `host`, `none` (loopback only); packets go to the device in the namespace Docker sets up | https://gvisor.dev/docs/user_guide/networking/ | 2026-10-21 |
| gVisor runtime monitoring | Trace points for all syscalls and other events, streamed to a process alongside and isolated from the sandbox | https://gvisor.dev/docs/user_guide/runtimemonitor/ · https://gvisor.dev/blog/2022/08/01/threat-detection/ | 2026-10-21 |
| gVisor trace session config | `--pod-init-config` JSON with top-level `trace_session` (`name: "Default"`, `points[]` with `name`/`optional_fields`/`context_fields`, `sinks[]` with `name: "remote"` and `config.endpoint` = Unix socket); example points `syscall/openat/enter`, `syscall/execve/enter`, `syscall/fork/enter`, `syscall/sysno/35/enter`, `sentry/clone`, `container/start`, `sentry/signal_delivered`; `runsc trace create/list/delete/metadata` | https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/README.md | 2026-10-21 (a named `connect` point is not listed; TODO `runsc trace metadata` on our build) |
| gVisor with Docker | `runsc install` registers runtime `runsc`; `runsc install --runtime <name> -- <flags>` registers another runtime name with its own flags; restart Docker afterwards | https://gvisor.dev/docs/user_guide/quick_start/docker/ | 2026-10-21 |
| Falco + gVisor | Falco consumes gVisor events through `--pod-init-config` in Docker's daemon.json; runsc released in 2023 or later is compatible | https://falco.org/docs/event-sources/gvisor | 2026-10-21 (search summary; prior art only, Falco is not proposed) |
| Docker internal networks | `--internal`: "no default route is configured and firewall rules are set up to drop all traffic to or from other networks"; containers can still reach the gateway IP, so host services there remain reachable | https://docs.docker.com/reference/cli/docker/network/create/ | 2026-10-21 |
| MCP 2026-07-28 tools | `tools/list` "MUST NOT vary per-connection or as a side effect of other requests on the connection" (may vary by authorization); `listChanged` + `notifications/tools/list_changed` over `subscriptions/listen`; `tools/call` shape; tool annotations untrusted unless from trusted servers | https://modelcontextprotocol.io/specification/2026-07-28/server/tools | 2026-10-21 |
| MCP 2026-07-28 transports | stdio = newline-delimited JSON-RPC over a client-launched subprocess's standard streams; cancellation via `notifications/cancelled`; earlier revisions used an `initialize` handshake, with fallback rules in Versioning | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports | 2026-10-21 |
| INetSim | A suite simulating common internet services in a lab, used to analyze the network behavior of unknown malware; 1.3.2 (2020-05-19) | https://www.inetsim.org/ | 2026-10-21 (prior art for the fakenet design; not proposed as a dependency) |
| npm `--ignore-scripts` | Skips package lifecycle scripts during install | https://docs.npmjs.com/cli/v11/using-npm/config#ignore-scripts | TODO (not re-read for this document) |
| pip `--only-binary=:all:` | Refuses source distributions, so no build backend runs at install | https://pip.pypa.io/en/stable/cli/pip_install/ | TODO (not re-read for this document) |
