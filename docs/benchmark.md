# Benchmark: corpus, splits and how the numbers were produced

`agentguard bench` scores the corpus under `bench/corpus/` (manifest: `bench/manifest.yaml`).
Results are committed in `bench/results/latest.json`; CI reruns the benchmark and fails on
target misses or regressions (`scripts/check_bench.py`).

## Corpus

| Source | Label | Items | Split |
|---|---|---|---|
| Synthetic malicious / adversarial (`bench/generate_synthetic.py`) | malicious, adversarial | 36 | dev / heldout by template author |
| Synthetic benign | benign | 25 | dev / heldout by template author |
| anthropics/skills @ `8a1541c4a3ff` (13 Apache-2.0 skills) | benign | 13 | dev |
| openai/skills @ `49f948faa925` (35 Apache-2.0 / MIT skills) | benign | 35 | dev |
| modelcontextprotocol/servers @ `f46d9578190b` (7 reference servers) | benign | 7 | dev |
| microsoft/playwright-mcp @ `f183dad4a529` | benign | 1 | dev |
| huggingface/skills @ `80f9fa530e46` (25 skills) | benign | 25 | dev |
| supabase-community/supabase-mcp @ `4cc6660f6566` (3 packages) | benign | 3 | dev |
| microsoft/skills @ `23d0dac5f83f` (61 skills) | benign | 61 | **heldout** |
| cloudflare/mcp-server-cloudflare @ `1d7a16b25db7` (18 servers) | benign | 18 | **heldout** |

Real items are vendored verbatim, one benchmark item per skill or server directory, by
`bench/fetch_real.py` from `bench/real_sources.yaml` (pinned commit + tarball SHA-256, license
text checked per directory). Nothing is executed. Attribution is in `bench/NOTICE`; repository
license files are copied to `bench/licenses/`.

Not vendored, on purpose: the anthropics/skills `docx`, `pdf`, `pptx` and `xlsx` skills and the
openai/skills Figma skills (proprietary licenses), anthropics `doc-coauthoring` (no license
file), anthropics `canvas-design` (mostly bundled third-party fonts), openai `cloudflare-deploy`
(1.3 MB of vendored docs), and Cloudflare's generated `worker-configuration.d.ts` files.

## How the real items were used (read this before quoting the held-out numbers)

The real corpus was added while rules were being tuned for false positives, in rounds. A
source is `dev` once any rule was changed after looking at its findings:

| Round | Tuned on | Held-out set, measured once before tuning on it | Held-out items flagged ≥ HIGH |
|---|---|---|---|
| 0 (before) | — | openai/skills, MCP servers, playwright-mcp (43 items), old rules | 19 / 43 |
| 1 | anthropics/skills | same 43 items | 16 / 43 |
| 2 | + openai/skills, MCP servers, playwright-mcp | huggingface/skills, supabase-mcp (28 items) | 7 / 28 |
| 3 | + huggingface/skills, supabase-mcp | microsoft/skills, cloudflare MCP (79 items) | **1 / 79** |

Only the last row's sources are labelled `heldout` in the manifest; no rule was changed in
response to them. (The round-3 fix of a backtracking bug in a pattern written in round 2 was
found through a round-2 held-out item; the 7 / 28 figure is from before that fix.) For
comparison, the pre-tuning rules flag 8 / 28 of the round-2 held-out items (rounds 1-2
generalized poorly: 8 → 7) and 3 / 79 of the final held-out items (tuned rules: 1 / 79).

## Results (bench/results/latest.json)

Item level; AG-FLOW/AG-SYS/AG-POL findings are not counted as detections.

| Threshold | Precision | Recall | FPR | TP / FP / FN / TN |
|---|---|---|---|---|
| ≥ CRITICAL | 1.000 | 0.611 | 0.000 | 22 / 0 / 14 / 188 |
| ≥ HIGH | 0.914 | 0.889 | 0.016 | 32 / 3 / 4 / 185 |
| ≥ MEDIUM | 0.557 | 0.944 | 0.144 | 34 / 27 / 2 / 161 |

Held-out split at ≥ HIGH: precision 0.923, recall 0.800, FPR 0.012 (1 of 87 benign items).
Recall on every malicious and adversarial item is unchanged by the tuning (no item's flags,
maximum severity or expected-rule hit changed).

MEDIUM is noisy on real code (27 of 188 benign items; mostly AG-MCP-META-020, AG-CODE-024
npm lifecycle scripts and AG-CODE-020): treat MEDIUM as review material, not a gate.

### Benign items still flagged at HIGH, and why they are left

- `openai/skills speech` — `references/codex-network.md` tells the user how to set
  `approval_policy = "never"`. That is what AG-SKL-INJ-004 exists to catch; counted as a false
  positive here because the repository is benign.
- `huggingface/skills huggingface-llm-trainer` — `scripts/convert_to_gguf.py` runs
  `pip install sentencepiece protobuf` at run time (AG-CODE-025, unpinned install).
- `microsoft/skills agent-framework-azure-ai-py` (held-out) — a reference snippet sets
  `approval_mode="never_require"` for MCP tools (AG-SKL-INJ-004). Not tuned: it is held out.

## Decisions recorded with the tuning

- **AG-SKL-SE-007, quarantine removal:** stays CRITICAL for downloaded apps, DMGs and local
  binaries; reported at MEDIUM when the target is under a package manager prefix
  (`$(brew --prefix)`, `/opt/homebrew`, `/usr/local/{Cellar,Caskroom,opt}`, linuxbrew). The
  anthropics/skills `claude-api` instruction to clear quarantine on the Homebrew-installed
  `ant` CLI still skips Gatekeeper, so it is reported, but the trust decision is the tap.
- **Vendor installers:** `cli.sentry.dev/install`, Render's CLI installer and
  `hf.co/cli/install.sh` were added to the AG-SKL-SE-002 allowlist; such pipe-to-shell
  installs are still reported at LOW by AG-SKL-SE-008. An allowlist cannot generalize: an
  unlisted vendor installer is CRITICAL until someone adds it.
- **Mentions vs. directives:** a quoted or code-span prompt pattern in a reference document
  (AG-SKL-INJ-001/002/003/005), a chat-template token in quotes or a code span in any file
  (INJ-002), a CLI-reference line documenting an approval flag (INJ-004), and agent/MCP config
  writes that are the skill's declared purpose or are setup steps for the user (INJ-007) are
  reported at MEDIUM instead of HIGH (the rule `downgrade` field). They are not suppressed.
- **Toxic flows:** for skills, AG-FLOW-002 needs the private-data read and the egress to be
  behaviour (code, a command, a fenced snippet), not words in prose.

## Reproducing

```bash
python bench/fetch_real.py            # network; verifies pinned tarball hashes and licenses
python bench/generate_synthetic.py    # regenerates synthetic items and merges real_manifest.json
agentguard bench --output bench/results/latest.json
python scripts/check_bench.py bench/results/latest.json bench/results/latest.json
```
