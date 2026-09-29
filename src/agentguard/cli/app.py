"""agentguard command-line interface.

Exit codes: 0 = no findings at/above the threshold, 1 = findings at/above
the threshold, 2 = scanner error (including any analyzer failure).
"""

from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .. import __version__
from ..core.engine import ENGINE_VERSION, scan
from ..core.models import NetworkOptions, ScanOptions
from ..core.models.enums import Severity
from ..core.report.render import render_cyclonedx, render_json, render_markdown, render_sarif
from ..core.rules.pack import RulePack, RulePackError
from ..io import guard
from ..io.discovery import discover
from ..io.fs_loader import load_path
from .config import ConfigError, find_project_config, load_baseline, load_policy, parse_project_config
from .terminal import print_report

app = typer.Typer(
    name="agentguard",
    help="Offline-first security scanner for AI agent skills, instruction files and MCP servers. "
    "Agent Guard never executes what it scans.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
rules_app = typer.Typer(help="Inspect the rule pack.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"
    html = "html"


class SeverityOpt(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


def _console(stderr: bool = False) -> Console:
    return Console(stderr=stderr, highlight=False, soft_wrap=False)


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _fail(msg: str) -> None:
    _console(stderr=True).print(f"[bold red]error:[/bold red] {escape(msg)}")
    raise typer.Exit(2)


def _emit(text: str, output: Optional[Path]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(text.encode("utf-8"))
    else:
        sys.stdout.write(text)


def _version(value: bool) -> None:
    if value:
        pack = RulePack.default()
        typer.echo(f"agentguard {__version__} (engine {ENGINE_VERSION}, rule pack {pack.version})")
        raise typer.Exit(0)


@app.callback()
def _main(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.", is_eager=True,
                                          callback=_version)] = False,
) -> None:
    guard.install()
    _utf8_stdio()


@app.command("scan")
def scan_cmd(
    path: Annotated[Optional[Path], typer.Argument(help="Skill folder, repository, or MCP config file. "
                                                   "Omit to discover this machine's agent configuration plus the current project.")] = None,
    format: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.terminal,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write output to a file.")] = None,
    fail_on: Annotated[Optional[SeverityOpt], typer.Option("--fail-on", help="Exit 1 if any finding is at or above this severity (default: high).")] = None,
    config: Annotated[Optional[Path], typer.Option("--config", help="Path to .agentguard.yaml (default: next to the target).")] = None,
    policy: Annotated[Optional[Path], typer.Option("--policy", help="Policy YAML file (overrides the policy in .agentguard.yaml).")] = None,
    baseline: Annotated[Optional[Path], typer.Option("--baseline", help="Previous JSON report or baseline file; only new findings are reported.")] = None,
    changed_since: Annotated[Optional[str], typer.Option("--changed-since", help="PR mode: report only components touched since this git ref. Config is read from the ref.")] = None,
    lock: Annotated[Optional[Path], typer.Option("--lock", help="agentguard.lock to check for drift.")] = None,
    no_user: Annotated[bool, typer.Option("--no-user", help="When discovering, skip user-level (home directory) configuration.")] = False,
    live_metadata: Annotated[bool, typer.Option("--live-metadata", help="NETWORK: fetch read-only tool lists from remote MCP servers.")] = False,
    auth_checks: Annotated[bool, typer.Option("--auth-checks", help="NETWORK: check remote servers' OAuth/TLS conformance.")] = False,
    osv: Annotated[bool, typer.Option("--osv", help="NETWORK: look up dependencies in OSV.")] = False,
    provenance: Annotated[bool, typer.Option("--provenance", help="NETWORK: verify npm/Sigstore provenance.")] = False,
    registry: Annotated[bool, typer.Option("--registry", help="NETWORK: MCP Registry / package age checks.")] = False,
    allow_partial: Annotated[bool, typer.Option("--allow-partial", help="Do not exit 2 when an analyzer fails (recorded in the report).")] = False,
    show_info: Annotated[bool, typer.Option("--show-info", help="Show info-level findings in terminal output.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show evidence, remediation and mappings.")] = False,
    timestamps: Annotated[bool, typer.Option("--timestamps", help="Include a generation timestamp (makes output non-deterministic).")] = False,
) -> None:
    """Scan skills, instruction files and MCP configuration. Never executes the target."""
    try:
        target_root = (path or Path.cwd()).resolve()
        if path is not None and not path.exists():
            _fail(f"path not found: {path}")
        # Project config: from the base ref in PR mode (a PR cannot relax its own policy).
        pconf = None
        changed: set[str] | None = None
        repo_root = target_root if target_root.is_dir() else target_root.parent
        if changed_since:
            from ..io.git import GitError, changed_files, read_at_ref

            try:
                changed = set(changed_files(repo_root, changed_since))
                for name in (".agentguard.yaml", ".agentguard.yml"):
                    data = read_at_ref(repo_root, changed_since, name)
                    if data is not None:
                        pconf = parse_project_config(data.decode("utf-8", "replace"), f"{changed_since}:{name}")
                        break
            except GitError as exc:
                _fail(str(exc))
        else:
            cfg_path = config or find_project_config(target_root)
            if cfg_path:
                pconf = parse_project_config(cfg_path.read_text(encoding="utf-8"), str(cfg_path))
        pol = load_policy(policy) if policy else (pconf.policy if pconf else None)
        threshold = Severity(fail_on.value) if fail_on else (pconf.fail_on if pconf and pconf.fail_on else Severity.high)
        if pol and pol.max_severity is not None:
            stricter = pol.max_severity.bump(1) if pol.max_severity != Severity.critical else None
            if stricter is not None and stricter.rank < threshold.rank:
                threshold = stricter
        lockfile = None
        lock_path = lock or (repo_root / "agentguard.lock" if (repo_root / "agentguard.lock").is_file() else None)
        if lock_path:
            from ..core.models import Lockfile

            lockfile = Lockfile.model_validate_json(lock_path.read_text(encoding="utf-8"))
        options = ScanOptions(
            fail_on=threshold,
            network=NetworkOptions(live_metadata=live_metadata, auth_checks=auth_checks, osv=osv,
                                   provenance=provenance, registry=registry),
            policy=pol,
            suppressions=list(pconf.suppressions) if pconf else [],
            baseline=load_baseline(baseline) if baseline else None,
            changed_paths=changed,
            lock=lockfile,
            popular_skills=list(pconf.popular_skills) if pconf else [],
            include_timestamps=timestamps,
        )
        from ..io.intel_store import load_active_feed

        options.intel, _intel_note = load_active_feed()
        if path is None:
            tree = discover(Path.cwd(), include_user=not no_user, limits=options.limits).tree
        else:
            tree = load_path(path, options.limits, extra_excludes=tuple(pconf.exclude) if pconf else ())
        if options.network.enabled():
            from ..net.collect import collect

            _console(stderr=True).print(f"[yellow]Network features enabled:[/yellow] {', '.join(options.network.enabled())}")
            collect(tree, options)
        report = scan(tree, options)
    except (ConfigError, RulePackError, OSError, ValueError) as exc:
        _fail(str(exc))
        return
    rendered = {
        OutputFormat.json: lambda: render_json(report),
        OutputFormat.sarif: lambda: render_sarif(report),
        OutputFormat.markdown: lambda: render_markdown(report),
    }
    if format == OutputFormat.terminal:
        if output:
            _emit(render_json(report), output)
        print_report(report, _console(), verbose=verbose, show_info=show_info)
    elif format == OutputFormat.html:
        from ..core.report.html import render_html

        _emit(render_html(report), output)
    else:
        _emit(rendered[format](), output)
    code = report.exit_code()
    if code == 2 and allow_partial:
        code = 1 if any(f.severity.at_least(report.fail_on) for f in report.findings) else 0
    raise typer.Exit(code)


class DiscoverFormat(str, Enum):
    table = "table"
    json = "json"
    cyclonedx = "cyclonedx"


@app.command("discover")
def discover_cmd(
    format: Annotated[DiscoverFormat, typer.Option("--format", "-f")] = DiscoverFormat.table,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    no_user: Annotated[bool, typer.Option("--no-user", help="Skip user-level configuration.")] = False,
    project: Annotated[Optional[Path], typer.Option("--project", help="Project root (default: current directory).")] = None,
) -> None:
    """Inventory agents, MCP servers, skills and instruction files (no findings)."""
    disc = discover((project or Path.cwd()), include_user=not no_user)
    report = scan(disc.tree, ScanOptions(analyzers={"mcp.units"}))
    if format == DiscoverFormat.cyclonedx:
        _emit(render_cyclonedx(report), output)
        return
    if format == DiscoverFormat.json:
        data = {
            "locations": [r.__dict__ for r in disc.records],
            "components": [json.loads(c.model_dump_json(exclude_none=True, exclude={"capabilities"})) for c in report.inventory],
        }
        _emit(json.dumps(data, indent=2, ensure_ascii=False) + "\n", output)
        return
    con = _console()
    t = Table(title="Checked locations", title_justify="left")
    for col in ("Client", "Scope", "Kind", "Path", "Found", "Verified path"):
        t.add_column(col)
    for r in disc.records:
        t.add_row(r.client, r.scope, r.kind, escape(r.path), "yes" if r.exists else "-", "yes" if r.verified else "no")
    con.print(t)
    s = Table(title="MCP servers", title_justify="left")
    for col in ("Name", "Client", "Transport", "Command / URL", "Pinned", "Env vars (names)"):
        s.add_column(col, overflow="fold")
    for c in report.inventory:
        if c.server:
            target = c.server.url or " ".join([c.server.command or "", *c.server.args])
            s.add_row(escape(c.name), c.server.client, c.server.transport.value, escape(target[:120]),
                      "yes" if c.server.pinned else f"no ({escape(c.server.pin_detail or '')})", escape(", ".join(c.server.env_names)))
    con.print(s)
    k = Table(title="Skills and instruction files", title_justify="left")
    for col in ("Kind", "Name", "Location", "Content hash"):
        k.add_column(col, overflow="fold")
    for c in report.inventory:
        if c.kind.value in ("skill", "instruction_file", "subagent", "command"):
            k.add_row(c.kind.value, escape(c.name), escape(c.root), c.content_hash[:16])
    con.print(k)


@rules_app.command("list")
def rules_list(
    json_out: Annotated[bool, typer.Option("--json", help="JSON output.")] = False,
) -> None:
    """List every rule in the rule pack."""
    pack = RulePack.default()
    if json_out:
        _emit(json.dumps([{"id": r.id, "title": r.title, "severity": r.severity.value, "confidence": r.confidence.value}
                          for r in pack.rules.values()], indent=2) + "\n", None)
        return
    t = Table(title=f"Rule pack {pack.version} ({len(pack.rules)} rules)", title_justify="left")
    for col in ("ID", "Severity", "Confidence", "Title"):
        t.add_column(col)
    for r in pack.rules.values():
        t.add_row(r.id, r.severity.value, r.confidence.value, r.title)
    _console().print(t)


@rules_app.command("explain")
def rules_explain(rule_id: Annotated[str, typer.Argument(help="Rule ID, e.g. AG-SKL-SE-002")]) -> None:
    """Explain one rule: what it detects, why it matters, how to fix it."""
    pack = RulePack.default()
    rule = pack.rules.get(rule_id.upper())
    if rule is None:
        _fail(f"unknown rule {rule_id}")
        return
    con = _console()
    con.print(f"[bold]{rule.id}[/bold] v{rule.version} — {escape(rule.title)}")
    con.print(f"severity: {rule.severity.value} · confidence: {rule.confidence.value}")
    con.print(f"\n[bold]Detects[/bold]\n{escape(rule.description)}")
    if rule.why:
        con.print(f"\n[bold]Why it matters[/bold]\n{escape(rule.why)}")
    con.print(f"\n[bold]Remediation[/bold]\n{escape(rule.remediation)}")
    con.print("\n[bold]Standards[/bold]")
    for m in rule.mappings:
        con.print(f"  {m.framework}: {m.id or '—'}{' ' + escape(m.title) if m.title else ''}{' (TODO: ' + escape(m.todo) + ')' if m.todo else ''}")
    for ref in rule.references:
        con.print(f"  ref: {escape(ref)}")


@rules_app.command("export")
def rules_export(
    format: Annotated[str, typer.Option("--format", help="Only 'json' is supported.")] = "json",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Export the rule pack (with mappings and fixtures) as JSON for the website."""
    if format != "json":
        _fail("only --format json is supported")
    from ..core.rules.export import export_rules

    _emit(json.dumps(export_rules(RulePack.default()), indent=2, ensure_ascii=False) + "\n", output)


def _load_target(path: Optional[Path], no_user: bool, options: ScanOptions):
    if path is None:
        return discover(Path.cwd(), include_user=not no_user, limits=options.limits).tree
    if not path.exists():
        _fail(f"path not found: {path}")
    return load_path(path, options.limits)


@app.command("lock")
def lock_cmd(
    path: Annotated[Optional[Path], typer.Argument(help="Target to lock (default: discover this machine + project).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Lockfile path.")] = Path("agentguard.lock"),
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
) -> None:
    """Write agentguard.lock: hashes of skill files and normalized tool definitions."""
    from ..core.lock import build_lock, dump_lock

    options = ScanOptions()
    report = scan(_load_target(path, no_user, options), options)
    lock = build_lock(report)
    _emit(dump_lock(lock), output)
    _console(stderr=True).print(f"Locked {len(lock.entries)} components → {escape(str(output))}")


@app.command("verify")
def verify_cmd(
    path: Annotated[Optional[Path], typer.Argument(help="Target to verify (default: discover this machine + project).")] = None,
    lock: Annotated[Path, typer.Option("--lock", help="Lockfile to compare against.")] = Path("agentguard.lock"),
    fail_on: Annotated[SeverityOpt, typer.Option("--fail-on")] = SeverityOpt.low,
    format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.terminal,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    no_user: Annotated[bool, typer.Option("--no-user")] = False,
) -> None:
    """Report rug-pull / update-drift findings against agentguard.lock, with diffs."""
    from ..core.models import Lockfile

    if not lock.is_file():
        _fail(f"lockfile not found: {lock} (run `agentguard lock` first)")
    lockfile = Lockfile.model_validate_json(lock.read_text(encoding="utf-8"))
    options = ScanOptions(lock=lockfile, fail_on=Severity(fail_on.value))
    report = scan(_load_target(path, no_user, options), options)
    report.findings = [f for f in report.findings if f.rule_id.startswith("AG-SC-00")]
    report.summary = (f"{len(report.findings)} drift finding(s) against {lock}." if report.findings
                      else f"No drift from {lock} ({len(lockfile.entries)} locked components).")
    if format == OutputFormat.terminal:
        con = _console()
        for f in report.findings:
            con.print(f"[bold]{f.rule_id}[/bold] {escape('[' + f.severity.value + ']')} {escape(f.message)}")
            for ev in f.evidence[1:]:
                if ev.detail.startswith("definition diff"):
                    con.print(escape(str(ev.snippet)), highlight=False)
        con.print(escape(report.summary))
    else:
        _emit({OutputFormat.json: render_json, OutputFormat.sarif: render_sarif,
               OutputFormat.markdown: render_markdown}.get(format, render_json)(report), output)
    raise typer.Exit(1 if any(f.severity.at_least(report.fail_on) for f in report.findings) else 0)


intel_app = typer.Typer(help="Manage the local, signed IOC feed.", no_args_is_help=True)
app.add_typer(intel_app, name="intel")


@intel_app.command("status")
def intel_status() -> None:
    """Show which IOC feed is active."""
    from ..io.intel_store import load_active_feed

    feed, note = load_active_feed()
    _console().print(escape(note))
    if feed:
        e = feed.entries
        _console().print(f"{len(e.hashes)} hashes · {len(e.domains)} domains · {len(e.ips)} IPs · {len(e.publishers)} publishers")


@intel_app.command("update")
def intel_update(
    source: Annotated[str, typer.Option("--from", help="Path to feed.json (a feed.json.sig must sit next to it), or an https:// URL (NETWORK).")],
) -> None:
    """Install a newer signed IOC feed (signature and rollback checks enforced)."""
    from ..core.intel.feed import FeedError
    from ..io.intel_store import install_feed

    try:
        if source.startswith("https://"):
            from ..net.safe_http import SafeHttpClient

            client = SafeHttpClient()
            feed_bytes = client.get(source).body
            sig_bytes = client.get(source + ".sig").body
        else:
            p = Path(source)
            feed_bytes, sig_bytes = p.read_bytes(), Path(str(p) + ".sig").read_bytes()
        feed = install_feed(feed_bytes, sig_bytes)
    except (FeedError, OSError, ValueError) as exc:
        _fail(str(exc))
        return
    _console().print(f"Installed {escape(feed.describe())}")


@app.command("bench")
def bench_cmd(
    corpus: Annotated[Path, typer.Option("--corpus", help="Benchmark root containing manifest.yaml and corpus/.")] = Path("bench"),
    split: Annotated[str, typer.Option("--split", help="all | dev | heldout")] = "all",
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write results JSON here.")] = None,
    perf: Annotated[bool, typer.Option("--perf/--no-perf", help="Also time 100 skills + 20 configs.")] = True,
) -> None:
    """Measure precision, recall, F1 and false-positive rate on the benchmark corpus."""
    from ..bench.runner import THRESHOLDS, perf_check, run_bench

    if not (corpus / "manifest.yaml").is_file():
        _fail(f"no manifest.yaml under {corpus}")
    results = run_bench(corpus, split=split)
    if perf:
        results["performance"]["perf_check"] = perf_check()
    if output:
        _emit(json.dumps(results, indent=2, default=str) + "\n", output)
    con = _console()
    c = results["corpus"]
    con.print(f"[bold]Benchmark[/bold] ({split}): {c['items']} items — {c['malicious']} malicious, "
              f"{c['adversarial']} adversarial, {c['benign']} benign · sources {c['sources']}")
    t = Table(title="Overall (item level)", title_justify="left")
    for col in ("Threshold", "Precision", "Recall", "F1", "FPR", "TP", "FP", "FN", "TN"):
        t.add_column(col)
    for th in THRESHOLDS:
        m = results["overall"][th.value]
        t.add_row(f">= {th.value}", *(str(m[k]) for k in ("precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn")))
    con.print(t)
    ct = Table(title="Per category", title_justify="left")
    for col in ("Category", "Label", "Items", "@critical", "@high", "@medium", "Expected rule hit"):
        ct.add_column(col)
    for name, e in results["categories"].items():
        key = "recall" if e["label"] != "benign" else "fpr"
        ct.add_row(name, e["label"], str(e["items"]), *(f"{key} {e.get(f'{key}_{s}')}" for s in ("critical", "high", "medium")),
                   str(e.get("expected_rule_hit_rate", "")))
    con.print(ct)
    for name, tgt in results["targets"].items():
        style = "green" if tgt["met"] else "red"
        con.print(f"[{style}]{name}: actual {tgt['actual']} vs target {tgt['target']} — {'met' if tgt['met'] else 'NOT met'}[/{style}]")
    if perf:
        p = results["performance"]["perf_check"]
        con.print(f"perf: {p['skills']} skills + {p['configs']} configs in {p['seconds']}s (target < {p['target_seconds']}s)")
    if results["benign_hits_by_rule"]:
        con.print(f"benign hits (>= medium) by rule: {results['benign_hits_by_rule']}")


@app.command("report")
def report_cmd(
    input: Annotated[Path, typer.Option("--input", "-i", help="An Agent Guard JSON report.")],
    format: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.sarif,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
) -> None:
    """Re-render a JSON report as SARIF, Markdown, HTML or terminal output (no rescan)."""
    from ..core.models import Report

    try:
        report = Report.model_validate_json(input.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _fail(f"cannot read report: {exc}")
        return
    if format == OutputFormat.terminal:
        print_report(report, _console())
    elif format == OutputFormat.html:
        from ..core.report.html import render_html

        _emit(render_html(report), output)
    else:
        _emit({OutputFormat.json: render_json, OutputFormat.sarif: render_sarif,
               OutputFormat.markdown: render_markdown}[format](report), output)


@app.command("schema")
def schema_cmd(
    name: Annotated[str, typer.Argument(help="report | rule | lock | policy | config")] = "report",
) -> None:
    """Print a JSON Schema for one of Agent Guard's data formats."""
    from ..core.schemas import SCHEMAS

    if name not in SCHEMAS:
        _fail(f"unknown schema {name}; choose from {', '.join(SCHEMAS)}")
    _emit(json.dumps(SCHEMAS[name](), indent=2) + "\n", None)


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(2)


if __name__ == "__main__":
    main()
