"""Terminal rendering (Rich). All scanned text is escaped for Rich markup and
control characters are already rendered visible by the redaction layer."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..core.models import Report
from ..core.models.enums import Severity
from ..core.textutil import visible_escape

SEV_STYLE = {
    Severity.critical: "bold white on red",
    Severity.high: "bold red",
    Severity.medium: "yellow",
    Severity.low: "cyan",
    Severity.info: "dim",
}


def _e(text: str) -> str:
    return escape(visible_escape(text))


def print_report(report: Report, console: Console, *, verbose: bool = False, show_info: bool = False) -> None:
    findings = [f for f in report.findings if show_info or f.severity != Severity.info]
    comps = {c.id: c for c in report.inventory}
    console.print(f"[bold]Agent Guard[/bold] {report.engine_version} · rule pack {report.rule_pack.version}"
                  f" · {report.stats.components} components · {report.stats.files_scanned} files")
    if report.network_features_used:
        console.print(f"[yellow]Network features used:[/yellow] {', '.join(report.network_features_used)}")
    else:
        console.print("[dim]Offline scan (no network features used).[/dim]")
    for sev in Severity:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        table = Table(title=f"{sev.value.upper()} ({len(group)})", title_style=SEV_STYLE[sev], title_justify="left",
                      show_lines=False, expand=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Location", overflow="fold", max_width=48)
        table.add_column("Finding", overflow="fold")
        for f in group:
            loc = f"{f.primary.path}:{f.primary.start_line}" if f.primary else "-"
            comp = comps.get(f.component_ids[0]).name if f.component_ids and f.component_ids[0] in comps else ""
            msg = _e(f.message)
            if comp:
                msg = f"[dim]{_e(comp)}[/dim] · {msg}"
            if verbose:
                if f.evidence and f.evidence[0].snippet:
                    msg += f"\n[dim]  › {_e(str(f.evidence[0].snippet))}[/dim]"
                msg += f"\n[green]  fix:[/green] {_e(f.remediation)}"
                ids = ", ".join(m.id for m in f.mappings if m.id)
                if ids:
                    msg += f"\n[dim]  maps: {_e(ids)}[/dim]"
            conf = f" [dim]({f.confidence.value})[/dim]"
            table.add_row(f"{f.rule_id}{conf}", _e(loc), msg)
        console.print(table)
    notes = [a for a in report.analyzers if a.status != "ran" and a.reason != "not selected"]
    if notes:
        console.print("[dim]Coverage notes:[/dim]")
        for a in notes:
            console.print(f"[dim]  - {escape(a.id)}: {a.status} ({escape(a.reason)})[/dim]")
    if report.stats.suppressed:
        console.print(f"[dim]{report.stats.suppressed} finding(s) suppressed by configuration.[/dim]")
    style = "bold green" if not report.findings else "bold"
    console.print(f"[{style}]{escape(report.summary)}[/{style}]")
