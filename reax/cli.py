"""reax CLI: analyze, report, diff, doctor, mcp."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from reax import __version__
from reax.core import evidence as evmod
from reax.core import target as targetmod

app = typer.Typer(help="REAX — reverse engineer anything, improved.", no_args_is_help=True)
console = Console()


def _analyze(path: str) -> dict:
    if path.startswith(("http://", "https://")):
        kind = "web"
    else:
        kind = targetmod.detect(path)
    from reax.analyzers import get, supported
    fn = get(kind)
    if fn is None:
        raise typer.BadParameter(
            f"unsupported file type ({kind}). Supported: {', '.join(supported())}"
        )
    ev = evmod.new_evidence(kind, path)
    with console.status(f"[bold green]Analyzing {Path(path).name}…"):
        ev["sections"] = fn(path)
    return ev


@app.command()
def analyze(
    path: str = typer.Argument(..., help="APK, ELF, JS file/package, or URL target to analyze"),
    out: str = typer.Option("reports", "--out", "-o", help="output directory"),
    fmt: str = typer.Option("all", "--format", "-f", help="json|md|html|all"),
    json_out: bool = typer.Option(False, "--json", help="also print evidence JSON path"),
):
    """Analyze a target and write JSON + Markdown + HTML reports."""
    ev = _analyze(path)
    name = Path(path).stem
    outdir = Path(out)
    written = []
    if fmt in ("all", "json"):
        written.append(evmod.save_evidence(ev, outdir / f"{name}.reax.json"))
    if fmt in ("all", "md"):
        from reax.report import markdown as md
        p = outdir / f"{name}.md"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md.render(ev), encoding="utf-8")
        written.append(p)
    if fmt in ("all", "html"):
        from reax.report import html as htmlrep
        p = outdir / f"{name}.html"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(htmlrep.render(ev), encoding="utf-8")
        written.append(p)

    risk = ev["sections"]["risk"]
    emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(risk["grade"], "⚪")
    console.print(f"\n{emoji} [bold]{risk['grade'].upper()}[/bold] — risk score [bold]{risk['score']}/100[/bold]")
    for f in risk["findings"]:
        console.print(f"  • {f['text']}")
    if risk.get("breakdown"):
        btable = Table(show_header=False, box=None, padding=(0, 2))
        for k, v in risk["breakdown"].items():
            bar = "█" * (v // 5) + "░" * (5 - v // 5)
            btable.add_row(k.capitalize(), f"[blue]{bar}[/blue]", f"{v}/25")
        console.print()
        console.print("[dim]Score breakdown:[/dim]")
        console.print(btable)
    console.print()
    for w in written:
        console.print(f"  [green]✓[/green] {w}")
    if json_out:
        console.print(f"\nJSON: {outdir / f'{name}.reax.json'}")


@app.command()
def diff(
    old: str = typer.Argument(..., help="old APK (or its .reax.json)"),
    new: str = typer.Argument(..., help="new APK (or its .reax.json)"),
):
    """Diff two APK versions: permissions, trackers, libs, APIs, risk."""
    from reax.diff.apk_diff import diff_apk, render_markdown

    def load(p: str):
        return evmod.load_evidence(p) if p.endswith(".reax.json") else _analyze(p)

    old_ev, new_ev = load(old), load(new)
    if old_ev["target"]["kind"] != "apk" or new_ev["target"]["kind"] != "apk":
        raise typer.BadParameter("diff currently supports APK evidence only")
    d = diff_apk(old_ev, new_ev)
    console.print()
    console.print(render_markdown(d))


@app.command()
def doctor():
    """Check that REAX and its engine are ready."""
    table = Table(title="REAX doctor")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("reax", f"v{__version__} ✅")
    try:
        import androguard
        table.add_row("androguard", f"{androguard.__version__} ✅")
    except ImportError:
        table.add_row("androguard", "❌ missing — pip install androguard")
    try:
        import fastmcp  # noqa
        table.add_row("fastmcp (mcp extra)", "✅")
    except ImportError:
        table.add_row("fastmcp (mcp extra)", "not installed (pip install 'reax[mcp]')")
    from reax.analyzers import supported
    table.add_row("analyzers", ", ".join(supported()))
    console.print(table)


@app.command()
def version():
    """Print version."""
    console.print(f"reax {__version__}")


def main():
    app()


if __name__ == "__main__":
    main()
