"""REAX MCP server: use REAX from any MCP-capable agent."""

from __future__ import annotations


def build_server():
    try:
        from fastmcp import FastMCP
    except ImportError as e:
        raise SystemExit("fastmcp not installed — run: pip install 'reax[mcp]'") from e

    from reax.analyzers import get as get_analyzer
    from reax.core import evidence as evmod
    from reax.core import target as targetmod
    from reax.diff.apk_diff import diff_apk, render_markdown

    mcp = FastMCP("reax")

    @mcp.tool()
    def analyze(path: str) -> dict:
        """Reverse-engineer a target (APK today). Returns the full evidence JSON:
        identity, permission risks, trackers, suspicious APIs, network indicators, risk verdict."""
        kind = targetmod.detect(path)
        fn = get_analyzer(kind)
        if fn is None:
            return {"error": f"unsupported file type: {kind}"}
        ev = evmod.new_evidence(kind, path)
        ev["sections"] = fn(path)
        return ev

    @mcp.tool()
    def diff_apks(old_path: str, new_path: str) -> str:
        """Diff two APK versions. Returns a Markdown report of what changed:
        permissions, trackers, native libs, suspicious APIs, risk delta."""
        def load(p: str):
            if p.endswith(".reax.json"):
                return evmod.load_evidence(p)
            kind = targetmod.detect(p)
            ev = evmod.new_evidence(kind, p)
            ev["sections"] = get_analyzer(kind)(p)
            return ev
        return render_markdown(diff_apk(load(old_path), load(new_path)))

    @mcp.tool()
    def risk_summary(path: str) -> dict:
        """Quick risk verdict for an APK without the full evidence dump."""
        kind = targetmod.detect(path)
        fn = get_analyzer(kind)
        if fn is None:
            return {"error": f"unsupported file type: {kind}"}
        sections = fn(path)
        ident = sections["identity"]
        return {
            "package": ident.get("package"),
            "version": ident.get("version_name"),
            "risk": sections["risk"],
            "trackers": sections["trackers"]["items"],
        }

    return mcp


def main():
    build_server().run()


if __name__ == "__main__":
    main()
