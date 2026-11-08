"""sift command line. stdout is machine-readable; warnings and errors go to stderr."""

import argparse
import json
import sys
from pathlib import Path

from sift import __version__, config, diff, pipeline, store
from sift.packet import build_packet
from sift.report import load_triage, render_report
from sift.sarif import to_sarif


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sift", description="Deterministic tools find, the LLM triages.")
    p.add_argument("--version", action="version", version=f"sift {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run all tools on changed code (or everything with --all)")
    s.add_argument("--base", default="main", help="base branch for diff scoping (default: main)")
    s.add_argument("--paths", nargs="+", help="restrict to these files/directories")
    s.add_argument("--format", choices=["packet", "sarif", "md", "json"], default="packet")
    s.add_argument("--all", action="store_true", help="ignore the diff and scan every file")
    s.add_argument("--output", type=Path, help="write to this file instead of stdout")

    h = sub.add_parser("hook-check", help="new findings in one file vs. a baseline ref")
    h.add_argument("file")
    h.add_argument("--baseline-ref", default="HEAD")

    sub.add_parser("tools", help="list detected tools and versions")

    sub.add_parser("mcp", help="run the MCP server over stdio")

    c = sub.add_parser("config", help="resolve validated review settings from .sift.toml")
    c.add_argument("--base", help="base branch given by the user; wins over .sift.toml")

    r = sub.add_parser("report", help="render report.md + review.sarif from triage + findings")
    r.add_argument("--triage", required=True, type=Path, help="triager JSON array")
    r.add_argument("--findings", required=True, type=Path, help="output of `sift scan --format json`")
    r.add_argument("--out", type=Path, default=Path(".sift/out"))
    r.add_argument("--md-name", default="report.md", help="file name of the Markdown report")
    r.add_argument("--test-status", choices=["passed", "failed", "skipped"], help="test command result")
    r.add_argument("--test-note", help="reason shown beside a skipped status")
    r.add_argument("--test-output", type=Path, help="test log; its tail is shown on failure")
    return p


def _emit(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def cmd_scan(args: argparse.Namespace) -> int:
    root = pipeline.find_root()
    result, clusters = pipeline.scan(root, base=args.base, paths=args.paths, all_mode=args.all)
    if args.format == "json":
        text = result.model_dump_json(indent=2)
    elif args.format == "packet":
        text = build_packet(clusters, root, secret_lines=result.secret_lines)
    elif args.format == "sarif":
        text = json.dumps(to_sarif(clusters, root=root), indent=2)
    else:
        meta = {"mode": result.mode, "base": result.base, "elapsed": f"{result.seconds:.1f}s"}
        text = render_report(clusters, None, result.tools, meta=meta, notes=result.notes, root=root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    else:
        _emit(text)
    if pipeline.no_tool_completed(result.tools):
        print("sift: error: no analysis tool completed; this scan is not evidence of anything", file=sys.stderr)
        return 1
    return 0


def cmd_hook_check(args: argparse.Namespace) -> int:
    _emit(json.dumps(pipeline.hook_check(args.file, baseline_ref=args.baseline_ref), indent=2))
    return 0


def cmd_tools(_: argparse.Namespace) -> int:
    rows = [(t["name"], t["version"] or "-", t["binary"] or "not found") for t in pipeline.tool_inventory()]
    width = max(len(r[0]) for r in rows)
    for name, version, binary in rows:
        _emit(f"{name:<{width}}  {version:<10}  {binary}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    _emit(json.dumps(config.resolve_config(pipeline.find_root(), args.base)))
    return 0


def cmd_mcp(_: argparse.Namespace) -> int:
    from sift.mcp_server import main as serve  # imported here so other commands skip the MCP SDK's startup cost

    serve()
    return 0


def _test_result(args: argparse.Namespace) -> dict | None:
    if not args.test_status:
        return None
    tail = ""
    if args.test_status == "failed" and args.test_output and args.test_output.is_file():
        tail = "\n".join(args.test_output.read_text(encoding="utf-8", errors="replace").splitlines()[-30:])
    note = args.test_note or ("no test_command configured" if args.test_status == "skipped" else None)
    return {"status": args.test_status, "tail": tail, "note": note}


def cmd_report(args: argparse.Namespace) -> int:
    triage = load_triage(args.triage)
    args.out.mkdir(parents=True, exist_ok=True)
    paths, problems = store.write_outputs(
        store.load_scan(args.findings), args.out, root=pipeline.find_root(), triage=triage,
        md_name=args.md_name, tests=_test_result(args),
    )
    for problem in problems:
        print(f"sift: sarif: {problem}", file=sys.stderr)
    _emit(json.dumps({"report": str(paths["md"]), "sarif": str(paths["sarif"])}))
    return 1 if problems else 0


COMMANDS = {
    "scan": cmd_scan, "hook-check": cmd_hook_check, "tools": cmd_tools,
    "config": cmd_config, "report": cmd_report, "mcp": cmd_mcp,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except diff.GitError as exc:
        print(f"sift: error: git: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"sift: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
