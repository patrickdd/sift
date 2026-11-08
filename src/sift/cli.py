"""sift command line. stdout is machine-readable; warnings and errors go to stderr."""

import argparse
import json
import sys
from pathlib import Path

from sift import __version__, diff, pipeline
from sift.adapters import all_adapters
from sift.dedupe import cluster, dedupe
from sift.finding import Finding, ScanResult
from sift.packet import build_packet
from sift.report import load_triage, render_report
from sift.sarif import to_sarif, validate


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sift", description="Deterministic tools find, the LLM triages.")
    p.add_argument("--version", action="version", version=f"sift {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="run all tools on changed code (or everything with --all)")
    s.add_argument("--base", default="main", help="base branch for diff scoping (default: main)")
    s.add_argument("--paths", nargs="+", help="restrict to these files/directories")
    s.add_argument("--format", choices=["packet", "sarif", "md", "json"], default="packet")
    s.add_argument("--all", action="store_true", help="ignore the diff and scan every file")

    h = sub.add_parser("hook-check", help="new findings in one file vs. a baseline ref")
    h.add_argument("file")
    h.add_argument("--baseline-ref", default="HEAD")

    sub.add_parser("tools", help="list detected tools and versions")

    r = sub.add_parser("report", help="render report.md + review.sarif from triage + findings")
    r.add_argument("--triage", required=True, type=Path, help="triager JSON array")
    r.add_argument("--findings", required=True, type=Path, help="output of `sift scan --format json`")
    r.add_argument("--out", type=Path, default=Path(".sift/out"))
    return p


def _emit(text: str) -> None:
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def cmd_scan(args: argparse.Namespace) -> int:
    root = pipeline.find_root()
    result, clusters = pipeline.scan(root, base=args.base, paths=args.paths, all_mode=args.all)
    if args.format == "json":
        _emit(result.model_dump_json(indent=2))
    elif args.format == "packet":
        _emit(build_packet(clusters, root))
    elif args.format == "sarif":
        _emit(json.dumps(to_sarif(clusters), indent=2))
    else:
        meta = {"mode": result.mode, "base": result.base, "elapsed": f"{result.seconds:.1f}s"}
        _emit(render_report(clusters, None, result.tools, meta=meta))
    return 0


def cmd_hook_check(args: argparse.Namespace) -> int:
    _emit(json.dumps(pipeline.hook_check(args.file, baseline_ref=args.baseline_ref), indent=2))
    return 0


def cmd_tools(_: argparse.Namespace) -> int:
    rows = [(a.name, a.version() or "-", a.binary() or "not found") for a in all_adapters()]
    width = max(len(r[0]) for r in rows)
    for name, version, binary in rows:
        _emit(f"{name:<{width}}  {version:<10}  {binary}")
    return 0


def _load_findings(path: Path) -> ScanResult:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return ScanResult(findings=[Finding.model_validate(f) for f in data])
    return ScanResult.model_validate(data)


def cmd_report(args: argparse.Namespace) -> int:
    scan = _load_findings(args.findings)
    clusters = cluster(dedupe(scan.findings))
    triage = load_triage(args.triage)
    args.out.mkdir(parents=True, exist_ok=True)
    meta = {"mode": scan.mode, "base": scan.base, "scanned": scan.generated_at}
    report_path = args.out / "report.md"
    report_path.write_text(render_report(clusters, triage, scan.tools, meta=meta), encoding="utf-8")
    log = to_sarif(clusters, triage)
    problems = validate(log)
    for problem in problems:
        print(f"sift: sarif: {problem}", file=sys.stderr)
    sarif_path = args.out / "review.sarif"
    sarif_path.write_text(json.dumps(log, indent=2), encoding="utf-8")
    _emit(json.dumps({"report": str(report_path), "sarif": str(sarif_path)}))
    return 1 if problems else 0


COMMANDS = {"scan": cmd_scan, "hook-check": cmd_hook_check, "tools": cmd_tools, "report": cmd_report}


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
