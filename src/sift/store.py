"""The scan record and report files under .sift/out, shared by the CLI and the MCP server."""

import json
from pathlib import Path

from sift.dedupe import cluster, dedupe
from sift.finding import Finding, ScanResult, TriageResult
from sift.report import render_report
from sift.sarif import to_sarif, validate

OUT_DIR = Path(".sift/out")
FINDINGS_NAME = "findings.json"


def out_dir(root: Path) -> Path:
    """The output directory, refusing a repository that redirects it with a symlink."""
    for part in (root / ".sift", root / OUT_DIR):
        if part.is_symlink():
            raise ValueError(f"refusing to write through symlink {part}")
    path = root / OUT_DIR
    path.mkdir(parents=True, exist_ok=True)
    ignore = path / ".gitignore"
    if not ignore.exists():
        ignore.write_text("*\n", encoding="utf-8")
    return path


def _write(path: Path, text: str) -> Path:
    if path.is_symlink():
        path.unlink()
    path.write_text(text, encoding="utf-8")
    return path


def save_scan(result: ScanResult, root: Path) -> Path:
    return _write(out_dir(root) / FINDINGS_NAME, result.model_dump_json(indent=2))


def load_scan(path: Path) -> ScanResult:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return ScanResult(findings=[Finding.model_validate(f) for f in data])
    return ScanResult.model_validate(data)


def load_last_scan(root: Path) -> ScanResult:
    path = root / OUT_DIR / FINDINGS_NAME
    if not path.is_file():
        raise ValueError(f"no scan found at {OUT_DIR / FINDINGS_NAME}; run scan first")
    return load_scan(path)


def write_outputs(
    scan: ScanResult,
    out: Path,
    *,
    root: Path,
    triage: list[TriageResult] | None = None,
    formats: tuple[str, ...] = ("md", "sarif"),
    md_name: str = "report.md",
    tests: dict | None = None,
) -> tuple[dict[str, Path], list[str]]:
    """Render the requested formats; returns ({format: path}, SARIF validation problems)."""
    clusters = cluster(dedupe(scan.findings))
    paths: dict[str, Path] = {}
    problems: list[str] = []
    if "md" in formats:
        meta = {"mode": scan.mode, "base": scan.base, "scanned": scan.generated_at}
        text = render_report(clusters, triage, scan.tools, meta=meta, tests=tests, notes=scan.notes, root=root)
        paths["md"] = _write(out / md_name, text)
    if "sarif" in formats:
        log = to_sarif(clusters, triage, root)
        problems = validate(log)
        paths["sarif"] = _write(out / "review.sarif", json.dumps(log, indent=2))
    return paths, problems
