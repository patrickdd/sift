"""Orchestration: select targets, run adapters in parallel, scope to the diff, dedupe."""

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sift import diff
from sift.adapters import ToolAdapter, all_adapters, warn
from sift.dedupe import Cluster, cluster, dedupe
from sift.finding import Finding, ScanResult, ToolRun
from sift.normalize import to_abs, to_rel

SKIP_DIRS = {".git", ".sift", ".venv", "venv", "node_modules", "target", "build", "dist", "__pycache__"}


def find_root(cwd: Path | str = ".") -> Path:
    try:
        return diff.repo_root(cwd)
    except diff.GitError:
        return Path(cwd).resolve()


def _walk(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        out += [to_rel(Path(dirpath) / f, root) for f in filenames]
    return out


def select_targets(root: Path, *, all_mode: bool, paths: list[str] | None,
                   changed: dict[str, set[int]]) -> list[str]:
    if all_mode:
        try:
            files = diff.all_files(root)
        except diff.GitError:
            files = _walk(root)
    else:
        files = [p for p in changed if (root / p).is_file()]
    if paths:
        prefixes = [to_rel(to_abs(p, Path.cwd()), root) for p in paths]
        if not any(p in (".", root.as_posix()) for p in prefixes):
            files = [f for f in files if any(f == p or f.startswith(p.rstrip("/") + "/") for p in prefixes)]
    return sorted(f for f in files if not f.startswith(".sift/"))


def run_adapters(adapters: list[ToolAdapter], targets: list[str], root: Path
                 ) -> tuple[list[Finding], list[ToolRun]]:
    if not targets:
        return [], [ToolRun(name=a.name, version=a.version(), available=a.available()) for a in adapters]
    with ThreadPoolExecutor(max_workers=len(adapters) or 1) as pool:
        results = list(pool.map(lambda a: a.run(targets, root), adapters))
    runs = [
        ToolRun(name=a.name, version=a.version(), available=a.available(), findings=len(r),
                seconds=round(a.seconds, 2), warnings=list(a.warnings))
        for a, r in zip(adapters, results, strict=True)
    ]
    return [f for r in results for f in r], runs


def scan(root: Path, *, base: str = "main", paths: list[str] | None = None,
         all_mode: bool = False, adapters: list[ToolAdapter] | None = None
         ) -> tuple[ScanResult, list[Cluster]]:
    start = time.monotonic()
    changed: dict[str, set[int]] = {}
    try:
        changed = diff.changed_lines(base, root)
    except diff.GitError as exc:
        if not all_mode:
            raise
        warn(f"not a git repository or git failed ({exc}); in_diff will be false")
    targets = select_targets(root, all_mode=all_mode, paths=paths, changed=changed)
    findings, runs = run_adapters(adapters if adapters is not None else all_adapters(), targets, root)
    for f in findings:
        f.in_diff = diff.in_diff(changed, f.path, f.start_line, f.end_line)
    if not all_mode:
        findings = [f for f in findings if f.in_diff]
    clusters = cluster(dedupe(findings))
    result = ScanResult(
        mode="all" if all_mode else "diff",
        base=None if all_mode else base,
        seconds=round(time.monotonic() - start, 2),
        tools=runs,
        findings=[f for c in clusters for f in c.members],
    )
    return result, clusters


def hook_check(file: str, *, baseline_ref: str = "HEAD", cwd: Path | str = ".") -> dict:
    """Findings in `file` that are not present in the baseline_ref version of the file."""
    root = find_root(cwd)
    rel = to_rel(to_abs(file, Path(cwd).resolve()), root)
    adapters = [a for a in all_adapters() if a.single_file_ok and a.handles(rel)]
    current, runs = run_adapters(adapters, [rel], root)
    current = dedupe(current)

    baseline_ids: set[str] = set()
    try:
        content = diff.git(["show", f"{baseline_ref}:{rel}"], root)
    except diff.GitError:
        content = None  # new or untracked file: everything is new
    if content is not None:
        with tempfile.TemporaryDirectory(prefix="sift-baseline-") as td:
            tmp = Path(td) / Path(rel).name
            tmp.write_text(content, encoding="utf-8")
            base_findings, _ = run_adapters(adapters, [str(tmp)], root)
        for f in base_findings:
            f.path = rel
            baseline_ids.add(f.refingerprint().id)

    new = [f for f in current if f.id not in baseline_ids]
    return {
        "file": rel,
        "baseline_ref": baseline_ref,
        "new_findings": [f.model_dump() for f in new],
        "tools": [r.model_dump() for r in runs],
    }
