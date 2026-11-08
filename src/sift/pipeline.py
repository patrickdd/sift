"""Orchestration: select targets, run adapters in parallel, scope to the diff, dedupe."""

import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sift import diff
from sift.adapters import ToolAdapter, all_adapters, warn
from sift.config import validate_base
from sift.dedupe import Cluster, cluster, dedupe
from sift.finding import Finding, ScanResult, ToolRun
from sift.normalize import mask_snippets, secret_line_map, to_abs, to_rel

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
    return sorted(f for f in files if ".sift" not in Path(f).parts)


def run_adapters(adapters: list[ToolAdapter], targets: list[str], root: Path
                 ) -> tuple[list[Finding], list[ToolRun]]:
    if not targets:
        return [], [ToolRun(name=a.name, version=a.version(), available=a.available(), ran=False)
                    for a in adapters]
    with ThreadPoolExecutor(max_workers=len(adapters) or 1) as pool:
        results = list(pool.map(lambda a: a.run(targets, root), adapters))
    runs = [
        ToolRun(name=a.name, version=a.version(), available=a.available(), findings=len(r),
                seconds=round(a.seconds, 2), warnings=list(a.warnings),
                ran=any(a.handles(t) for t in targets))
        for a, r in zip(adapters, results, strict=True)
    ]
    findings = [f for r in results for f in r]
    mask_snippets(findings, secret_line_map(findings))
    return findings, runs


def no_tool_completed(runs: list[ToolRun]) -> bool:
    """True when tools were due to run and not one of them finished cleanly."""
    due = [t for t in runs if t.ran]
    return bool(due) and not any(t.available and not t.warnings for t in due)


def tool_inventory() -> list[dict]:
    return [
        {"name": a.name, "version": a.version(), "binary": a.binary(), "available": a.available()}
        for a in all_adapters()
    ]


def scan(root: Path, *, base: str = "main", paths: list[str] | None = None,
         all_mode: bool = False, adapters: list[ToolAdapter] | None = None
         ) -> tuple[ScanResult, list[Cluster]]:
    validate_base(base)
    start = time.monotonic()
    notes: list[str] = []
    changed: dict[str, set[int]] = {}
    try:
        changed = diff.changed_lines(base, root)
    except diff.GitError as exc:
        if not all_mode:
            raise
        warn(f"not a git repository or git failed ({exc}); in_diff will be false")
    if not all_mode and not diff.base_exists(base, root):
        notes.append(f"base `{base}` was not found, so only changes against HEAD were scanned; "
                     "committed branch work was not reviewed.")
    targets = select_targets(root, all_mode=all_mode, paths=paths, changed=changed)
    links = [t for t in targets if (root / t).is_symlink()]
    if links:  # Semgrep aborts on them, and the others would read outside the repo
        targets = [t for t in targets if t not in links]
        notes.append(f"{len(links)} symlinked file(s) were not scanned: {', '.join(links[:10])}")
        warn(notes[-1])
    findings, runs = run_adapters(adapters if adapters is not None else all_adapters(), targets, root)
    secret_lines = secret_line_map(findings)  # before the diff filter: context can show old lines
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
        notes=notes,
        secret_lines=secret_lines,
    )
    return result, clusters


def hook_check(file: str, *, baseline_ref: str = "HEAD", cwd: Path | str = ".") -> dict:
    """Findings in `file` that are not present in the baseline_ref version of the file."""
    root = find_root(cwd)
    rel = to_rel(to_abs(file, Path(cwd).resolve()), root)
    adapters = [a for a in all_adapters() if a.single_file_ok and a.handles(rel)]
    current, runs = run_adapters(adapters, [rel], root)
    current = dedupe(current)

    base_findings: list[Finding] = []
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
            f.refingerprint()
    # Deduped like `current`, so a second copy of a line that exists at HEAD still counts as new.
    baseline_ids = {f.id for f in dedupe(base_findings)}

    new = [f for f in current if f.id not in baseline_ids]
    return {
        "file": rel,
        "baseline_ref": baseline_ref,
        "new_findings": [f.model_dump() for f in new],
        "tools": [r.model_dump() for r in runs],
    }
