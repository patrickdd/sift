"""Turn raw tool results into Findings: family lookup, relpaths, snippets, fingerprints."""

import os
from functools import cache
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml

from sift.finding import Finding

SNIPPET_MAX_LINES = 5


def rules_dir() -> Path:
    """sift's own rules directory (the `sift.rules` package data), never the reviewed repo's.

    Resolved via importlib.resources so it works from a wheel/pipx install and from an
    editable install alike. SIFT_RULES_DIR overrides it (for rule development).
    """
    override = os.environ.get("SIFT_RULES_DIR")
    if override:
        return Path(override).resolve()
    return Path(str(files("sift.rules"))).resolve()


@cache
def load_families(path: str | None = None) -> dict[tuple[str, str], dict]:
    """Return {(tool, rule_id): {"family", "category", "cwe"}}; rule_id may be '*'."""
    file = Path(path) if path else rules_dir() / "families.yaml"
    data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    out: dict[tuple[str, str], dict] = {}
    for family, spec in (data.get("families") or {}).items():
        meta = {"family": family, "category": spec.get("category"), "cwe": spec.get("cwe")}
        for tool, rule_ids in (spec.get("members") or {}).items():
            for rule_id in rule_ids:
                out[(tool, str(rule_id))] = meta
    return out


def family_for(tool: str, rule_id: str) -> dict:
    fams = load_families()
    return fams.get((tool, rule_id)) or fams.get((tool, "*")) or {
        "family": f"{tool}:{rule_id}", "category": None, "cwe": None,
    }


@cache
def _read_lines(abs_path: str, mtime_ns: int) -> tuple[str, ...]:
    try:
        return tuple(Path(abs_path).read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return ()


def read_lines(path: Path) -> tuple[str, ...]:
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return ()
    return _read_lines(str(path), mtime)


def to_abs(raw_path: str, repo_root: Path) -> Path:
    if raw_path.startswith("file:"):
        raw_path = unquote(urlparse(raw_path).path)
    p = Path(raw_path)
    return (p if p.is_absolute() else repo_root / p).resolve()


def to_rel(abs_path: Path, repo_root: Path) -> str:
    try:
        return abs_path.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return abs_path.as_posix()  # outside the repo (e.g. a hook baseline temp file)


def make_finding(
    *,
    tool: str,
    tool_version: str,
    rule_id: str,
    message: str,
    severity: str,
    raw_path: str,
    start_line: int,
    end_line: int | None,
    repo_root: Path,
    category: str,
    cwe: str | None = None,
) -> Finding:
    abs_path = to_abs(raw_path, repo_root)
    start = max(1, int(start_line or 1))
    end = max(start, int(end_line or start))
    lines = read_lines(abs_path)
    snippet = "\n".join(lines[start - 1 : min(end, start + SNIPPET_MAX_LINES - 1)])
    fam = family_for(tool, rule_id)
    return Finding(
        tool=tool,
        tool_version=tool_version,
        rule_id=rule_id,
        rule_family=fam["family"],
        category=fam["category"] or category,
        cwe=fam["cwe"] or cwe,
        severity=severity,
        path=to_rel(abs_path, repo_root),
        start_line=start,
        end_line=end,
        snippet=snippet,
        message=" ".join(message.split()),
        tools_agreeing=[tool],
    ).refingerprint()


def downgrade(severity: str) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    return order[min(order.index(severity) + 1, len(order) - 1)]
