"""Turn raw tool results into Findings: family lookup, relpaths, snippets, fingerprints."""

import hashlib
import os
import re
from collections.abc import Iterable, Mapping
from functools import cache
from importlib.resources import files
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml

from sift.finding import Finding, normalize_code_line

SNIPPET_MAX_LINES = 5
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


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
        data = Path(abs_path).read_bytes().decode("utf-8", "replace")
    except OSError:
        return ()
    # Split on \n only, as the tools count lines: a form feed or U+2028 must not shift numbers,
    # or redaction would mask the wrong line.
    lines = [line.removesuffix("\r") for line in data.split("\n")]
    return tuple(lines[:-1] if lines and lines[-1] == "" else lines)


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


def redact_line(line: str, path: str) -> str:
    """Stand-in for a secret-bearing line. The digest keeps fingerprints distinct and stable."""
    key = normalize_code_line(line, path) or line.strip()
    return f"[secret redacted by sift: {hashlib.sha256(key.encode()).hexdigest()[:12]}]"


def mask_lines(lines: Iterable[str], first: int, hidden: Iterable[int], path: str) -> list[str]:
    """Replace the lines whose 1-based number (counting from `first`) is in `hidden`."""
    secret = set(hidden)
    return [redact_line(t, path) if n in secret else t for n, t in enumerate(lines, start=first)]


def secret_line_map(findings: Iterable[Finding]) -> dict[str, list[int]]:
    """Every line any tool flagged as a secret, by path."""
    out: dict[str, set[int]] = {}
    for f in findings:
        if f.category == "secret":
            out.setdefault(f.path, set()).update(range(f.start_line, f.end_line + 1))
    return {path: sorted(lines) for path, lines in out.items()}


def mask_snippets(findings: Iterable[Finding], secrets: Mapping[str, list[int]]) -> None:
    """Mask secret lines inside the snippets of findings from other rules."""
    for f in findings:
        hidden = set(secrets.get(f.path, ()))
        if hidden & set(range(f.start_line, f.end_line + 1)) and f.category != "secret":
            f.snippet = "\n".join(mask_lines(f.snippet.split("\n"), f.start_line, hidden, f.path))
            f.refingerprint()


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
    shown = lines[start - 1 : min(end, start + SNIPPET_MAX_LINES - 1)]
    fam = family_for(tool, rule_id)
    final_category = fam["category"] or category
    if final_category == "secret":
        # Bandit B105 quotes the value in its message, and the snippet is the source line itself.
        shown = [redact_line(line, raw_path) for line in shown]
        message = _QUOTED.sub("[redacted]", message)
    snippet = "\n".join(shown)
    return Finding(
        tool=tool,
        tool_version=tool_version,
        rule_id=rule_id,
        rule_family=fam["family"],
        category=final_category,
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
