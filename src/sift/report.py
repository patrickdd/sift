"""Markdown report from clusters + triage verdicts.

Enforcement: a `false_positive` whose rationale cites no path:line is NOT accepted as a
dismissal; it is shown under "Needs human" with a note. Clusters without any verdict are
listed as untriaged, so nothing disappears silently.
"""

import json
import re
from pathlib import Path

from sift.adapters.base import warn
from sift.dedupe import Cluster
from sift.finding import SEVERITIES, ToolRun, TriageResult

CITATION = re.compile(r"[\w./\\-]+\.\w+:\d+")
NO_CITATION = "dismissal rejected by sift: rationale cites no path:line evidence"


def load_triage(path: Path) -> list[TriageResult]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("results", data) if isinstance(data, dict) else data
    return [TriageResult.model_validate(item) for item in items]


def resolve(clusters: list[Cluster], triage: list[TriageResult] | None) -> dict[str, TriageResult]:
    """Effective verdict per cluster id, after enforcement. Missing ids are untriaged."""
    known = {c.id for c in clusters}
    out: dict[str, TriageResult] = {}
    for t in triage or []:
        if t.id not in known:
            warn(f"triage verdict for unknown cluster id {t.id!r} ignored")
            continue
        if t.verdict == "false_positive" and not CITATION.search(t.rationale):
            t = t.model_copy(update={"verdict": "needs_human", "rationale": f"{t.rationale} ({NO_CITATION})"})
        out[t.id] = t
    return out


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _loc(c: Cluster) -> str:
    span = f"{c.start_line}" if c.start_line == c.end_line else f"{c.start_line}-{c.end_line}"
    return f"`{c.path}:{span}`"


def _item(c: Cluster, verdict: TriageResult | None) -> list[str]:
    rep = c.representative
    cwe = f" · {c.cwe}" if c.cwe else ""
    lines = [f"- **{rep.rule_id}** ({rep.rule_family}{cwe}) {_loc(c)} — {', '.join(c.tools)}",
             f"  {rep.message}"]
    if verdict:
        lines.append(f"  - *{verdict.verdict}, confidence {verdict.confidence}:* {verdict.rationale}")
        if verdict.duplicate_of:
            lines.append(f"  - duplicate of `{verdict.duplicate_of}`")
        if verdict.fix:
            lines += ["  - fix:", "", "    ```diff", *[f"    {x}" for x in verdict.fix.splitlines()], "    ```"]
    lines.append(f"  <sub>{c.id}</sub>")
    return lines


def _by_severity(clusters: list[Cluster], verdicts: dict[str, TriageResult], level: int) -> list[str]:
    out: list[str] = []
    for sev in SEVERITIES:
        group = [c for c in clusters if c.severity == sev]
        if group:
            out += [f"{'#' * level} {sev.capitalize()} ({len(group)})", ""]
            for c in group:
                out += _item(c, verdicts.get(c.id))
            out.append("")
    return out


def render_report(
    clusters: list[Cluster],
    triage: list[TriageResult] | None = None,
    tools: list[ToolRun] | None = None,
    *,
    meta: dict | None = None,
    tests: dict | None = None,
) -> str:
    verdicts = resolve(clusters, triage)
    tp = [c for c in clusters if c.id in verdicts and verdicts[c.id].verdict == "true_positive"]
    fp = [c for c in clusters if c.id in verdicts and verdicts[c.id].verdict == "false_positive"]
    nh = [c for c in clusters if c.id in verdicts and verdicts[c.id].verdict == "needs_human"]
    un = [c for c in clusters if c.id not in verdicts]
    meta = meta or {}
    tools = tools or []

    out = ["# sift review", ""]
    facts = [f"{k}: `{v}`" for k, v in meta.items() if v not in (None, "")]
    tool_secs = sum(t.seconds for t in tools)
    facts.append(f"tool time: {tool_secs:.1f}s")
    out += [" · ".join(facts), ""]
    out += ["| Clusters | Findings | True positive | Dismissed | Needs human | Untriaged |",
            "|---:|---:|---:|---:|---:|---:|",
            f"| {len(clusters)} | {sum(len(c.members) for c in clusters)} | {len(tp)} | "
            f"{len(fp)} | {len(nh)} | {len(un)} |", ""]

    if tests:
        note = f" ({tests['note']})" if tests.get("note") else ""
        out += [f"## Tests: {tests['status']}{note}", ""]
        if tests.get("tail"):
            fence = "`" * max(3, 1 + max((len(m) for m in re.findall(r"`+", tests["tail"])), default=0))
            out += ["Last 30 lines:", "", fence, tests["tail"], fence, ""]

    if tp:
        out += ["## True positives", ""] + _by_severity(tp, verdicts, 3)
    if nh:
        out += [f"## Needs human ({len(nh)})", ""] + _by_severity(nh, verdicts, 3)
    if un:
        title = "Findings (untriaged)" if triage is None else f"Untriaged ({len(un)})"
        out += [f"## {title}", ""] + _by_severity(un, verdicts, 3)
    if not clusters:
        out += ["No findings.", ""]
    out += ["<details>", f"<summary>Dismissed ({len(fp)})</summary>", ""]
    for c in fp:
        out += _item(c, verdicts[c.id])
    out += ["", "</details>", ""]

    out += ["## Tool summary", "", "| Tool | Version | Findings | Time (s) | Notes |",
            "|---|---|---:|---:|---|"]
    for t in tools:
        note = "missing" if not t.available else "; ".join(t.warnings)
        out.append(f"| {t.name} | {_cell(t.version or '-')} | {t.findings} | {t.seconds:.1f} | "
                   f"{_cell(note[:200])} |")
    return "\n".join(out).rstrip() + "\n"
