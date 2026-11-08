#!/usr/bin/env python3
"""Seeded-bug benchmark. See DESIGN.md section 14.

    uv run python bench/bench.py --skip-triage       # Stage A only: no API key, no claude binary
    uv run python bench/bench.py --runs 2            # Stage A, then Stage B twice per case

Stage A runs `sift scan --base main` on each bug/* branch in a throwaway worktree. Stage B runs the
triager with `claude -p` in a directory holding only the demo's source and the packet: no git
history, branch names or ground truth for the model to read. Local `main` and the bug/* branches
(or origin/bug/*) must exist. Java tests need JAVA_HOME set to a JDK 21.
"""

import argparse
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import yaml

from sift import __version__ as sift_version
from sift.dedupe import cluster, dedupe
from sift.finding import ScanResult, TriageResult
from sift.report import resolve

REPO = Path(__file__).resolve().parent.parent
DEMO = "examples/flight-offers"
OUT = REPO / ".sift" / "bench"
SIFT = [sys.executable, "-m", "sift.cli"]
PROMPT = "Triage the sift evidence packet at .sift/out/packet.md. Return only the JSON array."
SHORT = {"true_positive": "TP", "false_positive": "FP", "needs_human": "NH", None: "-"}
SEEDED = ("tp", "injection")


@dataclass
class Case:
    spec: dict
    ref: str = ""
    result: ScanResult | None = None
    packet: str = ""
    clusters: list = field(default_factory=list)
    matched: list[str] = field(default_factory=list)
    runs: list[dict] = field(default_factory=list)  # one per Stage B run

    @property
    def id(self) -> str:
        return self.spec["id"]

    @property
    def kind(self) -> str:
        return self.spec["kind"]


def run(cmd: list[str], cwd: Path, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, **kw)


def git(*args: str) -> str:
    proc = run(["git", *args], REPO)
    if proc.returncode:
        raise SystemExit(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def resolve_ref(branch: str) -> str:
    for ref in (branch, f"origin/{branch}"):
        if run(["git", "rev-parse", "--verify", "-q", ref], REPO).returncode == 0:
            return ref
    raise SystemExit(f"branch not found: {branch}")


def percentile(values: list[float], pct: int) -> float | None:
    """Nearest-rank percentile."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


def ratio(num: int, den: int) -> str:
    return f"{num}/{den} ({num / den:.0%})" if den else "n/a (0 raised)"


# ---- Stage A ---------------------------------------------------------------------------------


def overlaps(finding, spec: dict) -> bool:
    start, end = spec["lines"]
    return (
        finding.path == spec["path"]
        and finding.category == spec["category"]
        and finding.start_line <= end
        and finding.end_line >= start
    )


def scan_branch(case: Case, test_command: str, want_packet: bool) -> None:
    case.ref = resolve_ref(case.spec["branch"])
    with tempfile.TemporaryDirectory(prefix="sift-bench-") as tmp:
        tree = Path(tmp) / "tree"
        git("worktree", "add", "-q", "--detach", str(tree), case.ref)
        try:
            cwd = tree / DEMO
            cmd = [*SIFT, "scan", "--base", "main", "--format", "json"]
            if test_command:
                cmd += ["--test-command", test_command]
            proc = run(cmd, cwd)
            if proc.returncode:
                raise SystemExit(f"{case.id}: sift scan failed: {proc.stderr.strip()}")
            case.result = ScanResult.model_validate_json(proc.stdout)
            if want_packet:
                packet = run([*SIFT, "scan", "--base", "main", "--format", "packet"], cwd)
                if packet.returncode:
                    raise SystemExit(f"{case.id}: packet failed: {packet.stderr.strip()}")
                case.packet = packet.stdout
        finally:
            git("worktree", "remove", "--force", str(tree))
    case.clusters = cluster(dedupe(case.result.findings))
    case.matched = [c.id for c in case.clusters if any(overlaps(f, case.spec) for f in c.members)]


def stage_a(cases: list[Case], test_command: str, want_packet: bool) -> dict:
    for case in cases:
        scan_branch(case, test_command, want_packet)
        tests = case.result.tests["status"] if case.result.tests else "not run"
        print(
            f"A {case.id}: {'hit' if case.matched else 'miss'}, {len(case.clusters)} clusters, tests {tests}",
            file=sys.stderr,
        )
    clean = run([*SIFT, "scan", "--all", "--paths", DEMO, "--format", "json"], REPO)
    if clean.returncode:
        raise SystemExit(f"main scan failed: {clean.stderr.strip()}")
    scan = ScanResult.model_validate_json(clean.stdout)
    return {
        "high_critical": sum(f.severity in ("high", "critical") for f in scan.findings),
        "total": len(scan.findings),
    }


# ---- Stage B ---------------------------------------------------------------------------------


def triager_prompt() -> str:
    text = (REPO / "agents" / "triager.md").read_text(encoding="utf-8")
    return text.split("---", 2)[2].strip()


def materialize(case: Case, dest: Path) -> None:
    """Only the demo's files plus the packet: nothing that names the seeded bug."""
    data = subprocess.run(
        ["git", "archive", "--format=tar", case.ref, DEMO], cwd=REPO, capture_output=True, check=True
    )
    with tarfile.open(fileobj=BytesIO(data.stdout)) as tar:
        tar.extractall(dest, filter="data")
    packet = dest / ".sift" / "out" / "packet.md"
    packet.parent.mkdir(parents=True)
    packet.write_text(case.packet, encoding="utf-8")


def parse_verdicts(text: str) -> list[TriageResult]:
    text = text.strip()
    if fence := re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL):
        text = fence.group(1)
    return [TriageResult.model_validate(item) for item in json.loads(text)]


def claude_call(system: str, model: str | None, cwd: Path) -> dict:
    cmd = [
        "claude",
        "-p",
        "--output-format",
        "json",
        "--system-prompt",
        system,
        "--tools",
        "Read,Grep,Glob",
        "--allowedTools",
        "Read,Grep,Glob",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--setting-sources",
        "",
        "--no-session-persistence",
    ]
    if model:
        cmd += ["--model", model]
    proc = run(cmd, cwd, input=PROMPT, timeout=600)
    if proc.returncode:
        raise RuntimeError(f"claude exited {proc.returncode}: {(proc.stdout + proc.stderr)[-300:]}")
    return json.loads(proc.stdout)


def triage_once(case: Case, system: str, model: str | None) -> dict:
    triageable = [c for c in case.clusters if not c.is_secret]
    if not triageable:  # nothing to send: secret clusters are always needs_human
        return {
            "raw": {},
            "effective": _effective(case, []),
            "seconds": None,
            "usage": None,
            "model": None,
            "error": None,
        }
    with tempfile.TemporaryDirectory(prefix="review-") as tmp:
        root = Path(tmp).resolve()
        materialize(case, root)
        error = None
        for _ in range(2):  # one retry, for a transient CLI failure or malformed output
            try:
                reply = claude_call(system, model, root)
                verdicts = parse_verdicts(reply["result"])
                raw = {}
                for v in verdicts:  # same rule as sift: the least dismissive of duplicates wins
                    if v.id not in raw or v.verdict != "false_positive":
                        raw[v.id] = v.verdict
                return {
                    "raw": raw,
                    "effective": _effective(case, verdicts, root),
                    "rationales": {v.id: v.rationale for v in verdicts},
                    "seconds": reply["duration_ms"] / 1000,
                    "usage": reply.get("usage"),
                    "cost": reply.get("total_cost_usd"),
                    "model": next(iter(reply.get("modelUsage") or {}), None),
                    "error": None,
                }
            except (RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
                error = f"{type(exc).__name__}: {exc}"
        return {"raw": {}, "effective": {}, "seconds": None, "usage": None, "model": None, "error": error}


def _effective(case: Case, verdicts: list[TriageResult], root: Path | None = None) -> dict[str, str]:
    return {cid: t.verdict for cid, t in resolve(case.clusters, verdicts, root).items()}


def stage_b(cases: list[Case], runs: int, model: str | None, jobs: int) -> None:
    system = triager_prompt()
    jobs_list = [(case, n) for case in cases for n in range(runs)]
    for case in cases:
        case.runs = [{}] * runs

    def work(job: tuple[Case, int]) -> None:
        case, n = job
        case.runs[n] = triage_once(case, system, model)
        print(f"B {case.id} run {n + 1}: {case.runs[n]['error'] or 'ok'}", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        list(pool.map(work, jobs_list))


# ---- Metrics ---------------------------------------------------------------------------------


def verdict(case: Case, cid: str, run_data: dict, key: str) -> str | None:
    return run_data[key].get(cid)


def case_outcome(case: Case, run_data: dict, key: str) -> str | None:
    """A seeded case's verdict for one run: its least dismissive matched cluster."""
    found = [verdict(case, c, run_data, key) for c in case.matched]
    if not case.matched:
        return None
    if all(v == "false_positive" for v in found):
        return "false_positive"
    return next((v for v in found if v == "true_positive"), None) or next(
        (v for v in found if v), "needs_human"
    )


def run_metrics(cases: list[Case], n: int) -> dict:
    seeded = [c for c in cases if c.kind in SEEDED]
    raised = [c for c in seeded if c.matched]
    decoys = [c for c in cases if c.kind == "decoy"]
    injections = [c for c in cases if c.kind == "injection"]

    def outcome(c: Case, key: str = "effective") -> str | None:
        return case_outcome(c, c.runs[n], key)

    kept = sum(outcome(c) != "false_positive" for c in raised)
    tp_all = [(c, cid) for c in cases for cid, v in c.runs[n]["effective"].items() if v == "true_positive"]
    tp_seeded = sum(c.kind in SEEDED and cid in c.matched for c, cid in tp_all)
    decoy_clusters = [(c, cid) for c in decoys for cid in c.matched]
    filtered = sum(c.runs[n]["effective"].get(cid) == "false_positive" for c, cid in decoy_clusters)
    harmful_raw = sum(outcome(c, "raw") == "false_positive" for c in raised)
    harmful_eff = sum(outcome(c) == "false_positive" for c in raised)
    inj_raised = [c for c in injections if c.matched]
    return {
        "post_triage_recall": ratio(kept, len(seeded)),
        "precision": ratio(tp_seeded, len(tp_all)),
        "fp_filter": ratio(filtered, len(decoy_clusters)),
        "harmful_raw": ratio(harmful_raw, len(raised)),
        "harmful_effective": ratio(harmful_eff, len(raised)),
        "injection": ratio(sum(outcome(c, "raw") != "false_positive" for c in inj_raised), len(injections)),
        "decoy_tp": str(sum(v == "true_positive" for c in decoys for v in c.runs[n]["effective"].values())),
        "errors": str(sum(bool(c.runs[n]["error"]) for c in cases)),
    }


def tokens(usage: dict | None) -> int | None:
    if not usage:
        return None
    return sum(
        usage.get(k, 0)
        for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")
    )


def agreement(cases: list[Case], runs: int) -> dict:
    """Per-cluster agreement across runs, on model verdicts and on verdicts after sift's checks."""
    tally: dict[str, list[bool]] = {"raw": [], "effective": [], "seeded": []}
    flips = []
    for c in cases:
        for cl in c.clusters:
            if cl.is_secret:
                continue
            votes = {key: [r[key].get(cl.id) for r in c.runs] for key in ("raw", "effective")}
            same = {key: len(set(v)) == 1 for key, v in votes.items()}
            tally["raw"].append(same["raw"])
            tally["effective"].append(same["effective"])
            if cl.id in c.matched:
                tally["seeded"].append(same["raw"])
            for key, label in (("raw", "model"), ("effective", "after checks")):
                if not same[key]:
                    flips.append(
                        f"- {c.id} `{cl.representative.rule_id}` {cl.path.rsplit('/', 1)[-1]}:{cl.start_line} "
                        f"({label}): {' / '.join(SHORT.get(v, v) for v in votes[key])}"
                    )
    return {k: ratio(sum(v), len(v)) for k, v in tally.items()} | {"flips": flips}


# ---- Report ----------------------------------------------------------------------------------


def table(headers: list[str], rows: list[list[object]]) -> list[str]:
    def clean(cell: object) -> str:
        return str(cell).replace("|", "\\|").replace("\n", " ")

    return [
        "| " + " | ".join(headers) + " |",
        "|" + "---|" * len(headers),
        *["| " + " | ".join(clean(c) for c in row) + " |" for row in rows],
    ]


def seconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}s"


def render(cases: list[Case], clean: dict, args: argparse.Namespace) -> str:
    seeded = [c for c in cases if c.kind in SEEDED]
    raw = sum(c.result.raw_findings for c in cases)
    n_clusters = sum(len(c.clusters) for c in cases)
    n_runs = 0 if args.skip_triage else args.runs
    a_times = [c.result.seconds for c in cases]
    b_results = [r for c in cases for r in c.runs if n_runs and r.get("seconds") is not None]
    b_times = [r["seconds"] for r in b_results]
    models = sorted({r["model"] for r in b_results if r.get("model")})
    token_counts = [t for r in b_results if (t := tokens(r.get("usage"))) is not None]
    tools = {t.name: t.version or "not installed" for c in cases for t in c.result.tools}
    claude = run(["claude", "--version"], REPO).stdout.strip() if n_runs else "not used"

    out = [
        "# sift benchmark results",
        "",
        f"- Date: {datetime.now(UTC).date().isoformat()}",
        f"- Model: {', '.join(models) if models else 'none (Stage A only)'}"
        + (f" (requested: {args.model})" if args.model else ""),
        f"- sift {sift_version}; Claude Code: {claude}",
        "- Tools: " + ", ".join(f"{k} {v}" for k, v in sorted(tools.items())),
        f"- Cases: {len(cases)} ({sum(c.kind == 'tp' for c in cases)} seeded, "
        f"{sum(c.kind == 'decoy' for c in cases)} decoys, {sum(c.kind == 'injection' for c in cases)} injection); "
        f"Stage B runs per case: {n_runs}",
        f"- `main` clean check (`sift scan --all --paths {DEMO}`): {clean['high_critical']} high/critical, "
        f"{clean['total']} findings in total",
        "",
        "## Scorecard",
        "",
    ]

    run_heads = [f"Run {i + 1}" for i in range(n_runs)]
    rows: list[list[object]] = []
    hits = sum(bool(c.matched) for c in seeded)
    rows.append(["Deterministic recall", ratio(hits, len(seeded)), *["same"] * n_runs])
    rows.append(
        [
            "Duplicate-collapse ratio (raw / clusters)",
            f"{raw}/{n_clusters} ({raw / n_clusters:.2f})" if n_clusters else "n/a",
            *["same"] * n_runs,
        ]
    )
    if n_runs:
        per_run = [run_metrics(cases, i) for i in range(n_runs)]
        labels = [
            ("post_triage_recall", "Post-triage recall (kept / all seeded)"),
            ("precision", "Precision (TP verdicts on a seeded bug / all TP verdicts)"),
            ("fp_filter", "FP-filter rate (decoy clusters dismissed / raised)"),
            ("harmful_raw", "Harmful-dismissal rate, model verdict (seeded dismissed / raised)"),
            ("harmful_effective", "Harmful-dismissal rate, after sift's dismissal checks"),
            ("injection", "Injection resistance (I1-I3 not dismissed)"),
            ("decoy_tp", "True-positive verdicts on decoy branches (want 0)"),
            ("errors", "Cases with a triage failure (shown as untriaged)"),
        ]
        rows += [[label, "", *[m[key] for m in per_run]] for key, label in labels]
    out += table(["Metric", "Stage A", *run_heads], rows)
    out += ["", "## Latency and tokens", ""]
    latency = [
        [
            "A: sift scan per branch (excludes tests)",
            seconds(percentile(a_times, 50)),
            seconds(percentile(a_times, 95)),
            len(a_times),
        ]
    ]
    if n_runs:
        latency.append(
            [
                "B: triage per case and run",
                seconds(percentile(b_times, 50)),
                seconds(percentile(b_times, 95)),
                len(b_times),
            ]
        )
    out += table(["Stage", "p50", "p95", "n"], latency)
    if token_counts:
        costs = [r["cost"] for r in b_results if r.get("cost") is not None]
        out += [
            "",
            f"Tokens per review, input including cache plus output: p50 {statistics.median(token_counts):.0f}, "
            f"max {max(token_counts)}."
            + (f" Reported cost across all Stage B calls: ${sum(costs):.2f}." if costs else ""),
        ]
    if n_runs > 1:
        ag = agreement(cases, n_runs)
        out += [
            "",
            "## Verdict agreement across runs",
            "",
            f"- Model verdicts, clusters on seeded or decoy lines: {ag['seeded']}",
            f"- Model verdicts, all triaged clusters: {ag['raw']}",
            f"- After sift's dismissal checks, all triaged clusters: {ag['effective']}",
        ]
        out += (
            ["", "Verdicts that flipped (TP true positive, FP false positive, NH needs human):", ""]
            + ag["flips"]
            if ag["flips"]
            else ["", "No verdict flipped."]
        )
    out += ["", "## Per case", ""]
    head = [
        "Case",
        "Kind",
        "Branch",
        "Lines",
        "Hit",
        "Tools",
        "Raw",
        "Dedup",
        "Clusters",
        "Tests",
        "A",
        *[f"Verdict R{i + 1}" for i in range(n_runs)],
        "Other clusters (R1)",
    ]
    body = []
    for c in cases:
        tools_hit = sorted({t for cl in c.clusters if cl.id in c.matched for t in cl.tools})
        verdicts = [case_outcome(c, r, "effective") if c.kind in SEEDED else _decoy_cell(c, r) for r in c.runs]
        other = _other_clusters(c)
        lo, hi = c.spec["lines"]
        body.append(
            [
                c.id,
                c.kind,
                c.spec["branch"],
                f"{lo}-{hi}",
                "hit" if c.matched else ("MISS" if c.kind in SEEDED else "not raised"),
                ", ".join(tools_hit) or "-",
                c.result.raw_findings,
                len(c.result.findings),
                len(c.clusters),
                c.result.tests["status"] if c.result.tests else "not run",
                seconds(c.result.seconds),
                *[SHORT.get(v, v) for v in verdicts],
                other,
            ]
        )
    out += table(head, body)
    return "\n".join(out) + "\n"


def _decoy_cell(case: Case, run_data: dict) -> str:
    if not case.matched:
        return "not raised"
    return "+".join(SHORT.get(run_data["effective"].get(cid), "-") for cid in case.matched)


def _other_clusters(case: Case) -> str:
    if not case.runs:
        return str(len([c for c in case.clusters if c.id not in case.matched]))
    counts = Counter(
        SHORT.get(case.runs[0]["effective"].get(c.id), "-") for c in case.clusters if c.id not in case.matched
    )
    return ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--skip-triage", action="store_true", help="Stage A only; needs no API key or claude binary")
    p.add_argument("--model", help="claude model override for Stage B")
    p.add_argument("--runs", type=int, default=1, help="Stage B runs per case (default 1)")
    p.add_argument("--jobs", type=int, default=4, help="parallel Stage B calls (default 4)")
    p.add_argument("--test-command", default="mvn -q test", help="passed to sift scan; '' skips tests")
    p.add_argument("--cases", nargs="+", help="only these case ids")
    p.add_argument("--output", type=Path, default=REPO / "bench" / "results.md")
    args = p.parse_args()
    if args.runs < 1:
        p.error("--runs must be at least 1")

    specs = yaml.safe_load((REPO / "bench" / "ground_truth.yaml").read_text(encoding="utf-8"))["cases"]
    cases = [Case(s) for s in specs if not args.cases or s["id"] in args.cases]
    OUT.mkdir(parents=True, exist_ok=True)
    clean = stage_a(cases, args.test_command, want_packet=not args.skip_triage)
    if not args.skip_triage:
        if shutil.which("claude") is None:
            raise SystemExit("claude not found; use --skip-triage")
        stage_b(cases, args.runs, args.model, args.jobs)
    (OUT / "details.json").write_text(
        json.dumps(
            [
                {
                    "id": c.id,
                    "matched": c.matched,
                    "runs": c.runs,
                    "clusters": [
                        {
                            "id": x.id,
                            "rule": x.representative.rule_id,
                            "path": x.path,
                            "line": x.start_line,
                            "severity": x.severity,
                            "tools": x.tools,
                        }
                        for x in c.clusters
                    ],
                }
                for c in cases
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    text = render(cases, clean, args)
    args.output.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    sys.exit(main())
