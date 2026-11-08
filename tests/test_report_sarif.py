from conftest import make

from sift.dedupe import cluster, dedupe
from sift.finding import ToolRun, TriageResult
from sift.report import render_report
from sift.sarif import to_sarif, validate


def _clusters():
    return cluster(dedupe([
        make(path="a.py", start_line=3, end_line=3, snippet="tp", severity="high", rule_id="S608"),
        make(path="a.py", start_line=9, end_line=9, snippet="fp", severity="critical", rule_family="f2"),
        make(path="b.py", start_line=1, end_line=1, snippet="nh", severity="low", rule_family="f3"),
        make(path="c.py", start_line=1, end_line=1, snippet="un", severity="info", rule_family="f4"),
    ]))


def _triage(clusters):
    by = {c.members[0].snippet: c.id for c in clusters}
    return [
        TriageResult(id=by["tp"], verdict="true_positive", confidence=90,
                     rationale="input reaches execute at a.py:3", fix="-a\n+b"),
        TriageResult(id=by["fp"], verdict="false_positive", confidence=85,
                     rationale="value is the constant TABLE defined at a.py:1"),
        TriageResult(id=by["nh"], verdict="needs_human", confidence=40, rationale="unclear, b.py:1"),
    ]


def test_report_sections_and_counts():
    clusters = _clusters()
    md = render_report(clusters, _triage(clusters), [ToolRun(name="ruff", version="0.1", findings=2,
                                                           seconds=0.4)], meta={"base": "main"})
    assert "| 4 | 4 | 1 | 1 | 1 | 1 |" in md
    assert "## True positives" in md and "### High (1)" in md
    assert "<summary>Dismissed (1)</summary>" in md and "constant TABLE defined at a.py:1" in md
    assert "## Needs human (1)" in md and "## Untriaged (1)" in md
    assert "| ruff | 0.1 | 2 | 0.4 |" in md
    assert "```diff" in md


def test_sarif_structure_and_suppressions():
    clusters = _clusters()
    log = to_sarif(clusters, _triage(clusters))
    assert validate(log) == []
    results = log["runs"][0]["results"]
    assert len(results) == 4
    suppressed = [r for r in results if "suppressions" in r]
    assert len(suppressed) == 1 and suppressed[0]["suppressions"][0]["kind"] == "external"
    assert {r["level"] for r in results} == {"error", "note"}
    assert all(len(r["partialFingerprints"]["sift/v1"]) == 64 for r in results)
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%" and loc["region"]["startLine"] >= 1


def test_validate_catches_bad_logs():
    assert validate({"version": "2.0", "runs": []}) == ["version must be '2.1.0'"]
    bad = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}},
                                          "results": [{"level": "fatal", "message": {}}]}]}
    assert len(validate(bad)) == 2
