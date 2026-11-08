"""SARIF 2.1.0 export of post-triage clusters (one result per cluster).

Dismissed clusters stay in the log as suppressed results (kind "external", with the
triager's rationale as justification) so the dismissal remains auditable.
`partialFingerprints["sift/v1"]` is the representative finding's fingerprint.
"""

from sift import __version__
from sift.dedupe import Cluster
from sift.finding import TriageResult
from sift.report import resolve

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
LEVELS = {"none", "note", "warning", "error"}


def _location(path: str, start: int, end: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start, "endLine": max(start, end)},
        }
    }


def to_sarif(clusters: list[Cluster], triage: list[TriageResult] | None = None) -> dict:
    verdicts = resolve(clusters, triage)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for c in clusters:
        rep = c.representative
        rule_key = f"{rep.tool}/{rep.rule_id}"
        if rule_key not in rules:
            tags = [rep.category, *([rep.cwe] if rep.cwe else [])]
            rules[rule_key] = {
                "id": rule_key,
                "shortDescription": {"text": rep.message[:200] or rule_key},
                "properties": {"tags": tags, "rule_family": rep.rule_family},
            }
        result: dict = {
            "ruleId": rule_key,
            "ruleIndex": list(rules).index(rule_key),
            "level": LEVEL[c.severity],
            "message": {"text": rep.message or rule_key},
            "locations": [_location(c.path, rep.start_line, rep.end_line)],
            "partialFingerprints": {"sift/v1": rep.id},
            "properties": {
                "severity": c.severity,
                "rule_family": rep.rule_family,
                "tools_agreeing": c.tools,
                "cluster_id": c.id,
                **({"cwe": c.cwe} if c.cwe else {}),
            },
        }
        others = [f for f in c.members if f is not rep]
        if others:
            result["relatedLocations"] = [
                {"id": i, **_location(f.path, f.start_line, f.end_line),
                 "message": {"text": f"{f.tool}:{f.rule_id}"}}
                for i, f in enumerate(others, start=1)
            ]
        verdict = verdicts.get(c.id)
        if verdict:
            result["properties"].update(
                verdict=verdict.verdict, confidence=verdict.confidence, rationale=verdict.rationale
            )
            if verdict.verdict == "false_positive":
                result["suppressions"] = [
                    {"kind": "external", "status": "accepted", "justification": verdict.rationale}
                ]
        results.append(result)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sift",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def validate(log: dict) -> list[str]:
    """Check the SARIF 2.1.0 constraints for every property sift emits."""
    errs: list[str] = []
    if log.get("version") != "2.1.0":
        errs.append("version must be '2.1.0'")
    runs = log.get("runs")
    if not isinstance(runs, list):
        return errs + ["runs must be an array"]
    for r_i, run in enumerate(runs):
        driver = run.get("tool", {}).get("driver", {})
        if not isinstance(driver.get("name"), str) or not driver["name"]:
            errs.append(f"runs[{r_i}].tool.driver.name is required")
        rule_ids = [r.get("id") for r in driver.get("rules", [])]
        if len(rule_ids) != len(set(rule_ids)) or not all(isinstance(i, str) for i in rule_ids):
            errs.append(f"runs[{r_i}] rule ids must be unique strings")
        for i, res in enumerate(run.get("results", [])):
            where = f"runs[{r_i}].results[{i}]"
            if not isinstance(res.get("message", {}).get("text"), str):
                errs.append(f"{where}.message.text is required")
            if res.get("level") not in LEVELS:
                errs.append(f"{where}.level must be one of {sorted(LEVELS)}")
            idx = res.get("ruleIndex")
            if idx is not None and (idx >= len(rule_ids) or rule_ids[idx] != res.get("ruleId")):
                errs.append(f"{where}.ruleIndex does not point at ruleId")
            locs = res.get("locations", []) + res.get("relatedLocations", [])
            for loc in locs:
                region = loc.get("physicalLocation", {}).get("region", {})
                if region.get("startLine", 0) < 1 or region.get("endLine", 1) < region.get("startLine", 1):
                    errs.append(f"{where} has an invalid region {region}")
            if not all(isinstance(v, str) for v in res.get("partialFingerprints", {}).values()):
                errs.append(f"{where}.partialFingerprints values must be strings")
            for s in res.get("suppressions", []):
                if s.get("kind") not in {"inSource", "external"}:
                    errs.append(f"{where}.suppressions kind must be inSource or external")
    return errs
