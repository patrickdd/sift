"""Semgrep / Opengrep adapter. Runs ONLY sift's own MIT rules from rules/<lang>/.

Severity: ERROR -> high, WARNING -> medium, INFO -> low.
`check_id` is prefixed with a dotted form of the config path, so the real rule id is
recovered by matching against the ids declared in sift's rule files.
"""

import json
from functools import cache
from pathlib import Path

import yaml

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import make_finding, rules_dir

LANG_DIRS = {".java": "java", ".py": "python"}
SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


@cache
def known_rule_ids(root: str) -> frozenset[str]:
    ids: set[str] = set()
    for f in Path(root).glob("*/*.y*ml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        ids.update(r["id"] for r in doc.get("rules", []) if "id" in r)
    return frozenset(ids)


def strip_check_id(check_id: str, known: frozenset[str]) -> str:
    for rule_id in sorted(known, key=len, reverse=True):
        if check_id == rule_id or check_id.endswith("." + rule_id):
            return rule_id
    return check_id


class SemgrepAdapter(ToolAdapter):
    name = "semgrep"
    binaries = ("opengrep", "semgrep")  # prefer the LGPL fork when present
    languages = tuple(LANG_DIRS)
    single_file_ok = False  # not part of Tier 1 (startup cost)

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        langs = {LANG_DIRS[Path(p).suffix.lower()] for p in paths if Path(p).suffix.lower() in LANG_DIRS}
        if any(Path(repo_root / p).is_dir() for p in paths):
            langs = set(LANG_DIRS.values())
        cmd = [binary]
        for lang in sorted(langs):
            cmd += ["--config", str(rules_dir() / lang)]
        cmd += [
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",  # in-repo "nosemgrep" comments cannot silence findings
            *paths,
        ]
        return [cmd]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        data = json.loads(stdout)
        for err in data.get("errors", []):
            self.warn(f"{err.get('type', 'error')}: {str(err.get('message', ''))[:200]}")
        known = known_rule_ids(str(rules_dir()))
        findings: list[Finding] = []
        for res in data.get("results", []):
            extra = res.get("extra", {})
            meta = extra.get("metadata", {})
            cwe = meta.get("cwe")
            findings.append(
                make_finding(
                    tool=self.name,
                    tool_version=version or data.get("version", ""),
                    rule_id=strip_check_id(res["check_id"], known),
                    message=extra.get("message", ""),
                    severity=meta.get("sift_severity") or SEVERITY.get(extra.get("severity"), "medium"),
                    raw_path=res["path"],
                    start_line=res["start"]["line"],
                    end_line=res["end"]["line"],
                    repo_root=repo_root,
                    category=meta.get("category", "security"),
                    cwe=cwe[0] if isinstance(cwe, list) else cwe,
                )
            )
        return findings
