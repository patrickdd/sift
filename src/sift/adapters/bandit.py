"""Bandit adapter (Python). Parses `bandit -f json`.

Always passes sift's neutral --ini, because a repo-level .bandit file is otherwise
auto-loaded and can skip tests (verified with bandit 1.9). --ignore-nosec stops in-repo
"# nosec" comments from silencing findings.

Severity: issue_severity HIGH/MEDIUM/LOW -> high/medium/low, one step lower when
issue_confidence is LOW.
"""

import json
from pathlib import Path

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import downgrade, make_finding, rules_dir

SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditAdapter(ToolAdapter):
    name = "bandit"
    binaries = ("bandit",)
    languages = (".py",)
    single_file_ok = True

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        return [[
            binary, "-r", "-f", "json", "-q",
            "--ini", str(rules_dir() / "tool-config" / "bandit.ini"),
            "--ignore-nosec",
            *paths,
        ]]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        data = json.loads(stdout)
        for err in data.get("errors", []):
            self.warn(f"{err.get('filename', '?')}: {str(err.get('reason', ''))[:200]}")
        findings: list[Finding] = []
        for res in data.get("results", []):
            severity = SEVERITY.get(res.get("issue_severity", ""), "low")
            if res.get("issue_confidence") == "LOW":
                severity = downgrade(severity)
            line_range = res.get("line_range") or [res["line_number"]]
            cwe_id = (res.get("issue_cwe") or {}).get("id")
            findings.append(
                make_finding(
                    tool=self.name,
                    tool_version=version,
                    rule_id=res["test_id"],
                    message=res["issue_text"],
                    severity=severity,
                    raw_path=res["filename"],
                    start_line=res["line_number"],
                    end_line=max(line_range),
                    repo_root=repo_root,
                    category="security",
                    cwe=f"CWE-{cwe_id}" if cwe_id else None,
                )
            )
        return findings
