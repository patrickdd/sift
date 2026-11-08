"""Ruff adapter (Python). Parses `ruff check --output-format json`.

Runs with --isolated (the repo's ruff config cannot deselect or exclude rules),
--ignore-noqa (in-repo "# noqa" cannot silence findings) and --no-cache (no writes).

Severity: E9xx (syntax errors) -> high; S, B, F -> medium; other E -> low.
Category: S -> security, B/F -> bug, E -> style.
"""

import json
from pathlib import Path

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import make_finding


def _severity(code: str) -> str:
    if code.startswith("E9"):
        return "high"
    if code[:1] in ("S", "B", "F"):
        return "medium"
    return "low"


def _category(code: str) -> str:
    return {"S": "security", "B": "bug", "F": "bug"}.get(code[:1], "style")


class RuffAdapter(ToolAdapter):
    name = "ruff"
    binaries = ("ruff",)
    languages = (".py", ".pyi")
    single_file_ok = True

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        return [[
            binary, "check",
            "--output-format", "json",
            "--select", "E,F,B,S",
            "--isolated", "--ignore-noqa", "--no-cache", "--exit-zero",
            *paths,
        ]]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for item in json.loads(stdout or "[]"):
            code = item.get("code") or "syntax-error"  # ruff reports syntax errors with code null
            findings.append(
                make_finding(
                    tool=self.name,
                    tool_version=version,
                    rule_id=code,
                    message=item["message"],
                    severity="high" if code == "syntax-error" else _severity(code),
                    raw_path=item["filename"],
                    start_line=item["location"]["row"],
                    end_line=(item.get("end_location") or {}).get("row"),
                    repo_root=repo_root,
                    category="bug" if code == "syntax-error" else _category(code),
                )
            )
        return findings
