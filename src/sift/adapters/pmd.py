"""PMD adapter (Java). Parses PMD's SARIF output.

PMD resolves `-R rulesets/java/quickstart.xml` against the working directory before its
built-in classpath, so a repository could shadow the ruleset (verified with PMD 7.29).
PMD therefore runs from an empty temp directory with absolute target paths.

Severity: PMD priority 1 -> high, 2 -> medium, 3/4 -> low, 5 -> info. Style rules (naming
conventions are priority 1) are capped at low, so they never interrupt an edit.
"""

import json
import secrets
import tempfile
from pathlib import Path

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import make_finding

PRIORITY_SEVERITY = {1: "high", 2: "medium", 3: "low", 4: "low", 5: "info"}
RULESET_CATEGORY = {
    "Error Prone": "bug",
    "Multithreading": "bug",
    "Security": "security",
    "Performance": "resource",
}


class PmdAdapter(ToolAdapter):
    name = "pmd"
    binaries = ("pmd",)
    languages = (".java",)
    single_file_ok = True  # one-file cold start measured at ~2.0 s; formal check in phase 2
    ok_returncodes = (0, 4, 5)  # 4 = violations found, 5 = recoverable errors
    version_pattern = r"PMD (\d[\w.\-]*)"

    def __init__(self) -> None:
        super().__init__()
        self._neutral = tempfile.TemporaryDirectory(prefix="sift-pmd-")

    def cwd(self, repo_root: Path) -> Path:
        return Path(self._neutral.name)

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        cmd = [binary, "check"]
        for p in paths:
            cmd += ["-d", str((repo_root / p).resolve())]
        cmd += [
            "-R", "rulesets/java/quickstart.xml",
            "-f", "sarif",
            "--no-cache",
            "--no-progress",
            # A random marker means in-repo "// NOPMD" comments cannot silence findings.
            "--suppress-marker", f"SIFT_{secrets.token_hex(8)}",
        ]
        return [cmd]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        data = json.loads(stdout)
        findings: list[Finding] = []
        for run in data.get("runs", []):
            driver = run["tool"]["driver"]
            rules = {r["id"]: r for r in driver.get("rules", [])}
            for res in run.get("results", []):
                rule_id = res["ruleId"]
                props = rules.get(rule_id, {}).get("properties", {})
                loc = res["locations"][0]["physicalLocation"]
                region = loc.get("region", {})
                category = RULESET_CATEGORY.get(props.get("ruleset", ""), "style")
                severity = PRIORITY_SEVERITY.get(int(props.get("priority", 3)), "low")
                findings.append(
                    make_finding(
                        tool=self.name,
                        tool_version=version or driver.get("version", ""),
                        rule_id=rule_id,
                        message=res["message"]["text"],
                        severity="low" if category == "style" and severity == "high" else severity,
                        raw_path=loc["artifactLocation"]["uri"],
                        start_line=region.get("startLine", 1),
                        end_line=region.get("endLine"),
                        repo_root=repo_root,
                        category=category,
                    )
                )
        return findings
