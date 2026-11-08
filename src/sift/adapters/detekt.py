"""detekt adapter (Kotlin). EXPERIMENTAL AND UNTESTED: detekt was not installed when this was written.

Not registered in ADAPTER_CLASSES, so sift does not run it. The command comes from detekt's CLI
documentation and the parser was only exercised on a hand-written SARIF file. Before relying on it,
follow "Finish the job" in docs/ADDING_AN_ADAPTER.md.

detekt writes reports to a file and prints other text on stdout, so the report goes to a temp file.
It runs from an empty temp directory with absolute paths, as PMD does, so a repository file cannot
act as its configuration. Known gap: detekt still honours `@Suppress` annotations in the code.

Severity (SARIF level): error -> medium, warning -> low, note -> info. detekt gives most rules the
same default level, so a level alone cannot justify "high". Rules in style-like rule sets are capped
at low. Category (rule set): potential-bugs, exceptions, coroutines -> bug; performance -> resource;
everything else -> style.
"""

import json
import tempfile
from pathlib import Path

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import make_finding

LEVEL_SEVERITY = {"error": "medium", "warning": "low", "note": "info"}
RULESET_CATEGORY = {
    "potential-bugs": "bug",
    "exceptions": "bug",
    "coroutines": "bug",
    "performance": "resource",
}


class DetektAdapter(ToolAdapter):
    name = "detekt"
    binaries = ("detekt", "detekt-cli")
    languages = (".kt", ".kts")
    single_file_ok = False  # JVM cold start not measured
    ok_returncodes = (0, 2)  # 2 = at least one issue found

    def __init__(self) -> None:
        super().__init__()
        self._neutral = tempfile.TemporaryDirectory(prefix="sift-detekt-")
        self._report = Path(self._neutral.name) / "detekt.sarif"

    def cwd(self, repo_root: Path) -> Path:
        return Path(self._neutral.name)

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        absolute = [str((repo_root / p).resolve()) for p in paths]
        usable = [p for p in absolute if ":" not in p]  # ":" separates --input entries
        if len(usable) != len(absolute):
            self.warn(f"skipped {len(absolute) - len(usable)} path(s) containing ':'")
        if not usable:
            return []
        return [[binary, "--input", ":".join(usable), "--report", f"sarif:{self._report}"]]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        text = self._report.read_text(encoding="utf-8") if self._report.exists() else stdout
        findings: list[Finding] = []
        for run in json.loads(text).get("runs", []):
            for res in run.get("results", []):
                parts = res["ruleId"].split(".")  # e.g. detekt.potential-bugs.UnsafeCast
                ruleset = parts[-2] if len(parts) > 1 else ""
                category = RULESET_CATEGORY.get(ruleset, "style")
                severity = LEVEL_SEVERITY.get(res.get("level", "warning"), "low")
                loc = res["locations"][0]["physicalLocation"]
                region = loc.get("region", {})
                findings.append(
                    make_finding(
                        tool=self.name,
                        tool_version=version or run["tool"]["driver"].get("version", ""),
                        rule_id=parts[-1],
                        message=res["message"]["text"],
                        severity="low" if category == "style" and severity == "medium" else severity,
                        raw_path=loc["artifactLocation"]["uri"],
                        start_line=region.get("startLine", 1),
                        end_line=region.get("endLine"),
                        repo_root=repo_root,
                        category=category,
                    )
                )
        return findings
