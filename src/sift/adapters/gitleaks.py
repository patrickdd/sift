"""gitleaks adapter (any file). Parses `gitleaks dir ... -f json`.

gitleaks 8.x replaced `detect --no-git` with `gitleaks dir`. sift always passes:
  --config <sift's own config>  (a repo .gitleaks.toml can allowlist everything; verified)
  --gitleaks-ignore-path <sift rules/tool-config>  (repo .gitleaksignore is not loaded)
  --ignore-gitleaks-allow  (in-repo "gitleaks:allow" comments cannot silence findings)
  --redact  (raw secrets never reach stdout, the packet, or the LLM)
`gitleaks dir` takes one source, so each target gets its own (parallel) invocation.

Severity: every leak -> high; category: secret.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sift.adapters.base import ToolAdapter
from sift.finding import Finding
from sift.normalize import make_finding, rules_dir


class GitleaksAdapter(ToolAdapter):
    name = "gitleaks"
    binaries = ("gitleaks",)
    languages = ("*",)
    single_file_ok = True
    ok_returncodes = (0,)
    version_args = ("version",)

    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        cfg = rules_dir() / "tool-config"
        return [
            [
                binary, "dir", p,
                "--config", str(cfg / "gitleaks.toml"),
                "--gitleaks-ignore-path", str(cfg),
                "--ignore-gitleaks-allow",
                "--report-format", "json",
                "--report-path", "-",
                "--exit-code", "0",
                "--redact",
                "--no-banner",
                "--log-level", "error",
            ]
            for p in paths
        ]

    def run(self, paths: list[str], repo_root: Path) -> list[Finding]:
        binary = self.binary()
        if not binary or len(paths) <= 1:
            return super().run(paths, repo_root)
        version = self.version()
        cmds = self.commands(binary, [p for p in paths if self.handles(p)], repo_root)
        with ThreadPoolExecutor(max_workers=8) as pool:
            chunks = pool.map(lambda c: self._run_one(c, repo_root, version), cmds)
        return [f for chunk in chunks for f in chunk]

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for leak in json.loads(stdout or "[]"):
            findings.append(
                make_finding(
                    tool=self.name,
                    tool_version=version,
                    rule_id=leak["RuleID"],
                    message=leak.get("Description") or leak["RuleID"],
                    severity="high",
                    raw_path=leak["File"],
                    start_line=leak["StartLine"],
                    end_line=leak.get("EndLine"),
                    repo_root=repo_root,
                    category="secret",
                )
            )
        return findings
