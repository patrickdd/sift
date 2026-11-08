"""The normalized Finding model and its fingerprint.

Fingerprint = sha256(rule_family, relpath, normalized code line), where the code line is
the finding's start line with whitespace collapsed and any trailing comment removed. It is
stable across line moves and formatting changes, and two tools that report the same rule
family on the same line produce the same fingerprint (cross-tool dedupe for free).
"""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, Field

Category = Literal["security", "bug", "resource", "style", "secret", "type"]
Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_RANK: dict[str, int] = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Languages whose line comments start with '#'; everything else is treated as C-like ('//').
_HASH_COMMENT_SUFFIXES = {
    ".py", ".pyi", ".yaml", ".yml", ".toml", ".sh", ".bash", ".rb", ".properties", ".cfg",
    ".ini", ".env", ".r", ".pl",
}
_SLASH_COMMENT_SUFFIXES = {
    ".java", ".kt", ".kts", ".scala", ".groovy", ".js", ".jsx", ".ts", ".tsx", ".go", ".c",
    ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".rs", ".php",
}


class Finding(BaseModel):
    id: str = ""  # fingerprint
    tool: str
    tool_version: str = ""
    rule_id: str
    rule_family: str
    category: Category
    cwe: str | None = None
    severity: Severity
    path: str  # repo-relative, POSIX separators
    start_line: int
    end_line: int
    snippet: str = ""  # source lines start_line..(capped); first line feeds the fingerprint
    message: str
    in_diff: bool = False
    cluster_id: str | None = None
    tools_agreeing: list[str] = Field(default_factory=list)

    def code_line(self) -> str:
        # Unreadable source: fall back to the line number so distinct findings never collide.
        return self.snippet.splitlines()[0] if self.snippet else f"@L{self.start_line}"

    def refingerprint(self) -> "Finding":
        self.id = fingerprint(self.rule_family, self.path, self.code_line())
        return self


class ToolRun(BaseModel):
    name: str
    version: str = ""
    available: bool = True
    findings: int = 0
    seconds: float = 0.0
    warnings: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    generated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    mode: Literal["diff", "all", "hook"] = "diff"
    base: str | None = None
    seconds: float = 0.0
    tools: list[ToolRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class TriageResult(BaseModel):
    """One triager verdict per cluster (the subagent's JSON contract)."""

    id: str
    verdict: Literal["true_positive", "false_positive", "needs_human"]
    confidence: int = Field(ge=0, le=100)
    rationale: str
    duplicate_of: str | None = None
    fix: str | None = None


def _strip_trailing_comment(line: str, marker: str) -> str:
    """Cut a trailing line comment that starts outside of a string literal."""
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif line.startswith(marker, i):
            return line[:i]
        i += 1
    return line


def normalize_code_line(line: str, path: str = "") -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _HASH_COMMENT_SUFFIXES:
        line = _strip_trailing_comment(line, "#")
    elif suffix in _SLASH_COMMENT_SUFFIXES:
        line = _strip_trailing_comment(line, "//")
    return re.sub(r"\s+", " ", line).strip()


def fingerprint(rule_family: str, relpath: str, code_line: str) -> str:
    normalized = normalize_code_line(code_line, relpath)
    payload = "\x1f".join((rule_family, relpath, normalized))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
