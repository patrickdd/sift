#!/usr/bin/env python3
"""sift Tier 1 PostToolUse hook. See hooks/README.md.

Exit 0 silently unless the edited file has new findings at or above the severity threshold;
then print at most 5 `path:line [tool/rule] message` lines to stderr and exit 2. Any internal
failure exits 0 and is written to hook.log in the cache dir: sift must never block editing.
"""

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

TIMEOUT_SECONDS = 15
MAX_LINES = 5
MAX_MESSAGE = 200
SUFFIXES = {".py", ".java"}
RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def cache_root() -> Path:
    root = Path(tempfile.gettempdir()) / f"sift-hook-{os.getuid()}"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def log(message: str) -> None:
    try:
        with (cache_root() / "hook.log").open("a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {message}\n")
    except OSError:
        pass


def digest(text: str | bytes) -> str:
    return hashlib.sha256(text.encode("utf-8") if isinstance(text, str) else text).hexdigest()


def resolve_path(payload: dict) -> Path | None:
    raw = (payload.get("tool_input") or {}).get("file_path")
    if not raw:
        raw = (payload.get("tool_response") or {}).get("filePath")
    if not raw:
        return None
    path = Path(raw)
    return path if path.is_absolute() else Path(payload.get("cwd") or ".") / path


def repo_threshold(start: Path) -> str | None:
    for folder in (start, *start.parents):
        candidate = folder / ".sift.toml"
        if candidate.is_file():
            return tomllib.loads(candidate.read_text(encoding="utf-8")).get("severity_threshold")
        if (folder / ".git").exists():
            return None
    return None


def threshold_rank(start: Path) -> int:
    """Precedence per DESIGN section 11: .sift.toml > plugin userConfig > default."""
    try:
        repo_value = repo_threshold(start)
    except (OSError, ValueError) as exc:
        log(f"ignoring unreadable .sift.toml: {exc}")
        repo_value = None
    for value in (repo_value, os.environ.get("CLAUDE_PLUGIN_OPTION_SEVERITY_THRESHOLD")):
        if value in RANK:
            return RANK[value]
    return RANK["high"]


def run_sift(path: Path, budget: float) -> dict:
    binary = os.environ.get("SIFT_BIN") or shutil.which("sift")
    if not binary:
        raise RuntimeError("sift executable not found on PATH")
    # A separate process group: killing sift alone would leave its tools holding the pipes.
    proc = subprocess.Popen(
        [binary, "hook-check", str(path)], cwd=path.parent, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise RuntimeError(f"sift hook-check timed out after {budget:.1f}s on {path}") from None
    if proc.returncode != 0:
        raise RuntimeError(f"sift hook-check exited {proc.returncode}: {stderr[-500:]}")
    return json.loads(stdout)


def format_line(finding: dict) -> str:
    message = " ".join(str(finding.get("message", "")).split())[:MAX_MESSAGE]
    return f"{finding['path']}:{finding['start_line']} [{finding['tool']}/{finding['rule_id']}] {message}"


def check(payload: dict, started: float) -> int:
    if os.environ.get("CLAUDE_PLUGIN_OPTION_HOOK_ENABLED", "true").lower() == "false":
        return 0
    path = resolve_path(payload)
    if path is None or path.suffix.lower() not in SUFFIXES or not path.is_file():
        return 0
    if ".sift" in path.parts:
        return 0

    session = digest(str(payload.get("session_id") or "no-session"))[:32]
    seen_file = cache_root() / f"{session}.seen"
    seen = set(seen_file.read_text(encoding="utf-8").split()) if seen_file.exists() else set()
    file_key = "file:" + digest(str(path).encode() + b"\0" + path.read_bytes())
    if file_key in seen:
        return 0

    result = run_sift(path, TIMEOUT_SECONDS - (time.monotonic() - started))
    for tool in result.get("tools", []):
        if not tool.get("available", True) or tool.get("warnings"):
            log(f"{tool.get('name')}: available={tool.get('available')} warnings={tool.get('warnings')}")

    minimum = threshold_rank(path.parent)
    findings = [f for f in result.get("new_findings", []) if RANK.get(f.get("severity"), 0) >= minimum]
    findings.sort(key=lambda f: (-RANK[f["severity"]], f["start_line"]))

    shown: list[str] = []
    keys = [file_key]
    for finding in findings:
        line = format_line(finding)
        # Stable id: a finding that only moved lines. Message hash: identical text, new code.
        id_key, message_key = "id:" + str(finding.get("id")), "msg:" + digest(line)
        if id_key in seen or message_key in seen or line in shown:
            continue
        if len(shown) == MAX_LINES:
            break
        shown.append(line)
        keys += [id_key, message_key]

    with seen_file.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(keys) + "\n")
    if not shown:
        return 0
    print("\n".join(shown), file=sys.stderr)
    return 2


def main() -> int:
    started = time.monotonic()
    try:
        return check(json.load(sys.stdin), started)
    except Exception as exc:  # noqa: BLE001 - the hook must never block editing
        log(f"{type(exc).__name__}: {exc}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
