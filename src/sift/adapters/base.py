"""Adapter contract, scrubbed subprocess runner, and a shared base class.

Security: tools run with an allow-listed environment (no API keys or cloud credentials),
a per-tool timeout, stdin closed, and only sift's own rules/config files.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol, runtime_checkable

from sift.finding import Finding

PASSTHROUGH_ENV = ("PATH", "HOME", "LANG", "JAVA_HOME", "TMPDIR")
# Opt-outs sift sets itself (they carry no user data): keep tools off the network.
TOOL_ENV = {"SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}


def warn(msg: str) -> None:
    """Warnings go to stderr only; stdout is reserved for machine-readable output."""
    print(f"sift: warning: {msg}", file=sys.stderr)


def scrubbed_env(source: dict[str, str] | None = None) -> dict[str, str]:
    src = os.environ if source is None else source
    env = {k: src[k] for k in PASSTHROUGH_ENV if k in src}
    env.update(TOOL_ENV)
    return env


def run_tool(
    cmd: list[str], timeout: float, cwd: Path | str
) -> tuple[str, str, int, float]:
    """Run a tool and return (stdout, stderr, returncode, duration_seconds).

    Raises FileNotFoundError if the binary does not exist. A timeout yields returncode -1.
    """
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=scrubbed_env(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout:.0f}s", -1, time.monotonic() - start
    # Decoded by hand: text mode would turn a lone CR inside repo content into a line break.
    out, err = (b.decode("utf-8", "replace") for b in (proc.stdout, proc.stderr))
    return out, err, proc.returncode, time.monotonic() - start


def safe_target(path: str) -> str:
    """A relative target as `./path`, so a file named `--exclude=*.py` cannot become an option."""
    return path if Path(path).is_absolute() or path.startswith("./") else f"./{path}"


@runtime_checkable
class Adapter(Protocol):
    name: str
    languages: tuple[str, ...]  # file suffixes, or ("*",) for any file
    single_file_ok: bool

    def version(self) -> str: ...

    def run(self, paths: list[str], repo_root: Path) -> list[Finding]: ...


class ToolAdapter:
    """Convenience base: binary detection, version caching, warning/timing bookkeeping."""

    name = ""
    binaries: tuple[str, ...] = ()
    languages: tuple[str, ...] = ()
    single_file_ok = False
    timeout = 300.0
    ok_returncodes: tuple[int, ...] = (0, 1)
    version_args: tuple[str, ...] = ("--version",)
    version_pattern = r"(\d+\.\d+(?:\.\d+)?)"

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.seconds = 0.0
        self._version: str | None = None

    # --- to override -------------------------------------------------------------
    def commands(self, binary: str, paths: list[str], repo_root: Path) -> list[list[str]]:
        raise NotImplementedError

    def parse(self, stdout: str, repo_root: Path, version: str = "") -> list[Finding]:
        raise NotImplementedError

    def cwd(self, repo_root: Path) -> Path:
        return repo_root

    # --- shared ------------------------------------------------------------------
    def binary(self) -> str | None:
        path = scrubbed_env().get("PATH")
        for name in self.binaries:
            found = shutil.which(name, path=path)
            if found:
                return found
        return None

    def available(self) -> bool:
        return self.binary() is not None

    def version(self) -> str:
        if self._version is None:
            self._version = ""
            binary = self.binary()
            if binary:
                out, err, _, _ = run_tool([binary, *self.version_args], 30, Path.cwd())
                match = re.search(self.version_pattern, out + "\n" + err)
                self._version = match.group(1) if match else ""
        return self._version

    def handles(self, path: str) -> bool:
        p = Path(path)
        return "*" in self.languages or p.suffix.lower() in self.languages or p.is_dir()

    def warn(self, msg: str) -> None:
        text = f"{self.name}: {msg}"
        self.warnings.append(text)
        warn(text)

    def run(self, paths: list[str], repo_root: Path) -> list[Finding]:
        targets = [safe_target(p) for p in paths if self.handles(p)]
        if not targets:
            return []
        binary = self.binary()
        if not binary:
            self.warn(f"none of {', '.join(self.binaries)} found on PATH; skipped")
            return []
        version = self.version()
        findings: list[Finding] = []
        for cmd in self.commands(binary, targets, repo_root):
            findings.extend(self._run_one(cmd, repo_root, version))
        return findings

    def _run_one(self, cmd: list[str], repo_root: Path, version: str) -> list[Finding]:
        try:
            out, err, code, secs = run_tool(cmd, self.timeout, self.cwd(repo_root))
        except FileNotFoundError:
            self.warn("binary disappeared; skipped")
            return []
        except OSError as exc:  # e.g. E2BIG: one tool must not take the whole scan down
            self.warn(f"could not start ({exc})")
            return []
        self.seconds += secs
        if code not in self.ok_returncodes:
            self.warn(f"exit code {code}: {err.strip()[:300]}")
            if not out.strip():
                return []
        try:
            return self.parse(out, repo_root, version)
        except (ValueError, KeyError, TypeError, IndexError, AttributeError) as exc:
            self.warn(f"could not parse output ({exc.__class__.__name__}: {exc})")
            return []
