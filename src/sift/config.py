"""Repository configuration (.sift.toml), read and validated in code rather than by the LLM.

The file is controlled by the repository under review, so it may only tune the review.
Only the keys in REPO_KEYS are read. In particular `test_command` is ignored: a repository
must never be able to choose a command that sift's user then runs.
"""

import re
import sys
import tomllib
from pathlib import Path

REPO_KEYS = {"base", "severity_threshold"}
DEFAULT_BASE = "main"
_SAFE_BASE = re.compile(r"[\w./~^@-]+")


def validate_base(base: str) -> str:
    """Reject a base that git would read as an option or a shell would expand."""
    if not isinstance(base, str) or base.startswith("-") or not _SAFE_BASE.fullmatch(base):
        raise ValueError(f"invalid base ref: {base!r}")
    return base


def read_repo_config(root: Path) -> tuple[dict, list[str]]:
    """(allowed settings, names of keys that were ignored) from <root>/.sift.toml."""
    path = root / ".sift.toml"
    if not path.is_file():
        return {}, []
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    ignored = sorted(set(data) - REPO_KEYS)
    for key in ignored:
        print(f"sift: warning: .sift.toml key '{key}' is not honoured and was ignored", file=sys.stderr)
    return {k: v for k, v in data.items() if k in REPO_KEYS}, ignored


def resolve_config(root: Path, base: str | None = None) -> dict:
    """Effective review settings. A base from the user outranks the repository's."""
    repo, ignored = read_repo_config(root)
    return {"base": validate_base(base or repo.get("base", DEFAULT_BASE)), "ignored_keys": ignored}
