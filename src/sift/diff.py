"""Diff scoping: which files and which lines changed relative to a base branch.

One `git diff --unified=0 <merge-base(base, HEAD)>` compares the merge base with the
WORKING TREE, so committed, staged and unstaged changes all land in working-tree line
numbers (the coordinates the tools report). Untracked, non-ignored files count as
entirely changed. A pure deletion marks the lines on either side of it as changed,
because removing a guard can make the neighbouring code vulnerable.

Hardening: git runs with the scrubbed env, fsmonitor disabled, and no external diff
drivers or textconv filters, so repository config cannot execute programs.
"""

import re
from pathlib import Path

from sift.adapters.base import run_tool, warn

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.quotePath=false"]


class GitError(RuntimeError):
    pass


def git(args: list[str], cwd: Path | str) -> str:
    out, err, code, _ = run_tool([*_GIT, *args], 60, cwd)
    if code != 0:
        raise GitError(err.strip() or f"git {' '.join(args)} failed ({code})")
    return out


def repo_root(cwd: Path | str = ".") -> Path:
    return Path(git(["rev-parse", "--show-toplevel"], cwd).strip()).resolve()


def resolve_base(base: str, root: Path) -> str:
    try:
        return git(["merge-base", base, "HEAD"], root).strip()
    except GitError:
        pass
    try:
        head = git(["rev-parse", "--verify", "HEAD"], root).strip()
        warn(f"base '{base}' not found; diffing against HEAD (uncommitted changes only)")
        return head
    except GitError:
        warn("repository has no commits; every tracked or untracked file counts as changed")
        return EMPTY_TREE


def _unquote(path: str) -> str:
    if len(path) >= 2 and path[0] == path[-1] == '"':
        raw = path[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
        return raw.encode("latin-1").decode("utf-8", "replace")
    return path


def parse_unified0(text: str) -> dict[str, set[int]]:
    """Parse `git diff --unified=0` output into {new_path: changed new-side line numbers}."""
    changed: dict[str, set[int]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            target = _unquote(line[4:].rstrip("\t"))
            current = None if target == "/dev/null" else target.removeprefix("b/")
            if current is not None:
                changed.setdefault(current, set())
        elif current is not None and (m := _HUNK.match(line)):
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            if count == 0:  # pure deletion after line `start`
                changed[current].update(n for n in (start, start + 1) if n >= 1)
            else:
                changed[current].update(range(start, start + count))
    return changed


def untracked_files(root: Path) -> list[str]:
    out = git(["ls-files", "--others", "--exclude-standard", "-z"], root)
    return [p for p in out.split("\0") if p]


def _line_count(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            data = fh.read()
    except OSError:
        return 0
    if b"\0" in data[:8192]:
        return 0  # binary
    return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)


def changed_lines(base: str = "main", cwd: Path | str = ".") -> dict[str, set[int]]:
    """Map repo-relative path -> set of changed line numbers (working-tree coordinates)."""
    root = repo_root(cwd)
    base_rev = resolve_base(base, root)
    text = git(
        ["diff", "--unified=0", "--no-color", "--no-ext-diff", "--no-textconv",
         "--src-prefix=a/", "--dst-prefix=b/", base_rev],
        root,
    )
    changed = parse_unified0(text)
    for rel in untracked_files(root):
        changed[rel] = set(range(1, _line_count(root / rel) + 1))
    return changed


def all_files(root: Path) -> list[str]:
    """Tracked + untracked-but-not-ignored files that exist on disk."""
    out = git(["ls-files", "--cached", "--others", "--exclude-standard", "-z"], root)
    return sorted({p for p in out.split("\0") if p and (root / p).is_file()})


def in_diff(changed: dict[str, set[int]], path: str, start: int, end: int) -> bool:
    lines = changed.get(path)
    return bool(lines) and any(n in lines for n in range(start, end + 1))
