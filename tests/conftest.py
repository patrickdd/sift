import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sift.finding import Finding

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parents[1]

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=GIT_ENV, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def requires(*tools: str):
    missing = [t for t in tools if not shutil.which(t)]
    return pytest.mark.skipif(bool(missing), reason=f"missing tools: {missing}")


def make(**kw) -> Finding:
    base = dict(
        tool="semgrep", rule_id="r", rule_family="fam", category="security", severity="medium",
        path="a.py", start_line=1, end_line=1, snippet="x = 1", message="m",
    )
    base.update(kw)
    f = Finding(**base)
    f.tools_agreeing = f.tools_agreeing or [f.tool]
    return f.refingerprint()
