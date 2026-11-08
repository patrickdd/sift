import sys
from pathlib import Path

from sift.adapters import ToolAdapter, run_tool, scrubbed_env


def test_scrubbed_env_keeps_only_allowlist():
    env = scrubbed_env({
        "PATH": "/bin", "HOME": "/h", "LANG": "C", "JAVA_HOME": "/j", "TMPDIR": "/t",
        "ANTHROPIC_API_KEY": "sk-ant", "AWS_SECRET_ACCESS_KEY": "a", "GOOGLE_APPLICATION_CREDENTIALS": "g",
        "GITHUB_TOKEN": "ghp", "OPENAI_API_KEY": "o", "GIT_DIR": "/x",
    })
    assert {k for k in env if not k.startswith("SEMGREP_")} == {"PATH", "HOME", "LANG", "JAVA_HOME", "TMPDIR"}


def test_run_tool_uses_scrubbed_env(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "leak-me")
    out, _, code, secs = run_tool(
        [sys.executable, "-c", "import os; print(os.environ.get('ANTHROPIC_API_KEY', 'absent'))"],
        30, tmp_path,
    )
    assert (out.strip(), code) == ("absent", 0) and secs >= 0


def test_run_tool_timeout(tmp_path):
    _, err, code, _ = run_tool([sys.executable, "-c", "import time; time.sleep(5)"], 0.5, tmp_path)
    assert code == -1 and "timed out" in err


class Missing(ToolAdapter):
    name = "nope"
    binaries = ("sift-definitely-not-installed",)
    languages = (".py",)


def test_missing_binary_returns_empty_with_warning(capsys):
    a = Missing()
    assert a.run(["x.py"], Path(".")) == []
    assert a.warnings and "skipped" in a.warnings[0]
    captured = capsys.readouterr()
    assert captured.out == "" and "skipped" in captured.err
