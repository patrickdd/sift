"""Each adapter's parser against a real output sample captured from the installed tool."""

from pathlib import Path

from conftest import FIXTURES

from sift.adapters import BanditAdapter, GitleaksAdapter, PmdAdapter, RuffAdapter, SemgrepAdapter

ROOT = Path("/repo")


def parse(adapter):
    return adapter.parse((FIXTURES / f"{adapter.name}.json").read_text(), ROOT, "1.0")


def summary(findings):
    return sorted((f.rule_id, f.path, f.start_line, f.severity, f.rule_family) for f in findings)


def test_pmd_sarif():
    fs = parse(PmdAdapter())
    assert summary(fs) == [
        ("EmptyCatchBlock", "Demo.java", 9, "low", "empty-catch"),
        ("UnusedLocalVariable", "Demo.java", 8, "low", "unused-variable"),
    ]
    catch = next(f for f in fs if f.rule_id == "EmptyCatchBlock")
    assert catch.category == "bug" and catch.cwe == "CWE-390" and catch.tool_version == "1.0"


def test_semgrep_json_strips_config_prefix():
    fs = parse(SemgrepAdapter())
    assert summary(fs) == [
        ("java.weak-hash", "Hashes.java", 6, "medium", "weak-hash"),
        ("java.weak-hash", "Hashes.java", 11, "medium", "weak-hash"),
        ("python.sql-fstring", "app.py", 6, "high", "sql-injection"),
        ("python.subprocess-shell-true", "app.py", 7, "high", "command-injection"),
        ("python.yaml-unsafe-load", "app.py", 8, "high", "unsafe-deserialization"),
    ]
    assert len({f.id for f in fs}) == 5  # distinct fingerprints even without readable source
    assert all(f.cwe for f in fs)


def test_ruff_json_absolute_paths_become_relative():
    fs = parse(RuffAdapter())
    assert summary(fs) == [
        ("S506", "app.py", 8, "medium", "unsafe-deserialization"),
        ("S602", "app.py", 7, "medium", "command-injection"),
        ("S608", "app.py", 6, "medium", "sql-injection"),
    ]
    assert {f.category for f in fs} == {"security"}


def test_bandit_json():
    fs = parse(BanditAdapter())
    assert summary(fs) == [
        ("B404", "app.py", 1, "low", "bandit:B404"),
        ("B506", "app.py", 8, "medium", "unsafe-deserialization"),
        ("B602", "app.py", 7, "high", "command-injection"),
        ("B608", "app.py", 6, "medium", "sql-injection"),
    ]
    assert next(f for f in fs if f.rule_id == "B404").cwe == "CWE-78"


def test_gitleaks_json_is_redacted_and_secret():
    raw = (FIXTURES / "gitleaks.json").read_text()
    assert "REDACTED" in raw and "AKIA" not in raw and "ghp_" not in raw
    fs = parse(GitleaksAdapter())
    assert summary(fs) == [
        ("aws-access-token", "secrets.py", 1, "high", "hardcoded-secret"),
        ("github-pat", "secrets.py", 2, "high", "hardcoded-secret"),
    ]
    assert {f.category for f in fs} == {"secret"}


def test_cross_tool_same_line_shares_fingerprint():
    """semgrep, ruff and bandit all flag app.py:6 as sql-injection -> one fingerprint."""
    ids = {
        f.id
        for a in (SemgrepAdapter(), RuffAdapter(), BanditAdapter())
        for f in parse(a)
        if f.rule_family == "sql-injection"
    }
    assert len(ids) == 1


def test_ruff_rates_assert_low_like_bandit_b101():
    from sift.adapters.ruff import _severity

    assert _severity("S101") == "low"
    assert _severity("S603") == "medium"


def test_ruff_selection_keeps_syntax_errors_and_drops_style():
    from pathlib import Path

    from sift.adapters.ruff import RuffAdapter

    argv = RuffAdapter().commands("ruff", ["a.py"], Path("."))[0]
    assert argv[argv.index("--select") + 1] == "F,B,S,E9"
