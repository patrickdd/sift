"""CLI smoke tests against the real tools (skipped when a tool is not installed)."""

import json
import subprocess

import pytest
from conftest import REPO, git, requires

from sift.cli import main

VULN_PY = 'def q(cur, name):\n    cur.execute(f"SELECT * FROM t WHERE n = \'{name}\'")\n'


def run(capsys, monkeypatch, cwd, *argv):
    monkeypatch.chdir(cwd)
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_tools_lists_every_adapter(capsys, monkeypatch, tmp_path):
    code, out, _ = run(capsys, monkeypatch, tmp_path, "tools")
    assert code == 0
    assert [line.split()[0] for line in out.splitlines()] == ["semgrep", "pmd", "ruff", "bandit", "gitleaks"]


@requires("ruff", "bandit", "semgrep")
def test_scan_diff_scope_then_report(capsys, monkeypatch, repo, tmp_path):
    (repo / "old.py").write_text(VULN_PY)  # pre-existing debt on main: out of scope
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "feature")
    (repo / "new.py").write_text(VULN_PY)

    code, out, _ = run(capsys, monkeypatch, repo, "scan", "--format", "json")
    assert code == 0
    scan = json.loads(out)
    assert scan["mode"] == "diff" and {f["path"] for f in scan["findings"]} == {"new.py"}
    sql = [f for f in scan["findings"] if f["rule_family"] == "sql-injection"]
    assert len(sql) == 1 and {"semgrep", "ruff", "bandit"} <= set(sql[0]["tools_agreeing"])

    code, out_all, _ = run(capsys, monkeypatch, repo, "scan", "--all", "--format", "json")
    assert {f["path"] for f in json.loads(out_all)["findings"]} == {"new.py", "old.py"}

    findings = tmp_path / "findings.json"
    findings.write_text(out)
    cid = sql[0]["cluster_id"]
    triage = tmp_path / "triage.json"
    triage.write_text(json.dumps([
        {"id": cid, "verdict": "false_positive", "confidence": 80, "rationale": "looks fine"},
    ]))
    code, out, _ = run(capsys, monkeypatch, repo, "report", "--triage", str(triage),
                       "--findings", str(findings), "--out", str(tmp_path / "out"))
    assert code == 0
    report = (tmp_path / "out" / "report.md").read_text()
    assert "Needs human (1)" in report and "cites no path:line" in report  # uncited dismissal rejected
    sarif = json.loads((tmp_path / "out" / "review.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"][0]["partialFingerprints"]


@requires("ruff", "bandit")
def test_hook_check_reports_only_new_findings(capsys, monkeypatch, repo):
    (repo / "m.py").write_text("import subprocess\n" + VULN_PY)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    (repo / "m.py").write_text(
        "import subprocess\n\n\n" + VULN_PY + "\n\ndef r(c):\n    subprocess.call(c, shell=True)\n"
    )
    code, out, _ = run(capsys, monkeypatch, repo, "hook-check", "m.py")
    assert code == 0
    data = json.loads(out)
    families = {f["rule_family"] for f in data["new_findings"]}
    assert "command-injection" in families
    assert "sql-injection" not in families  # existed at HEAD (moved lines keep fingerprint)


def test_report_rejects_malformed_triage(capsys, monkeypatch, tmp_path):
    (tmp_path / "f.json").write_text("[]")
    (tmp_path / "t.json").write_text(json.dumps([{"id": "x", "verdict": "maybe", "confidence": 5,
                                                  "rationale": "r"}]))
    code, _, err = run(capsys, monkeypatch, tmp_path, "report", "--triage", "t.json",
                       "--findings", "f.json", "--out", "o")
    assert code == 1 and "verdict" in err


@requires("semgrep")
def test_semgrep_rule_tests_pass():
    proc = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--disable-version-check", "rules/"],
        cwd=REPO, capture_output=True, text=True, timeout=300,
    )
    assert "All tests passed" in proc.stdout + proc.stderr, proc.stdout + proc.stderr


def test_entry_point_installed():
    proc = subprocess.run(["sift", "--version"], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip("sift entry point not on PATH (run inside the venv)")
    assert proc.stdout.startswith("sift ")


def test_scan_output_file_and_report_test_section(capsys, monkeypatch, repo):
    code, out, _ = run(capsys, monkeypatch, repo, "scan", "--format", "json", "--output", "o/scan.json")
    assert code == 0 and out == ""
    (repo / "t.json").write_text("[]")
    (repo / "test.log").write_text("".join(f"line{i}\n" for i in range(40)))
    code, _, _ = run(capsys, monkeypatch, repo, "report", "--triage", "t.json", "--findings", "o/scan.json",
                     "--out", "o", "--md-name", "review.md", "--test-status", "failed",
                     "--test-output", "test.log")
    report = (repo / "o" / "review.md").read_text()
    assert code == 0 and "## Tests: failed" in report
    assert "line39" in report and "line9\n" not in report


def test_report_skipped_tests_line(capsys, monkeypatch, repo):
    run(capsys, monkeypatch, repo, "scan", "--format", "json", "--output", "o/scan.json")
    (repo / "t.json").write_text("[]")
    code, _, _ = run(capsys, monkeypatch, repo, "report", "--triage", "t.json", "--findings", "o/scan.json",
                     "--out", "o", "--test-status", "skipped")
    assert code == 0
    assert "## Tests: skipped (no test_command configured)" in (repo / "o" / "report.md").read_text()
