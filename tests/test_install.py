"""The rules directory must resolve from an installed wheel, not only an editable checkout."""

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from conftest import REPO

pytestmark = pytest.mark.skipif(shutil.which("uv") is None, reason="uv is needed to build/install")

VULN_PY = 'def q(cur, name):\n    cur.execute(f"SELECT * FROM t WHERE n = \'{name}\'")\n'


def _uv(*args: str, cwd: Path) -> str:
    env = {k: v for k, v in os.environ.items() if k not in ("SIFT_RULES_DIR", "VIRTUAL_ENV", "PYTHONPATH")}
    proc = subprocess.run(["uv", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_rules_resolve_from_installed_wheel(tmp_path):
    dist = tmp_path / "dist"
    _uv("build", "--wheel", "--out-dir", str(dist), str(REPO), cwd=tmp_path)
    (wheel,) = dist.glob("sift-*.whl")

    names = zipfile.ZipFile(wheel).namelist()
    assert "sift/rules/families.yaml" in names
    assert "sift/rules/java/jdbc-string-concat.yaml" in names
    assert "sift/rules/tool-config/gitleaks.toml" in names
    assert not [n for n in names if n.endswith(".java")]  # vulnerable rule test cases stay out

    venv = tmp_path / "venv"
    _uv("venv", "--quiet", "--python", sys.executable, str(venv), cwd=tmp_path)
    py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _uv("pip", "install", "--quiet", "--python", str(py), str(wheel), cwd=tmp_path)

    env = {k: v for k, v in os.environ.items() if k not in ("SIFT_RULES_DIR", "PYTHONPATH")}
    out = subprocess.run(
        [str(py), "-I", "-c", "from sift.normalize import rules_dir; print(rules_dir())"],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=True,
    ).stdout.strip()
    rules = Path(out)
    assert rules.is_relative_to(venv.resolve()), rules
    assert (rules / "families.yaml").is_file() and (rules / "python" / "sql-fstring.yaml").is_file()

    if shutil.which("semgrep"):  # end to end: the installed CLI finds and runs its own rules
        work = tmp_path / "work"
        work.mkdir()
        (work / "q.py").write_text(VULN_PY)
        sift = py.parent / "sift"
        proc = subprocess.run([str(sift), "scan", "--all", "--format", "json"], cwd=work, env=env,
                              capture_output=True, text=True, timeout=300)
        assert proc.returncode == 0, proc.stderr
        rule_ids = {f["rule_id"] for f in json.loads(proc.stdout)["findings"]}
        assert "python.sql-fstring" in rule_ids, proc.stdout
