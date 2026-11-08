"""End to end over real stdio: start `sift mcp` and call it as a client."""

import hashlib
import json
import os
import sys
from pathlib import Path

import anyio
import pytest
from conftest import REPO, git, requires
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sift.mcp_server import ExportResult, FindingDetail, ScanPacket, ToolInfo
from sift.sarif import validate

SEEDED = 'def q(cur, name):\n    cur.execute(f"SELECT * FROM t WHERE n = \'{name}\'")\n'
AWS_KEY = "AKIA" + "Z7Q2MNXC4LPD9RTV"  # assembled so this file is not itself a finding


def _content(result):
    assert not result.is_error, result.content
    return result.structured_content


async def _session(repo: Path, calls):
    env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"  # where `sift` is installed
    config = json.loads((REPO / ".mcp.json").read_text())["mcpServers"]["sift-mcp"]
    params = StdioServerParameters(command=config["command"], args=config["args"], cwd=repo, env=env)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        return await calls(session)


def _tree(repo: Path) -> dict[str, str]:
    """Hash of every file outside .git and .sift."""
    return {
        p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in repo.rglob("*")
        if p.is_file() and not {".git", ".sift"} & set(p.relative_to(repo).parts)
    }


@pytest.fixture
def scratch(repo):
    (repo / "old.py").write_text(SEEDED)
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "scratch")
    (repo / "seeded.py").write_text(f'KEY = "{AWS_KEY}"\n\n\n' + SEEDED)
    return repo


@requires("ruff", "bandit", "semgrep", "gitleaks")
def test_all_tools_over_stdio(scratch):
    before = _tree(scratch)

    async def calls(s):
        listed = await s.list_tools()
        scan = _content(await s.call_tool("scan", {"base": "main"}))
        cluster_id = next(c["id"] for c in scan["clusters"] if c["rule_family"] == "sql-injection")
        detail = _content(await s.call_tool("get_finding", {"id": cluster_id}))
        tools = _content(await s.call_tool("list_tools", {}))
        sarif = _content(await s.call_tool("export", {"format": "sarif"}))
        md = _content(await s.call_tool("export", {"format": "md"}))
        missing = await s.call_tool("get_finding", {"id": "nope"})
        bad_base = await s.call_tool("scan", {"base": "--upload-pack=x"})
        return listed, scan, detail, tools, sarif, md, missing, bad_base

    listed, scan, detail, tools, sarif, md, missing, bad_base = anyio.run(_session, scratch, calls)

    assert {t.name for t in listed.tools} == {"scan", "get_finding", "list_tools", "export"}

    # The packet schema validates, and the seeded issue on the scratch branch is in it.
    packet = ScanPacket.model_validate(scan)
    assert packet.mode == "diff" and packet.base == "main" and packet.coverage_complete
    assert {c.path for c in packet.clusters} == {"seeded.py"}  # old.py is out of the diff
    assert "sql-injection" in {c.rule_family for c in packet.clusters}
    assert packet.packet.startswith("# sift evidence packet") and "UNTRUSTED CODE" in packet.packet
    assert (scratch / packet.findings_path).is_file()

    found = FindingDetail.model_validate(detail)
    assert found.finding.rule_family == "sql-injection" and found.finding.path == "seeded.py"
    assert "cur.execute" in found.context and found.context.startswith("<<<UNTRUSTED CODE")

    assert AWS_KEY not in json.dumps([scan, detail])
    assert AWS_KEY not in (scratch / packet.findings_path).read_text()
    assert "[secret redacted by sift" in found.context

    wrapped = tools["result"] if "result" in tools else tools
    infos = [ToolInfo.model_validate(t) for t in wrapped]
    assert [t.name for t in infos] == ["semgrep", "pmd", "ruff", "bandit", "gitleaks"]

    assert ExportResult.model_validate(sarif).path == ".sift/out/review.sarif"
    assert validate(json.loads((scratch / sarif["path"]).read_text())) == []
    assert md["path"] == ".sift/out/report.md"
    assert AWS_KEY not in (scratch / md["path"]).read_text()

    assert missing.is_error and bad_base.is_error
    assert _tree(scratch) == before, "an MCP tool modified a source file"


def test_get_finding_before_any_scan_is_a_clear_error(repo):
    async def calls(s):
        return await s.call_tool("get_finding", {"id": "x"})

    result = anyio.run(_session, repo, calls)
    assert result.is_error and "run scan first" in result.content[0].text


def test_redirected_output_directory_is_refused(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("victim")
    (repo / ".sift").symlink_to(outside)
    (repo / "a.txt").write_text("x\n")

    async def calls(s):
        return await s.call_tool("scan", {"all_files": True})

    result = anyio.run(_session, repo, calls)
    assert result.is_error and "symlink" in result.content[0].text
    assert list(outside.iterdir()) == []


def test_plugin_registers_the_server():
    config = json.loads((REPO / ".mcp.json").read_text())
    assert config["mcpServers"]["sift-mcp"] == {"command": "sift", "args": ["mcp"]}


def test_no_logic_duplication_in_the_server():
    source = (REPO / "src" / "sift" / "mcp_server.py").read_text()
    assert "subprocess" not in source and "write_text" not in source
