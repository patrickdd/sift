"""The detekt adapter is experimental. The fixture is hand-written, not real detekt output."""

from conftest import FIXTURES

from sift.adapters import ADAPTER_CLASSES
from sift.adapters.detekt import DetektAdapter


def _parse(repo):
    (repo / "src").mkdir()
    (repo / "src" / "App.kt").write_text("fun main() {\n    val a = 1 as String\n    val b = 42\n}\n")
    return DetektAdapter().parse((FIXTURES / "detekt.handwritten.json").read_text(), repo, "x")


def test_severity_and_category_mapping(repo):
    bug, style = _parse(repo)
    assert (bug.rule_id, bug.severity, bug.category, bug.path) == ("UnsafeCast", "medium", "bug", "src/App.kt")
    assert (style.rule_id, style.severity, style.category) == ("MagicNumber", "low", "style")


def test_runs_from_a_neutral_directory_with_absolute_paths(repo):
    adapter = DetektAdapter()
    assert adapter.cwd(repo) != repo
    cmd = adapter.commands("detekt", ["./src/App.kt"], repo)[0]
    assert cmd[cmd.index("--input") + 1] == str((repo / "src/App.kt").resolve())
    assert "--config" not in cmd


def test_not_registered_until_verified():
    assert DetektAdapter not in ADAPTER_CLASSES
