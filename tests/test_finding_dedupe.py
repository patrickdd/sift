from conftest import make

from sift.dedupe import cluster, dedupe
from sift.finding import fingerprint, normalize_code_line


def test_fingerprint_ignores_whitespace_and_trailing_comments():
    a = fingerprint("sql-injection", "app.py", 'cur.execute(f"SELECT {x}")')
    b = fingerprint("sql-injection", "app.py", '    cur.execute(f"SELECT {x}")   # TODO fix')
    assert a == b


def test_fingerprint_is_stable_across_line_moves():
    f1 = make(start_line=10, end_line=10, snippet="digest = md5(x)")
    f2 = make(start_line=42, end_line=42, snippet="digest  =  md5(x)")
    assert f1.id == f2.id


def test_fingerprint_varies_with_family_path_and_code():
    base = fingerprint("fam", "a.py", "x = 1")
    assert base != fingerprint("other", "a.py", "x = 1")
    assert base != fingerprint("fam", "b.py", "x = 1")
    assert base != fingerprint("fam", "a.py", "x = 2")
    assert len(base) == 64


def test_comment_markers_inside_strings_are_kept():
    assert normalize_code_line('url = "http://x#y"  # c', "a.py") == 'url = "http://x#y"'
    assert normalize_code_line('String u = "http://x"; // c', "A.java") == 'String u = "http://x";'
    assert normalize_code_line("q = a // b", "a.py") == "q = a // b"  # floor division


def test_dedupe_merges_tools_and_keeps_highest_severity():
    a = make(tool="ruff", severity="medium")
    b = make(tool="semgrep", severity="high")
    out = dedupe([a, b])
    assert len(out) == 1
    assert out[0].tools_agreeing == ["ruff", "semgrep"]
    assert out[0].severity == "high" and out[0].tool == "semgrep"


def test_cluster_overlapping_lines_same_family():
    a = make(tool="pmd", start_line=5, end_line=8, snippet="try {")
    b = make(tool="semgrep", start_line=7, end_line=7, snippet="} catch (E e) {}")
    c = make(tool="ruff", start_line=20, end_line=20, snippet="other")  # same family, no overlap
    d = make(tool="ruff", rule_family="else", start_line=6, end_line=6, snippet="x")  # other family
    clusters = cluster(dedupe([a, b, c, d]))
    assert len(clusters) == 3
    pair = next(cl for cl in clusters if len(cl.members) == 2)
    assert pair.tools == ["pmd", "semgrep"]
    assert all(f.cluster_id == pair.id and f.tools_agreeing == ["pmd", "semgrep"] for f in pair.members)
    assert (pair.start_line, pair.end_line) == (5, 8)


def test_cluster_ids_are_deterministic_and_sorted_by_priority():
    hi = make(severity="high", snippet="h", path="z.py")
    lo = make(severity="low", snippet="l", path="a.py")
    first = cluster(dedupe([lo, hi]))
    again = cluster(dedupe([hi, lo]))
    assert [c.id for c in first] == [c.id for c in again]
    assert first[0].severity == "high"
