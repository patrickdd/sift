from conftest import git

from sift.diff import changed_lines, in_diff, parse_unified0


def test_parse_unified0_hunks_and_deletions():
    text = (
        "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
        "@@ -3 +3 @@\n-a\n+b\n"
        "@@ -10,0 +11,3 @@\n+c\n+d\n+e\n"
        "@@ -20,2 +22,0 @@\n-f\n-g\n"
        "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    )
    assert parse_unified0(text) == {"x.py": {3, 11, 12, 13, 22, 23}}


def test_changed_lines_committed_staged_unstaged_untracked(repo):
    (repo / "a.py").write_text("".join(f"l{i}\n" for i in range(1, 11)))
    (repo / "keep.py").write_text("same\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "base")
    git(repo, "checkout", "-qb", "feature")

    lines = (repo / "a.py").read_text().splitlines()
    lines[1] = "committed"  # line 2
    (repo / "a.py").write_text("\n".join(lines) + "\n")
    git(repo, "commit", "-qam", "feature work")

    lines[4] = "staged"  # line 5
    (repo / "a.py").write_text("\n".join(lines) + "\n")
    git(repo, "add", "a.py")

    lines[7] = "unstaged"  # line 8
    (repo / "a.py").write_text("\n".join(lines) + "\n")

    (repo / "new.py").write_text("one\ntwo\nthree\n")
    (repo / ".gitignore").write_text("ignored.py\n")
    (repo / "ignored.py").write_text("x\n")

    changed = changed_lines("main", repo)
    assert changed["a.py"] == {2, 5, 8}
    assert changed["new.py"] == {1, 2, 3}
    assert "keep.py" not in changed
    assert "ignored.py" not in changed
    assert in_diff(changed, "a.py", 4, 6) and not in_diff(changed, "a.py", 3, 4)


def test_missing_base_falls_back_to_head(repo, capsys):
    (repo / "a.py").write_text("a\nb\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")
    (repo / "a.py").write_text("a\nB\n")
    assert changed_lines("does-not-exist", repo) == {"a.py": {2}}
    assert "not found" in capsys.readouterr().err


def test_repo_without_commits(repo):
    (repo / "a.py").write_text("x\ny\n")
    assert changed_lines("main", repo) == {"a.py": {1, 2}}
