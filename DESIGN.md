# sift — design

> **Deterministic tools are the evidence; the LLM is the reviewer who reads it.
> Every dismissal is auditable, and I measured how often it's wrong.**

sift runs static-analysis tools on changed code, normalizes and dedupes their findings into a
compact evidence packet, and hands that packet to a read-only Claude Code subagent that triages
each finding (true positive / false positive / needs human) with a rationale citing `file:line`
evidence. Every dismissal is listed in the report. A seeded-bug benchmark measures recall, the
false-positive filter rate and the **harmful-dismissal rate** (real bugs the LLM wrongly dismissed).

Status legend used throughout: **[built]** exists in phase 1 and is covered by tests ·
**[planned: phase N]** designed but not implemented · **UNVERIFIED** assumption not yet checked.

## Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [Pipeline](#2-pipeline)
3. [Tiering](#3-tiering)
4. [Finding schema, severity and rule families](#4-finding-schema-severity-and-rule-families)
5. [Adapter contract](#5-adapter-contract)
6. [Evidence packet](#6-evidence-packet)
7. [Triager subagent contract](#7-triager-subagent-contract)
8. [Report and SARIF](#8-report-and-sarif)
9. [CLI](#9-cli)
10. [Repo layout](#10-repo-layout)
11. [Configuration and precedence](#11-configuration-and-precedence)
12. [Security notes](#12-security-notes)
13. [Deviations from the original brief](#13-deviations-from-the-original-brief)
14. [Benchmark design](#14-benchmark-design)
15. [Roadmap](#15-roadmap)

---

## 1. Goals and non-goals

**Goals**
- Review *changed* code (diff-scoped by default) for Java (Spring Boot first) and Python.
- Deterministic tools produce all evidence; the LLM only triages it and must cite `path:line`.
- Make every dismissal auditable (report section + SARIF suppression with justification).
- Measure the triager, especially the harmful-dismissal rate.
- Smallest design that works end to end in a weekend; docs are a first-class deliverable,
  because the repo doubles as enablement material for engineers and QA teams.

**Non-goals (v0.1)**
- No cloud service, no CodeRabbit-style repo cloning.
- No SpotBugs (it needs a build); see Roadmap.
- No Stop hook, no auto-fix command, no memories file.
- No bundling of analysis tools: they are separate processes found on `PATH`
  (PMD BSD, Semgrep CE / Opengrep LGPL, gitleaks MIT, Ruff MIT, Bandit Apache-2.0).

## 2. Pipeline

```
 git diff <merge-base(base,HEAD)> (working tree)  +  untracked files      [built] diff.py
                          │  path -> {changed lines}
                          ▼
        target files (diff-scoped; or every git-visible file with --all)  [built] pipeline.py
                          │
      ┌────────────┬──────┴─────┬────────────┬─────────────┐   ThreadPoolExecutor
      ▼            ▼            ▼            ▼             ▼   (one thread per adapter)
   semgrep/       pmd         ruff        bandit       gitleaks           [built] adapters/
   opengrep     (SARIF)      (JSON)       (JSON)    (JSON, per file)
      └────────────┴──────┬─────┴────────────┴─────────────┘
                          ▼
           normalize -> Finding (family, relpath, snippet, fingerprint)  [built] normalize.py
                          ▼
           in-diff filter (dropped in diff mode; flagged only with --all)
                          ▼
           fingerprint dedupe  (same family + path + normalized line)    [built] dedupe.py
                          ▼
           cross-tool cluster  (same path + family + overlapping lines)
                          ▼
           packet builder  (≤25 clusters, ~300 tokens each, UNTRUSTED env.) [built] packet.py
                          ▼
           triager subagent  (Read/Grep/Glob only; JSON verdicts)    [built]
                          ▼
           report.md + review.sarif                             [built] report.py, sarif.py
```

## 3. Tiering

| Tier | Trigger | Scope | Tools | Budget | Output |
|---|---|---|---|---|---|
| **1** | PostToolUse hook, matcher `Edit\|Write`, filtered to `*.py` / `*.java` **[built]**; backend `sift hook-check` **[built]** | the one edited file | single-file, no-build tools: Ruff, Bandit, gitleaks, Semgrep, PMD quickstart (one-file cold start ≤ 4 s; measured in `hooks/README.md`) | hard timeout 15 s | exit 0 silently; exit 2 with ≤ 5 one-line findings **only** when a finding is (a) error/high severity and (b) new relative to the baseline |
| **3** | `/sift:review` command **[built]**; backend `sift scan` + `sift report` **[built]** | `git diff <merge-base>` + uncommitted + untracked | all adapters, optional test command | per-tool timeout (300 s) | triage, then `report.md` + `review.sarif` |
| **4** | CI gate **[roadmap]** | PR diff | deterministic only, no LLM | CI | SARIF upload |

**Baseline (Tier 1).** `sift hook-check <file> [--baseline-ref HEAD]` runs every adapter with
`single_file_ok = True` on the file, runs them again on `git show <ref>:<path>` written to a temp
file, rewrites the baseline findings' paths, re-fingerprints them, and prints
`{file, baseline_ref, new_findings, tools}`. It returns **all** new findings with their severity;
the phase-2 hook applies the error/high filter, the ≤ 5 limit, and the per-session cache keyed
by (session_id, path, file hash), so identical messages are not repeated within a session (a new
session repeats them). The cache is in `hooks/post_edit.py` **[built]**.

**PMD in Tier 1.** Median one-file cold start is 1.79 s (limit 4 s), so PMD stays in the hook. Semgrep
also runs there, which takes a full Java `hook-check` to a 5.42 s median. Numbers are in `hooks/README.md`.

**Why the LLM never runs inside a hook.** A hook fires on every edit, so an LLM call there
would multiply cost and add seconds of latency to each keystroke-level action. It would also
risk feedback loops: the agent reacting to the reviewer's output, which triggers further
edits and hooks. Hooks stay deterministic and cheap; triage happens once, on demand.

**Claude Code platform facts:** verified against the docs and in live sessions; see `hooks/README.md`.

## 4. Finding schema, severity and rule families

**`Finding`** (pydantic v2, `src/sift/finding.py`) **[built]**

| Field | Type | Notes |
|---|---|---|
| `id` | str | fingerprint (sha256 hex) |
| `tool`, `tool_version` | str | tool that produced the kept record |
| `rule_id` | str | the tool's own rule id (Semgrep config-path prefix stripped) |
| `rule_family` | str | from `rules/families.yaml`, else `"<tool>:<rule_id>"` |
| `category` | `security\|bug\|resource\|style\|secret\|type` | family overrides the adapter's guess |
| `cwe` | str \| None | family overrides the tool's value |
| `severity` | `critical\|high\|medium\|low\|info` | see table below |
| `path` | str | repo-relative, POSIX separators |
| `start_line`, `end_line` | int | 1-based, `end ≥ start` |
| `snippet` | str | source lines from `start_line`, at most 5 (read by sift, not taken from the tool) |
| `message` | str | whitespace-collapsed tool message |
| `in_diff` | bool | any line of the range is a changed line |
| `cluster_id` | str \| None | `C-` + first 10 hex chars of sha256(sorted member ids) |
| `tools_agreeing` | list[str] | union of tools in the dedupe group, then in the cluster |

**Fingerprint** = `sha256(rule_family ␟ relpath ␟ normalized_code_line)`. The code line is the
finding's start line with whitespace collapsed and any trailing comment removed (`#` for
Python/YAML/shell-like files, `//` for Java/C-like files, ignoring markers inside string
literals; `a // b` in Python is preserved). A comment-only line keeps its text, and when the source is
unreadable the line is replaced by `@L<start_line>`. Because the rule *family* (not the
tool) is hashed, Semgrep, Ruff and Bandit flagging the same SQL line produce one fingerprint.
The same code repeated on another line of a file is a separate occurrence: `dedupe` merges only
findings on the same line and gives each later occurrence its own id. Fingerprints change if a
call is re-wrapped across lines, and whitespace inside string literals is collapsed.

**Per-tool severity mapping** **[built]**

| Tool | Native signal | sift severity |
|---|---|---|
| Semgrep / Opengrep | `ERROR` / `WARNING` / `INFO` (rule metadata `sift_severity` overrides) | high / medium / low |
| PMD | rule priority 1 / 2 / 3 / 4 / 5; style rules (e.g. naming) capped at low | high / medium / low / low / info |
| Ruff | `E9xx` or syntax error (code `null`) · `S*`, `B*`, `F*` · other `E*` | high · medium · low |
| Bandit | `issue_severity` HIGH / MEDIUM / LOW; one step lower if `issue_confidence` is LOW | high / medium / low |
| gitleaks | any leak | high |

A cluster's severity is that of its representative: the member with the highest severity,
then most tools agreeing, then earliest line.

Category guesses before family override: Semgrep `metadata.category` (default `security`);
PMD ruleset *Error Prone*/*Multithreading* → bug, *Security* → security, *Performance* →
resource, everything else → style; Ruff `S` → security, `B`/`F` → bug, `E` → style;
Bandit → security; gitleaks → secret.

**Rule families** (`rules/families.yaml`, 9 entries; `"*"` matches every rule of a tool)

| Family | Category | CWE | Members |
|---|---|---|---|
| sql-injection | security | CWE-89 | semgrep `java.jdbc-string-concat`, `python.sql-fstring`; bandit B608; ruff S608 |
| command-injection | security | CWE-78 | semgrep `java.runtime-exec-nonconstant`, `python.subprocess-shell-true`; bandit B602, B605; ruff S602, S605 |
| unsafe-deserialization | security | CWE-502 | semgrep `python.yaml-unsafe-load`; bandit B506, B301; ruff S506, S301 |
| weak-hash | security | CWE-328 | semgrep `java.weak-hash`; bandit B303, B324; ruff S303, S324 |
| hardcoded-secret | secret | CWE-798 | semgrep `java.hardcoded-secret-value`; bandit B105–B107; ruff S105–S107; gitleaks `*` |
| empty-catch | bug | CWE-390 | pmd EmptyCatchBlock; bandit B110; ruff S110 |
| unused-variable | style | — | pmd UnusedLocalVariable; ruff F841 |
| insecure-cors | security | CWE-942 | semgrep `java.cors-wildcard` |
| missing-authorization | security | CWE-862 | semgrep `java.permit-all-sensitive` |

**sift's own Semgrep rules** (MIT, original, never copied from the Semgrep registry; each has
`# ruleid:` / `# ok:` cases next to it and passes `semgrep --test rules/`):
`java.jdbc-string-concat` (taint: method parameter → first argument of JdbcTemplate /
NamedParameterJdbcTemplate / EntityManager query methods), `java.hardcoded-secret-value`,
`java.weak-hash`, `java.cors-wildcard`, `java.permit-all-sensitive`,
`java.runtime-exec-nonconstant`, `python.sql-fstring`, `python.yaml-unsafe-load`,
`python.subprocess-shell-true`.

## 5. Adapter contract

```python
@runtime_checkable
class Adapter(Protocol):                      # src/sift/adapters/base.py
    name: str
    languages: tuple[str, ...]                # file suffixes, or ("*",)
    single_file_ok: bool                      # eligible for the Tier 1 hook
    def version(self) -> str: ...
    def run(self, paths: list[str], repo_root: Path) -> list[Finding]: ...
```

`ToolAdapter` is a convenience base class. A new adapter sets `name`, `binaries`, `languages`,
`single_file_ok`, `ok_returncodes` (and `version_args` / `version_pattern` if needed), then
implements two methods:

- `commands(binary, paths, repo_root) -> list[list[str]]`: argv lists, never a shell string.
- `parse(stdout, repo_root, version) -> list[Finding]`: parses the tool's **native JSON or
  SARIF** and builds Findings via `normalize.make_finding(...)`. No screen-scraping.

The base class provides: binary detection on the scrubbed `PATH` (first match in `binaries`
wins, so `opengrep` is preferred over `semgrep`); cached `version()`; filtering targets by
suffix; and `run_tool(cmd, timeout, cwd) -> (stdout, stderr, returncode, duration)`, where a
timeout yields return code −1. It also handles graceful degradation: a missing binary,
unexpected exit code or unparseable output records a warning and returns `[]`. Warnings go to
**stderr only** and into `ToolRun.warnings` for the report; stdout stays machine-readable.

Adding an adapter (becomes `docs/ADDING_AN_ADAPTER.md` in phase 5):
1. Run the tool on a tiny fixture and save its real output as `tests/fixtures/<tool>.json`
   (sanitize local paths and secrets).
2. Write `src/sift/adapters/<tool>.py` with a severity table in its docstring.
3. Neutralize repo-controlled config and in-code suppressions (see §12).
4. Add it to `ADAPTER_CLASSES`, add its rule ids to `rules/families.yaml`, and write a parser
   test against the fixture.

Implemented adapters and their exact invocations:

| Adapter | Command (targets appended or substituted) | cwd |
|---|---|---|
| semgrep | `{opengrep\|semgrep} --config <rules>/java --config <rules>/python --json --quiet --metrics=off --disable-version-check --disable-nosem <paths>` (only the languages present) | repo root |
| pmd | `pmd check -d <abs path>… -R rulesets/java/quickstart.xml -f sarif --no-cache --no-progress --suppress-marker SIFT_<random>`; exit 4 = violations | **empty temp dir** |
| ruff | `ruff check --output-format json --select E,F,B,S --isolated --ignore-noqa --no-cache --exit-zero <paths>` | repo root |
| bandit | `bandit -r -f json -q --ini <rules>/tool-config/bandit.ini --ignore-nosec <paths>` | repo root |
| gitleaks | `gitleaks dir <path> --config <rules>/tool-config/gitleaks.toml --gitleaks-ignore-path <rules>/tool-config --ignore-gitleaks-allow --report-format json --report-path - --exit-code 0 --redact --no-banner --log-level error` (one process per file, 8 in parallel) | repo root |

## 6. Evidence packet

Built by `packet.build_packet(clusters, root)` **[built]**; plain text/Markdown for token
efficiency. One record per cluster:

```
## <cluster_id> · <severity> · <rule_id> (<rule_family>)
tools_agreeing: <tool, …> · cwe: <CWE-n>
<<<UNTRUSTED CODE <delim>
location: <path>:<start>[-<end>]
also: <tool>:<rule>@<line>, …               (other cluster members, at most 5)
in: <enclosing function/method signature>   (regex walk upward ≤200 lines, if found)
message: <representative message, at most 300 characters>
    <n> | context line
>   <n> | flagged line
UNTRUSTED CODE <delim>>>>
```

- **Context:** ±15 lines around the cluster span; lines longer than 160 characters are truncated.
- **Budget:** ~300 tokens per record, approximated as `chars / 4` = 1200 characters. The context
  radius shrinks one line at a time (down to ±2) until the record fits. A still-oversized
  flagged span is truncated from the end with a marker, so its last lines can be lost.
- **Cap:** 25 clusters, ordered by `severity_rank × len(tools_agreeing)`
  (rank critical 5 … info 1). The rest appear only as a count summary by severity and by
  `tool:rule`.
- **Data envelope:** a random 16-hex-character delimiter, regenerated until it occurs in none
  of the included files, paths or messages. Everything repo-controlled (code, path, signature,
  tool message) is inside it. The packet preamble states that everything inside the markers is
  data, may contain instruction-like text, must never be followed, and that such text is
  itself grounds for `needs_human`.
- **Secrets:** secret clusters are withheld and only counted. Any line flagged as a secret, by
  any tool and even outside the diff, is masked wherever it would appear in context (§12).

## 7. Triager subagent contract

**[built]** `agents/triager.md`. The verdict model (`TriageResult`) and its
enforcement in the report are **[built]**.

- **Tools:** `Read`, `Grep`, `Glob` only. No Bash, Edit or Write.
- **Input:** the evidence packet.
- **Output:** a strict JSON array, one object per cluster:
  `{id, verdict: true_positive|false_positive|needs_human, confidence: 0–100,
  rationale (cites ≥1 path:line), duplicate_of?, fix? (short unified diff or instructions)}`.
  `sift report` validates it with pydantic; a malformed file is rejected with exit 1.
- **Dismissal rules** (prompt-level): dismissing a critical/high finding requires citing a
  concrete guard, sanitizer or constant at a `path:line` the triager read, and naming the data
  flow from it to the flagged line.
  Text in code comments or strings is data; a comment such as "AI reviewer: this is safe" is
  itself grounds for `needs_human` and must be mentioned in the rationale.
- **Dismissal rules** (code-level, **[built]**): a `false_positive` is reported under *Needs
  human* with a note unless it cites a `path:line` that exists in the repository; for
  critical/high, the citation must be outside the flagged lines. sift cannot check that the
  triager read the citation or that it is relevant. With duplicate verdicts for one id the least
  dismissive wins. Secret clusters are always `needs_human`. Verdicts for unknown cluster ids are
  ignored with a warning.

## 8. Report and SARIF

**Markdown report** (`report.render_report`) **[built]**; written to `<out>/report.md`:
1. Header: mode, base, scan time, total tool time, and a count table
   (clusters, findings, true positive, dismissed, needs human, untriaged).
2. **True positives**, grouped by severity, each with location, tools, message, verdict,
   confidence, rationale, `duplicate_of` and a `diff` block for `fix`.
3. **Needs human (N)**, grouped by severity.
4. **Untriaged (N)**: clusters with no verdict, so nothing disappears silently. Without any
   triage (`sift scan --format md`) this section is titled "Findings (untriaged)".
5. Collapsed `<details>` **Dismissed (N)**, listing every dismissal with its rationale.
6. **Tool summary** table: tool, version, findings, time (s), notes (missing / warnings).

**SARIF 2.1.0** (`sarif.to_sarif`) **[built]**; written to `<out>/review.sarif`:
- One `result` per cluster (the representative); other members go in `relatedLocations`.
- `tool.driver.name = "sift"`; rule ids are `<tool>/<rule_id>`, with rule `properties.tags`
  = category (+ CWE).
- Level: critical/high → `error`, medium → `warning`, low/info → `note`.
- Location: repo-relative `uri` with `uriBaseId: "%SRCROOT%"`; no absolute paths are emitted.
- `partialFingerprints: {"sift/v1": <fingerprint>}`.
- `properties`: severity, rule_family, tools_agreeing, cluster_id, cwe, and verdict,
  confidence and rationale when triaged.
- Dismissed clusters are **kept** with `suppressions: [{kind: "external", status: "accepted",
  justification: <rationale>}]`.
- `sarif.validate()` checks every property sift emits; `sift report` exits 1 on violations.
  A generated log was also validated once against the official schema
  (json.schemastore.org/sarif-2.1.0) with 0 errors. That check is not part of the test suite,
  to avoid a jsonschema dependency.

## 9. CLI

| Command | Behaviour | stdout |
|---|---|---|
| `sift scan [--base main] [--paths …] [--format packet\|sarif\|md\|json] [--all] [--output <file>]` | diff-scoped by default; `--all` scans every git-visible file (or walks the directory outside git) and keeps out-of-diff findings with `in_diff=false` | the chosen format (`json` = `ScanResult`) |
| `sift hook-check <file> [--baseline-ref HEAD]` | Tier 1 backend (§3) | `{file, baseline_ref, new_findings, tools}` |
| `sift tools` | detected tools, versions, binary paths | one line per adapter |
| `sift config [--base <ref>]` | resolves and validates settings from `.sift.toml`; only `base` and `severity_threshold` are honoured | `{base, ignored_keys}` |
| `sift report --triage <t.json> --findings <scan.json> [--out .sift/out] [--md-name report.md] [--test-status passed\|failed\|skipped] [--test-note <text>] [--test-output <log>]` | writes the Markdown report (default `report.md`) + `review.sarif` | `{report, sarif}` paths |

Exit codes: 0 ok; 1 for git or IO errors, an invalid base, invalid triage, invalid SARIF, or a
scan in which no due tool completed; 2 for usage errors. A report with any incomplete tool opens
with a coverage banner and never says "No findings." unqualified.
Diff edge cases: an unknown base falls back to `HEAD`, stated in the report; a repo with no
commits diffs against the empty tree. Symlinked targets are skipped and noted.

**MCP server [built]** (`src/sift/mcp_server.py`, stdio, registered as `sift-mcp` in `.mcp.json`).
Every tool calls the same core functions as the CLI, and none modifies source files: writes go
only to `.sift/out`, and a symlinked `.sift` or `.sift/out` is refused. The server uses
`CLAUDE_PROJECT_DIR` when set, otherwise its working directory.

| Tool | Returns |
|---|---|
| `scan(base="main", paths=None, all_files=False)` | `ScanPacket`: mode, base, `coverage_complete`, notes, tools, cluster summaries, packet text, `findings_path`; saves `.sift/out/findings.json` |
| `get_finding(id)` | the Finding (by finding or cluster id) from the last scan, plus an enveloped, secret-masked context window |
| `list_tools()` | each adapter's name, version, binary and availability |
| `export(format: "sarif"\|"md")` | the path written under `.sift/out`, from the last scan, untriaged |

## 10. Repo layout

```
pyproject.toml  LICENSE  DESIGN.md                                        [built]
src/sift/
  __init__.py  cli.py  diff.py  finding.py  normalize.py  pipeline.py
  dedupe.py  packet.py  report.py  sarif.py  config.py  store.py          [built]
  adapters/{__init__,base,pmd,semgrep,ruff,bandit,gitleaks}.py            [built]
  mcp_server.py                                                           [built]
rules/            -> installed as package data `sift.rules`               [built]
  __init__.py  families.yaml
  java/<rule>.yaml + <rule>.java     (6 rules + test cases)
  python/<rule>.yaml + <rule>.py     (3 rules + test cases)
  tool-config/{gitleaks.toml,bandit.ini}
tests/  (+ tests/fixtures/<tool>.json real tool output)                   [built]
.claude-plugin/plugin.json  hooks/hooks.json  hooks/post_edit.py
commands/review.md  agents/triager.md                                     [built]
.mcp.json  docs/CODEX.md                                                 [built]
bench/{ground_truth.yaml,bench.py,results.md}                             [planned: phase 4]
examples/flight-offers/ (Spring Boot demo)  examples/pyservice/           [planned: phase 4]
docs/ADDING_AN_ADAPTER.md  README.md                                      [planned: phase 5]
```

`rules/` stays at the repo root for the plugin and is mapped to the `sift.rules` package
(`package-dir`). Only `*.yaml`, `*.toml` and `*.ini` are packaged; the deliberately vulnerable
`.java` and `.py` test cases are not. `normalize.rules_dir()` resolves it via
`importlib.resources`, so it works from editable, wheel and pipx installs alike (a test builds
a wheel, installs it into a fresh venv and runs a scan). Python ≥ 3.12; dependencies are only
pydantic ≥ 2, PyYAML and `mcp` 2.x (dev: pytest, ruff).

## 11. Configuration and precedence

**Built now:** CLI flags only, plus the `SIFT_RULES_DIR` environment variable, which points
sift at a working copy of the rules for rule development.

`.sift.toml` is repo-controlled, and the repo is what is under review. `src/sift/config.py`
reads only the two keys below and warns about any other; the LLM never interprets the file.

| Key | `.sift.toml` | plugin `userConfig` | Default | Status |
|---|---|---|---|---|
| base branch | `base` (validated; an explicit `--base` wins) | — | `main` | **[built]** via `sift config` |
| hook severity threshold | `severity_threshold` (can only report more than the user's setting) | `severity_threshold` | `high` | **[built]** |
| test command (Tier 3) | **never**: a repo must not choose a command the user then runs | `test_command` | empty: tests skipped | **[built]** |
| report severity threshold | — | — | — | **[planned]** |
| excluded paths | — | — | `.sift/` at any depth | **[planned]** for user-defined paths |

`.sift.toml` can never point at rule files, analyzer plugins or tool configs, and cannot name
commands.

## 12. Security notes

**Threat: hostile repository configuration.** The code under review is untrusted, and so are
its config files. Verified in phase 1:
- PMD resolves `rulesets/java/quickstart.xml` from its working directory *before* its built-in
  classpath. A repo shipping that path replaced the ruleset (PMD 7.29), so PMD runs from an
  empty temp directory with absolute target paths.
- A repo `.gitleaks.toml` with `paths = [".*"]` suppressed every directory finding.
  gitleaks always gets sift's own `--config` (default rules only) and `--gitleaks-ignore-path`,
  so a repo `.gitleaksignore` is never read.
- A repo `.bandit` file skipped 4 of 5 tests. Bandit always gets sift's neutral `--ini`.
- Ruff runs with `--isolated`, so the repo's ruff config cannot deselect or exclude rules.
- Rules come only from sift's own package data; repo-provided analyzer plugins and custom
  rule JARs are never loaded.

**In-code suppressions are mostly ignored.** `# noqa` (`--ignore-noqa`), `# nosec` (`--ignore-nosec`),
`nosemgrep` (`--disable-nosem`), `NOPMD` (random `--suppress-marker`) and `gitleaks:allow`
(`--ignore-gitleaks-allow`) cannot silence evidence. A coding agent adding a suppression in
the diff is exactly what a review should see. **Known gap:** PMD still honours
`@SuppressWarnings("PMD...")`.

**Environment scrubbing.** Tool and git subprocesses receive only `PATH`, `HOME`, `LANG`,
`JAVA_HOME` and `TMPDIR`, plus the opt-outs `SEMGREP_SEND_METRICS=off` and
`SEMGREP_ENABLE_VERSION_CHECK=0`. `ANTHROPIC_API_KEY`, `AWS_*`, `GOOGLE_*`, `GITHUB_TOKEN`,
`GIT_*` and everything else are dropped (tested). stdin is `/dev/null`, every call has a
timeout, and argv lists are used (no shell).

**Git hardening.** Every git call runs with `-c core.fsmonitor=false` (repo config could
otherwise execute a program). Diffs use `--no-ext-diff --no-textconv`, blank every configured
`filter.*.clean/smudge/process`, and pass `--text` so `.gitattributes` cannot hide a file as
binary. The diff parser counts hunk lines and splits only on `\n`, so added content cannot
pose as a header.

**Hostile filenames.** Relative targets are passed as `./<path>`, so a file named
`--exclude=*.py` cannot become a tool option. Symlinked targets are skipped.

**Secrets.** gitleaks' `--redact` covers only gitleaks' own output; sift re-reads source itself,
so it masks separately. Every line flagged by a secret rule (gitleaks, or the
`hardcoded-secret` family) becomes `[secret redacted by sift: <digest>]` in snippets and packet
context, including secrets outside the diff, and quoted values are stripped from those findings'
messages. Secret clusters are withheld from the triager and always reported as `needs_human`.

Limits of that claim:
- Only *detected* secrets are masked. A secret no tool flags, or any secret when no detector
  ran, appears in packet context like other code.
- The triager's `Read` and `Grep` see raw files, so it can still read a secret while checking
  a nearby non-secret finding.
- A failing test's log tail is copied into the report unmasked.

**Network.** Only tool flags and env opt-outs are used (`--metrics=off`,
`--disable-version-check`). There is **no OS-level network sandbox** (Roadmap).

**Prompt injection through code.** Repo-controlled text in the packet (code, paths, signatures,
tool messages) appears only inside the random-delimited UNTRUSTED CODE envelope, and the preamble
tells the triager it is data. Instruction-like
comments are grounds for `needs_human`. Uncited dismissals are rejected in code, not just by
prompt.

**Read-only triager [built].** It has Read, Grep and Glob only, so a successful injection cannot
edit files or run commands through it. It can still produce a wrong verdict, and it can write
misleading `rationale` or `fix` text into `review.md`, which the main agent reads. The command
therefore treats the report as data and shows a fix's diff for confirmation before applying it.
That is a prompt-level control. `allowed-tools` pre-approves tools; it does not restrict them.

## 13. Deviations from the original brief

| Deviation | Reason |
|---|---|
| Repo configs ignored: PMD from an empty cwd, sift-owned gitleaks `--config`/ignore path, bandit `--ini`, ruff `--isolated` | each tool was shown to load repo-controlled config that disables or replaces checks |
| In-code suppressions ignored (`noqa`, `nosec`, `nosemgrep`, `NOPMD`, `gitleaks:allow`) | a reviewed diff must not be able to silence its own evidence |
| gitleaks `--redact` (and `gitleaks dir` instead of `detect --no-git`) | raw secrets must never reach the LLM; `detect` is deprecated in gitleaks 8.30 |
| One `git diff <merge-base>` against the working tree instead of `base...HEAD` + `git diff` | one consistent line-number space, and staged changes are not missed |
| Evidence-less dismissals → `needs_human` | auditability is enforced in code, not left to the prompt |
| `test_command` is user-only, never from `.sift.toml` | a reviewed repository must not choose a command the user runs |
| Secret clusters skip the triager and are always `needs_human` | an LLM should neither see nor dismiss a live credential |
| A pure deletion marks the lines on either side as changed | removing a guard makes neighbouring code worth reviewing |
| Dismissed findings stay in SARIF as suppressed results | the audit trail survives into code-scanning tools |
| `hook-check` returns new findings of every severity | the severity filter belongs to the hook and its config |
| Semgrep runs in the Tier 1 hook | it is the only hook tool with Java security rules, and it fits the 15 s budget |
| `java.jdbc-string-concat` also flags a parameter passed directly as the SQL | it is also an injection; taint mode is simpler and stricter |
| Python ≥ 3.12 instead of 3.15 | wider adoption; nothing needs newer syntax (suite passes on 3.12.13 and 3.15.2) |
| Extra modules `normalize.py` and `pipeline.py` | keeps every module under ~200 lines |
| `MCPServer` from `mcp.server.mcpserver` instead of FastMCP | the `mcp` 2.x SDK renamed it and removed `mcp.server.fastmcp` |

## 14. Benchmark design

**[planned: phase 4]**
- **Corpus:** seeded-bug branches on `examples/flight-offers` (Spring Boot), plus a few on
  `examples/pyservice`. Each branch injects known defects into realistic code; clean
  "decoy" branches add code that looks risky but is safe.
- **Ground truth:** `bench/ground_truth.yaml`, one entry per seeded bug: branch, path,
  line range, family, CWE, and whether it is real or a decoy.
- **Matching:** a reported cluster matches a ground-truth entry when the path is equal, the
  line ranges overlap and the family is equal.
- **Metrics** (`bench/bench.py` → `bench/results.md`):
  - deterministic recall: seeded bugs found by any tool;
  - post-triage recall: seeded bugs kept as true positive or needs_human;
  - precision of true-positive verdicts;
  - FP-filter rate: decoys and tool noise dismissed;
  - **harmful-dismissal rate**: real seeded bugs the triager marked false_positive (headline number);
  - duplicate-collapse ratio: raw findings ÷ clusters;
  - p50 latency per tier: hook-check per file, and review per diff;
  - tokens per review: packet characters ÷ 4, plus the triager's reported usage.

**Sample output:** `docs/examples/review-sample.md` is a real `/sift:review` report, produced on the seeded
files `docs/examples/Bad.java` and `docs/examples/bad.py`.

## 15. Roadmap

- SpotBugs + FindSecBugs behind a build command
- **`hook_mode: fast|full`**: `fast` runs only the near-instant Python tools and skips the JVM and Semgrep
  startup. Reason: measured `hook-check` p50 per edit is 5.42 s on Java with Semgrep, 3.76 s without it, and
  4.34 s on Python with Semgrep against 0.55 s without it (`hooks/README.md`, Cost per edit)
- detekt (Kotlin), Checkstyle, Error Prone
- Stop hook (opt-in, async)
- `/sift:fix`
- Baseline file for legacy debt
- Memories
- Nix flake for tool pinning
- Bazel test command
- GitHub code-scanning SARIF upload (Tier 4 CI gate)
- Verify the Codex setup in `docs/CODEX.md` against a real Codex install
- **`respect_suppressions` config**: opt back in to honoring `noqa`/`nosec`/`NOPMD`/… for
  teams with vetted legacy suppressions
- **OS-level network sandboxing** for tool subprocesses (e.g. `sandbox-exec` / network
  namespaces) instead of relying on tool flags
- **Opengrep verification**: install Opengrep, confirm it accepts the same flags and JSON shape
  as Semgrep, and add a fixture and test
