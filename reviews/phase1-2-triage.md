# Triage of reviews/phase1-2.md

`fix-now` means fixed in the commit "fixes from review 1-2". The 5 blockers and the envelope issue are all fixed, each with a regression test in `tests/test_review_regressions.py`.

## Major

- fix-now — git `filter.*` execution: every configured clean/smudge/process is blanked for the diff (tested).
- fix-now — no tool completed: `sift scan` exits 1, and the report opens with a coverage banner instead of "No findings."
- fix-now — base fallback: stated in the report through `ScanResult.notes`.
- fix-now — in:/message:/also:/location: outside the envelope: all moved inside; triager.md scope widened.
- fix-now — citation loophole: a cited file and line must exist, and critical/high must cite outside the flagged span.
- fix-now (part) — fake verdict payload: duplicate ids keep the least dismissive verdict. v0.2 for per-scan salted cluster ids, which need stored salt across scan and report.
- fix-now (part) — dismiss-everything and string payloads: triager must name the guard-to-line data flow. Phase 4 adds the three payloads to the benchmark, because only a live model can measure them.
- fix-now — report treated as instructions: command marks it as data, requires diff and confirmation; DESIGN corrected.
- fix-now (part) — /sift:review can modify files: `disallowed-tools: NotebookEdit` added, dead `Write(...)` rule dropped. v0.2 for confining `--output`, which needs a plugin-only mode so normal CLI use keeps working.
- fix-now — `<base>` shell expansion: `sift config` and `pipeline.scan` both validate it.
- fix-now — saved `$HOME/...` test command skipped: only the literal unfilled reference now counts as empty.
- fix-now — identical lines merge and widen: per-line occurrence ids, no range widening, comment-only text kept.
- fix-now — hook misses a second copy of a sink: baseline is deduped the same way, so occurrence ids count it.
- v0.2 — hook blames uncommitted user code: needs edited-region mapping from `new_string`, not a five-minute change.
- v0.2 — hook latency: baseline cache and Python Semgrep default change need re-measuring against the hooks/README numbers.
- fix-now — PMD naming rules at high: style rules capped at low.
- fix-now (part) — `@SuppressWarnings("PMD")`: documented as a known gap. v0.2 for a rule flagging new suppressions.
- fix-now — symlink targets: skipped and noted in the report.
- fix-now — hook crash on old Python: `__future__` annotations and lazy tomllib; verified on /usr/bin/python3 3.9.6.
- v0.2 — silent hook when sift or analyzers are missing: per-session `systemMessage` needs a live plugin session to verify.
- fix-now — `severity_threshold` type error and repo silencing: type checked; `.sift.toml` can only report more than the user's setting.
- fix-now — §11 mostly unbuilt: built keys moved to `config.py`, the rest marked planned.

## Minor

- v0.2 — repo-local tool binary on PATH: useful warning, but it needs a policy for legitimate project venvs.
- won't-fix — `SIFT_BIN` / `SIFT_RULES_DIR`: reaching them already requires workspace trust, and rule development needs them.
- won't-fix — `.semgrepignore`: reviewer found no defect.
- fix-now — Bandit B105 quoting the value: quoted literals stripped from every secret-category message.
- v0.2 — test log tail unmasked: needs a masker run on the log; limit documented in DESIGN §12.
- fix-now (part) — `.sift/out` and nesting: `.sift` excluded at any depth, snippets masked, `.gitignore` written on the MCP path. v0.2 for the CLI `--output` path.
- fix-now (part) — packet budget: message and `also:` capped. v0.2 for keeping the representative line in huge spans; DESIGN corrected.
- won't-fix — delimiter guessability: reviewer found no defect.
- v0.2 — severity x tools priority: overflow stays visible as Untriaged, so nothing is lost.
- won't-fix — fingerprint limits: accepted and documented; AST normalization is out of scope.
- won't-fix — touching ranges do not cluster: matches the documented "overlapping".
- v0.2 — diff edge cases (renames, CRLF flips, untracked binaries): each needs its own policy decision.
- v0.2 — `_unquote` on non-Latin-1 paths: needs `-z` based parsing and only triggers on unusual filenames.
- won't-fix — adapter failure matrix: reviewer recommends keeping it; the new coverage banner surfaces failures.
- fix-now — wrong-shape JSON and OSError: caught in `_run_one`, so one tool cannot kill a scan.
- v0.2 — Ruff `invalid-syntax` severity: current low avoids hook noise; align code and table together.
- v0.2 — jdbc-string-concat FP/FN: tune against phase 4 benchmark data.
- v0.2 — hardcoded-secret-value FP/FN: tune against phase 4 benchmark data.
- v0.2 — weak-hash FP/FN: tune against phase 4 benchmark data.
- v0.2 — cors-wildcard FP/FN: tune against phase 4 benchmark data.
- v0.2 — permit-all-sensitive FP/FN: tune against phase 4 benchmark data.
- v0.2 — runtime-exec-nonconstant FP/FN: tune against phase 4 benchmark data; the `sh -c` array miss goes first.
- v0.2 — sql-fstring FP/FN: tune against phase 4 benchmark data.
- v0.2 — yaml-unsafe-load FP/FN: tune against phase 4 benchmark data.
- v0.2 — subprocess-shell-true FP/FN: tune against phase 4 benchmark data.
- won't-fix — entry point test: it already skips when `sift` is not on PATH.
- v0.2 — hook state under `/tmp`: move to `CLAUDE_PLUGIN_DATA`, verified in a live plugin session.
- v0.2 — hook timeouts and files outside the project: need `CLAUDE_PROJECT_DIR` handling and a live check.
- v0.2 — `.sift.toml` lookup walks to `/`: fix together with the `CLAUDE_PROJECT_DIR` work.
- v0.2 — one handler instead of `if` rules: the current form was verified live, and the conflict is untested.
- v0.2 — repeat behaviour docs: session scope corrected in DESIGN; `sed -i` bypass and reintroduced findings go in the README.
- v0.2 — two scans per review: one call writing both outputs is a CLI change, and the failure mode is visible as untriaged.
- won't-fix — failing tests and invalid triage flow: reviewer found no defect.
- v0.2 — plugin README and minimum version: README is a phase 5 deliverable.
