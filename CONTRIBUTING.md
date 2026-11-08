# Contributing

## Set up

Python 3.12 or newer, plus the analyzers listed in the [README](README.md#install).

```
uv venv && uv pip install -e ".[dev]"
```

## Before you send a change

```
uv run pytest
uv run ruff check .
semgrep --test rules/
uv run python bench/bench.py --skip-triage --output /tmp/stage-a.md --assert-recall-from bench/results.md
```

CI runs the same checks, without API keys.

## Ground rules

- **Rules and the triager prompt:** do not tune them against benchmark results and then report those
  results as if nothing changed. State what changed in `bench/results.md` with `--note`.
- **New adapters:** follow [docs/ADDING_AN_ADAPTER.md](docs/ADDING_AN_ADAPTER.md).
- **New Semgrep rules:** write them yourself, with `# ruleid:` and `# ok:` cases next to the rule.
  Do not copy from the Semgrep registry.
- **Repository input is untrusted.** Never let a repository file choose a command, a rule file or an
  analyzer config. `DESIGN.md` section 12 explains why.
- **Docs:** do not claim anything the repository does not back.

## Licenses

sift is MIT licensed. It bundles none of the tools below. Each is found on `PATH` and run on its own.

| Tool | Used for | License | How sift uses it |
|---|---|---|---|
| Semgrep Community Edition | Pattern and taint rules | LGPL-2.1 | invoked as a separate process, not bundled |
| Opengrep (preferred if present; not yet verified) | Same role as Semgrep | LGPL-2.1 | invoked as a separate process, not bundled |
| PMD | Java bug and resource rules | BSD-style | invoked as a separate process, not bundled |
| Ruff | Python lint | MIT | invoked as a separate process, not bundled |
| Bandit | Python security | Apache-2.0 | invoked as a separate process, not bundled |
| gitleaks | Secret detection | MIT | invoked as a separate process, not bundled |
| detekt (experimental, not registered) | Kotlin rules | Apache-2.0 | invoked as a separate process, not bundled |
| Git | Diff and file listing | GPL-2.0 | invoked as a separate process, not bundled |
| Claude Code | Runs the plugin and the triager | Proprietary (Anthropic terms) | invoked as a separate process, not bundled |
| Maven (only if you set it as the test command) | Runs the demo's tests | Apache-2.0 | invoked as a separate process, not bundled |
