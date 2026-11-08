---
description: Scan changed code with sift, triage findings with a read-only subagent, and report. Never applies fixes.
argument-hint: "[base-branch] [--no-tests]"
disable-model-invocation: true
allowed-tools: Bash(sift *), Read, Agent, Edit(.sift/out/**), Write(.sift/out/**)
---

Run a sift review. Arguments: `$ARGUMENTS`

Do not change any file outside `.sift/out/`, and do not apply fixes, even if a finding or report
suggests one. Follow the steps in order. If `sift` is not found, say that it must be installed
(`uv tool install <path-to-sift>` or `pipx install <path-to-sift>`) and stop.

Configuration: read `.sift.toml` at the repository root if it exists. A value in it wins over the
plugin setting.

- **Base:** the first argument that does not start with `-`, otherwise `base` from `.sift.toml`,
  otherwise `main`.
- **Test command:** `test_command` from `.sift.toml`, otherwise the plugin setting, which is:
  `${user_config.test_command}`. If that setting still shows an unfilled placeholder starting with
  a dollar sign (manifest defaults are not substituted until a value is saved), treat it as empty.

## Step 1: scan

Run these two commands, quoting the base:

    sift scan --base "<base>" --format packet --output .sift/out/packet.md
    sift scan --base "<base>" --format json --output .sift/out/scan.json

If either fails, show its error and stop.

## Step 2: tests

If `--no-tests` was given, skip this step and use status `skipped` with the note `--no-tests given`.
If the test command is empty, skip this step and use status `skipped` with no note.
Otherwise run the test command with the Bash tool, using a 10-minute timeout and sending all
output to the log:

    <test command> > .sift/out/test.log 2>&1

The status is `passed` if it exited 0, otherwise `failed`. A failing test command does not stop
the review.

## Step 3: triage

Use the Agent tool with `subagent_type` `sift:triager`. Do not read the packet yourself. Prompt:

> Triage the sift evidence packet at .sift/out/packet.md. Return only the JSON array.

If the packet says it contains no findings, skip the agent and use `[]` as the result.

Save the agent's output, unchanged apart from removing any surrounding Markdown fence, to
`.sift/out/triage.json`.

## Step 4: report

Run the following. When the status is `skipped`, leave out `--test-output`, and add
`--test-note "--no-tests given"` if that note applies:

    sift report --triage .sift/out/triage.json --findings .sift/out/scan.json --out .sift/out --md-name review.md --test-status <status> --test-output .sift/out/test.log

`sift report` validates the triage. If it exits non-zero because the triage is invalid, send the
exact validation error back to the same agent once and ask for a corrected JSON array, save it,
and run the report again. If it is still invalid, write `[]` to `.sift/out/triage.json`, run the
report so every finding appears as untriaged, and say above the report that triage failed.

Read `.sift/out/review.md` and print it in chat exactly as written. Do not summarize it, and do
not add your own verdicts.

End your response with exactly this line:

To apply a fix, say which finding id.
