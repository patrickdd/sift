# sift hooks

## Verified against the Claude Code docs (2026-11-08, Claude Code 2.1.319)

Sources: code.claude.com/docs/en/hooks, plugins-reference (plugin manifest), plugins/loading,
sub-agents, slash-commands. "Tested" means observed in a live session, not only read in the docs.

| Topic | Confirmed |
|---|---|
| `plugin.json` | At `.claude-plugin/plugin.json`. Only `name` is required; `version`, `description`, `author` (`{name, email?, url?}`), `license`, `userConfig` and others are optional. |
| `userConfig` | **Supported.** Strict per-option schema: `type` (`string`/`number`/`boolean`/`directory`/`file`), `title` and `description` required; `default`, `required`, `options`, `multiple`, `sensitive`, `min`/`max` optional. |
| `userConfig` delivery | Hooks get `CLAUDE_PLUGIN_OPTION_<KEY>` (key uppercased). `${user_config.KEY}` is substituted in exec-form hook `args` and in skill and agent content. |
| `userConfig` defaults | **Tested:** a manifest `default` is not substituted. With no saved value, a command shows the literal `${user_config.KEY}`; a saved value is substituted. `commands/review.md` handles this explicitly. |
| `hooks.json` | `{"hooks": {"PostToolUse": [{"matcher": "...", "hooks": [{"type": "command", "command": "...", "args": [...], "timeout": <seconds>}]}]}}`. Default command timeout is 600 s. |
| Exec vs shell form | `args` present = exec form with no shell, so a path with spaces stays one argument. This plugin uses exec form. |
| PostToolUse stdin | Top level: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_use_id`, `duration_ms`. Path: `tool_input.file_path` (always absolute); also `tool_response.filePath` for Write. |
| Exit codes | Exit 2 on PostToolUse: stderr is shown to Claude and the tool has already run. Exit 0: "Claude never sees stderr". Other codes: non-blocking error notice. **Tested** for exit 2. |
| `matcher` | Only letters, digits, `_`, `-`, spaces, `,`, `\|`: exact names separated by `\|` or `,`. Any other character: unanchored JS regex. |
| Per-handler `if` | **Exists**, on tool events including PostToolUse. Permission-rule syntax, exactly one rule per handler. |
| `if` and tool names | **Tested (not stated in the docs):** a rule matches only its own tool, so `Edit(**/*.py)` does not fire for `Write`. `hooks.json` therefore has four handlers (Edit and Write, py and java). |
| `additionalContext` | Stdout JSON on exit 0: `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "..."}}`. Not used here; the brief calls for exit 2 and stderr. |
| `${CLAUDE_PLUGIN_ROOT}` | The plugin's install directory. Substituted in hook `command` and `args`, and exported to the hook process. Changes on update, so state must not live there. |
| Subagent tools | Frontmatter field `tools`, comma-separated or a YAML list. Plugin agents ignore `hooks`, `mcpServers` and `permissionMode`. Plugin agent id: `sift:triager`. |
| Local development | `claude --plugin-dir <path>` loads a plugin in place for one session (id `sift@inline`); `/reload-plugins` picks up edits. |

## Behaviour

`post_edit.py` reads the PostToolUse JSON and runs `sift hook-check <file>` with a 15 s overall
budget (the handler `timeout` of 20 s is only a backstop). The baseline is the file at `HEAD`.
It exits 2 with at most 5 `path:line [tool/rule] message` lines only for new findings at or above
the threshold, and exits 0 silently otherwise.

- **Threshold:** `.sift.toml` `severity_threshold`, then `severity_threshold` in `userConfig`, then `high`.
- **Disable:** set `hook_enabled` to false.
- **Requires:** `python3` (3.11+) and `sift` on `PATH`, or `SIFT_BIN` set to the executable.
- **Session cache:** `<tempdir>/sift-hook-<uid>/<sha256(session_id)>.seen` holds file-content keys,
  finding ids and message hashes. Findings cut by the 5-line limit are not marked as seen.
- **Failures:** any internal error exits 0 and is appended to `<tempdir>/sift-hook-<uid>/hook.log`.
  Missing analyzers are logged there too.

## PMD cold start and Tier 1 tool set

PMD 7.29.0 quickstart, one 19-line Java file, JDK 27, Apple Silicon, three runs:
**2.32 s, 1.79 s, 1.71 s (median 1.79 s)**. The limit is 4 s, so **PMD stays in the hook**.

The 19-line file is small; a large class will cost more.

Semgrep is also in the hook, changed from phase 1 (`single_file_ok` was False). In Java it is the
only hook tool with security rules.

## Cost per edit

Full `sift hook-check` wall time (current + baseline runs), three runs each, on small files. These
are the latency added to each matching Edit or Write whose content has not been checked yet.

| File | Without Semgrep | With Semgrep | p50 without | p50 with |
|---|---|---|---|---|
| Java (19 lines) | 4.29, 3.76, 3.76 s | 6.07, 5.42, 4.96 s | 3.76 s | 5.42 s |
| Python (small) | 0.73, 0.55, 0.55 s | 4.34, 4.38, 4.29 s | 0.55 s | 4.34 s |
