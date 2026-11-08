# Adding an adapter

An adapter connects one analysis tool to sift. It says how to run the tool and how to turn the
tool's output into sift's `Finding` records. Everything after that (dedupe, clustering, the evidence
packet, triage and the report) works without further changes.

This guide states the contract, then walks through adding [detekt](https://detekt.dev) for Kotlin.

> **Status of the detekt example.** `src/sift/adapters/detekt.py` is real code, but it is
> **experimental and untested**: detekt was not installed when it was written. Its command comes from
> detekt's CLI documentation, its fixture is hand-written, and it is not registered, so sift does not
> run it. sift does not support Kotlin yet.

## The contract

`src/sift/adapters/base.py` defines it:

```python
class Adapter(Protocol):
    name: str
    languages: tuple[str, ...]   # file suffixes, or ("*",) for any file
    single_file_ok: bool         # may run in the edit hook
    def version(self) -> str: ...
    def run(self, paths: list[str], repo_root: Path) -> list[Finding]: ...
```

Most adapters subclass `ToolAdapter`. You set a few attributes and write two methods:

| You provide | Purpose |
|---|---|
| `name`, `binaries`, `languages` | Tool name, executables to look for (first match wins), file suffixes |
| `single_file_ok` | `True` only if a one-file run fits the hook's budget (see `hooks/README.md`) |
| `ok_returncodes` | Exit codes that mean "ran normally". Many tools exit non-zero when they find something |
| `commands(binary, paths, repo_root)` | A list of argv lists. Never a shell string |
| `parse(stdout, repo_root, version)` | Turn the tool's JSON or SARIF into findings with `make_finding(...)`. No screen-scraping |
| `cwd(repo_root)` (optional) | Working directory for the tool. Override it if the tool reads config from there |

The base class handles the rest: finding the binary on a scrubbed `PATH`, caching the version,
filtering files by suffix, timeouts, and carrying on when something goes wrong. A missing binary, an
unexpected exit code or unparseable output becomes a warning in the report, and the scan continues.

Three rules matter more than the rest:

1. **The repository under review is untrusted, and so is its config.** A repository must not be able
   to turn off checks. Point the tool at sift's own config or none, and run it where it cannot find
   the repository's config. `DESIGN.md` section 12 lists what each tool did when this was tested.
2. **In-code suppressions must not silence findings** if the tool has a flag for that. If it has
   none, write the gap down in the adapter's docstring.
3. **Use real output in the fixture.** Run the tool on a tiny file, save what it prints, and remove
   local paths and secrets. The detekt fixture breaks this rule because detekt was not available,
   which is why that adapter is marked untested.

## Worked example: detekt

### 1. The command

```
detekt --input /abs/App.kt:/abs/Other.kt --report sarif:/tmp/sift-detekt-x/detekt.sarif
```

- `--input` takes absolute paths separated by `:`, according to the current docs. Older detekt
  releases may use a different separator, so check this against the version you install.
- `--report sarif:<path>` writes the report to a file. detekt prints other text on stdout, so the
  adapter reads the file instead.
- There is no `--config`, so detekt uses its defaults. The adapter runs from an empty temp directory.
- Documented exit codes: 0 no issues, 1 unexpected error, 2 issues found, 3 invalid config. That gives
  `ok_returncodes = (0, 2)`.

### 2. The output shape

SARIF 2.1.0. The parser uses these fields. The `ruleId` form below is an assumption to confirm
against real output, because detekt's docs do not show a sample:

```json
{ "runs": [ { "tool": { "driver": { "version": "…" } },
    "results": [ {
      "ruleId": "detekt.potential-bugs.UnsafeCast",
      "level": "error",
      "message": { "text": "…" },
      "locations": [ { "physicalLocation": {
        "artifactLocation": { "uri": "src/App.kt" },
        "region": { "startLine": 2, "endLine": 2 } } } ]
    } ] } ] }
```

### 3. The severity mapping

Write the table in the adapter's docstring, so a reader can check it against the code.

| SARIF level | sift severity | Note |
|---|---|---|
| `error` | medium | detekt gives most rules the same default level, so a level alone does not justify high |
| `warning` | low | |
| `note` | info | |

Style-like rule sets are capped at low, so they never interrupt an edit through the hook.

| detekt rule set | sift category |
|---|---|
| `potential-bugs`, `exceptions`, `coroutines` | bug |
| `performance` | resource |
| anything else | style |

### 4. The adapter

See [`src/sift/adapters/detekt.py`](../src/sift/adapters/detekt.py). The core:

```python
class DetektAdapter(ToolAdapter):
    name = "detekt"
    binaries = ("detekt", "detekt-cli")
    languages = (".kt", ".kts")
    single_file_ok = False       # JVM cold start not measured
    ok_returncodes = (0, 2)      # 2 = at least one issue found
```

Known gap: detekt has no documented flag to ignore `@Suppress` annotations, so a change could silence
its own finding. The docstring records this.

### 5. The fixture

`tests/fixtures/detekt.handwritten.json` has one bug rule and one style rule. Its name says it is
hand-written. Replace it with real output and rename it `detekt.json` when you verify the adapter.

### 6. The test

`tests/test_detekt_adapter.py` checks three things: the severity and category mapping, that the tool
runs from a neutral directory with absolute paths and no `--config`, and that the adapter stays
unregistered until someone verifies it. Remove that last test when you register it.

### 7. `rules/families.yaml`

A family groups rule ids from different tools that describe the same defect, so they cluster into
one finding. A rule that has no family still works: it gets the family `detekt:<rule_id>`. Add entries
only where another tool reports the same problem. For example, to merge detekt's empty-catch rule
with PMD's, extend the existing family (not yet applied, since the adapter is not active):

```yaml
  empty-catch:
    category: bug
    cwe: CWE-390
    members:
      pmd: [EmptyCatchBlock]
      bandit: [B110]
      ruff: [S110]
      detekt: [EmptyCatchBlock]   # add this line
```

The rule id in the family must match what `parse` passes as `rule_id`.

### 8. Registration

Add the class to `src/sift/adapters/__init__.py`:

```python
from sift.adapters.detekt import DetektAdapter

ADAPTER_CLASSES: tuple[type[ToolAdapter], ...] = (
    SemgrepAdapter,
    PmdAdapter,
    RuffAdapter,
    BanditAdapter,
    GitleaksAdapter,
    DetektAdapter,
)
```

`sift tools` then lists it, and scans run it for `.kt` and `.kts` files.

## Finish the job

To move detekt from experimental to supported:

1. Install detekt and run the command above on a small Kotlin file.
2. Confirm the `--input` separator, the exit codes and the `ruleId` format.
3. Save the real SARIF as `tests/fixtures/detekt.json` with local paths removed, and point the test at it.
4. Check whether a repository file can change detekt's behaviour when it runs from a temp directory.
5. Register the adapter, add the family entries, and add Kotlin seeds to the benchmark.
6. Update "Supported languages and tools" in the README.
