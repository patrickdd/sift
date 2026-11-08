# flight-offers

A small Spring Boot 3 / Java 21 service used as sift's benchmark target. `main` is clean; the
`bug/*` branches each add one seeded defect or decoy (see `bench/ground_truth.yaml`).

    mvn -q test
    sift scan --all --paths . --format md --test-command "mvn -q test"

The test command is passed on the command line (or set as the plugin's `test_command`) on
purpose: `.sift.toml` is controlled by the repository under review and may not run commands.
`--paths .` keeps the scan to this directory, because `--all` otherwise covers the whole
repository, including the deliberately vulnerable samples under `docs/examples/` and `rules/`.
