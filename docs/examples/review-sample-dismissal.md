# sift review

mode: `diff` · base: `main` · scanned: `2026-11-08T23:36:39+00:00` · tool time: 4.0s

| Clusters | Findings | True positive | Dismissed | Needs human | Untriaged |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 0 | 1 | 0 | 0 |

## Tests: passed

<details>
<summary>Dismissed (1)</summary>

- **java.permit-all-sensitive** (missing-authorization · CWE-862) `examples/flight-offers/src/main/java/com/example/flightoffers/SecurityConfig.java:20` — semgrep
  permitAll() is applied to a sensitive path ("/actuator/health"). Admin/internal endpoints should require authentication and an explicit role.
  - *false_positive, confidence 85:* The matcher at src/main/java/com/example/flightoffers/SecurityConfig.java:20 opens only the exact path /actuator/health. It has no wildcard, so other paths fall through to anyRequest().authenticated() at SecurityConfig.java:23, and /admin/** stays role-gated at SecurityConfig.java:21. The concrete guard is the actuator configuration at src/main/resources/application.yaml:15-19: exposure include at application.yaml:19 limits the web actuator to the health endpoint, and that block sets no management.endpoint.health.show-details or show-components. The endpoint reached through the permitAll at SecurityConfig.java:20 therefore keeps the Spring Boot 3.5.7 (pom.xml:10) default of show-details=never, so an anonymous caller gets only the aggregate UP/DOWN status, with no component details, and no custom health contributors exist in src. No sensitive data or privileged operation is reachable through this rule, so CWE-862 does not apply at this severity. Residual caveat: a deployment environment variable could enable show-details, but nothing in the repository does.
  <sub>C-a3f32bcf3c</sub>

</details>

## Tool summary

| Tool | Version | Findings | Time (s) | Notes |
|---|---|---:|---:|---|
| semgrep | 1.184.0 | 1 | 1.9 |  |
| pmd | 7.29.0 | 0 | 1.9 |  |
| ruff | 0.17.4 | 0 | 0.0 |  |
| bandit | 1.9.4 | 0 | 0.0 |  |
| gitleaks | 8.30.1 | 0 | 0.1 |  |
