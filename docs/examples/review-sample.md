# sift review

mode: `diff` · base: `main` · scanned: `2026-11-08T23:35:36+00:00` · tool time: 4.1s

| Clusters | Findings | True positive | Dismissed | Needs human | Untriaged |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 0 | 0 | 0 |

## Tests: passed

## True positives

### High (1)

- **java.jdbc-string-concat** (sql-injection · CWE-89) `examples/flight-offers/src/main/java/com/example/flightoffers/OfferRepository.java:40` — semgrep
  SQL passed to query() is built from method parameter 'destination' (concatenation, String.format, or passed directly). Use bind parameters (? or :name) instead.
  - *true_positive, confidence 98:* Unauthenticated SQL injection. src/main/java/com/example/flightoffers/OfferRepository.java:37-38 concatenates `origin` and `destination` into the SQL string, which is executed at OfferRepository.java:40 with no bind parameters. Both values come straight from `@RequestParam` at src/main/java/com/example/flightoffers/OfferController.java:26-27. The only processing on the way is `trim()` at src/main/java/com/example/flightoffers/OfferService.java:22, which does not neutralize quotes. The `requireIata` validator at OfferService.java:35-40 is applied only in `create` (OfferService.java:30-31), not in `search`, and no other validation on these parameters was found under src. src/main/java/com/example/flightoffers/SecurityConfig.java:21 permits GET /offers to anonymous callers, so a single quote in either parameter breaks out of the literal and allows, for example, UNION-based reads of other tables. Both parameters are injectable, although the tool message names only `destination`.
  - fix:

    ```diff
    --- a/src/main/java/com/example/flightoffers/OfferRepository.java
    +++ b/src/main/java/com/example/flightoffers/OfferRepository.java
    @@ -36,5 +36,5 @@
             String sql = SELECT_OFFER
    -                + " WHERE UPPER(origin) = UPPER('" + origin + "')"
    -                + " AND UPPER(destination) = UPPER('" + destination + "')"
    +                + " WHERE UPPER(origin) = UPPER(?)"
    +                + " AND UPPER(destination) = UPPER(?)"
                     + " ORDER BY price";
    -        return jdbc.query(sql, OFFER_MAPPER);
    +        return jdbc.query(sql, OFFER_MAPPER, origin, destination);
         }
    ```
  <sub>C-845fc615d9</sub>

<details>
<summary>Dismissed (0)</summary>


</details>

## Tool summary

| Tool | Version | Findings | Time (s) | Notes |
|---|---|---:|---:|---|
| semgrep | 1.184.0 | 2 | 2.0 |  |
| pmd | 7.29.0 | 0 | 2.1 |  |
| ruff | 0.17.4 | 0 | 0.0 |  |
| bandit | 1.9.4 | 0 | 0.0 |  |
| gitleaks | 8.30.1 | 0 | 0.1 |  |
