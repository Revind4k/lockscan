# lockscan

Finds known vulnerabilities in the exact dependency versions your lockfiles pin, using the [OSV.dev](https://osv.dev) database. One static Go binary; also runs as a GitHub Action that uploads results to code scanning.

```
$ lockscan ~/Developer/job-tracker-api
lockscan: 186 packages from 1 lockfiles
10 vulnerabilities in 186 packages (3 critical, 5 high, 2 medium)

SEVERITY      PACKAGE                                    VERSION  FIXED IN                   ID
CRITICAL 9.8  org.apache.tomcat.embed:tomcat-embed-core  11.0.24  11.0.25, 10.1.58, 9.0.121  GHSA-9xv2-5v5q-p794
CRITICAL 9.1  org.apache.tomcat.embed:tomcat-embed-core  11.0.24  11.0.25, 10.1.58, 9.0.121  GHSA-gcx9-497g-6cp6
CRITICAL 9.1  org.apache.tomcat.embed:tomcat-embed-core  11.0.24  11.0.25, 10.1.58, 9.0.121  GHSA-h3x4-894j-xpx5
HIGH 7.5      tools.jackson.core:jackson-core            3.1.5    3.1.7, 3.2.3               GHSA-7hhh-6rmp-j9qf
...
```

That's a real scan of one of my own projects. The three critical Tomcat issues were authentication bypasses pulled in by the newest Spring Boot release; the fix was [one commit](https://github.com/Revind4k/job-tracker-api/commit/b40af6a) and a re-run of the test suite.

## Supported lockfiles

| File | Ecosystem | Notes |
|---|---|---|
| `package-lock.json` (v2/v3) | npm | nested duplicates at different versions are each checked |
| `uv.lock` | PyPI | the project itself (editable/virtual source) is skipped |
| `requirements.txt` | PyPI | only exact `==` pins; ranges can't be checked without resolving |
| `pubspec.lock` | Pub (Dart/Flutter) | SDK, path and git packages are skipped |
| `go.mod` | Go | |
| `gradle.lockfile` | Maven | enable with `dependencyLocking { lockAllConfigurations() }` |
| `Package.resolved` | SwiftPM | |
| `Cargo.lock` (v3/v4) | crates.io | workspace members and git crates are skipped |

Directories are searched recursively, skipping `node_modules`, `.venv`, `vendor`, `build` and similar.

## Usage

```bash
go install github.com/Revind4k/lockscan/cmd/lockscan@latest

lockscan                          # scan the current directory
lockscan --fail-on critical .     # exit 1 only for critical findings (default: high)
lockscan --format json .          # machine-readable
lockscan --format sarif --output lockscan.sarif .
lockscan --ignore GHSA-xxxx-xxxx-xxxx,CVE-2024-1234 .   # by ID or any alias
```

Exit codes: `0` nothing at or above `--fail-on`, `1` at least one finding at or above it, `2` usage or lookup error. A failed lookup is never reported as "no vulnerabilities".

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # for the SARIF upload
steps:
  - uses: actions/checkout@v5
  - uses: Revind4k/lockscan@main
    with:
      fail-on: high
```

Findings appear under the repository's Security → Code scanning tab, each located on the lockfile that pins the package, and the table is written to the job summary.

## How it works

```
parse (8 formats) → dedupe → POST /v1/querybatch ──→ IDs per package
                               (≤1000 per request,      │
                                follows page tokens)     ▼
                     GET /v1/vulns/{id}  ← worker pool (8), disk cache keyed by id + modified
                               │
                     enrich: no rating? look up GHSA / CVE aliases
                               │
                     merge aliases per package → score → table | JSON | SARIF
```

- **Two-step lookup.** `querybatch` returns only IDs, so full records are fetched separately, once per distinct advisory, by a bounded worker pool. Records are cached on disk under their `modified` timestamp, so an updated advisory is refetched and an unchanged one never is.
- **Failure handling.** Each request has a timeout; 429s, 5xx and network errors retry with jittered exponential backoff; other 4xx fail immediately. The whole scan has a deadline (`--timeout`), and the first worker error cancels the rest.
- **Severity.** OSV ships CVSS vectors, not scores, so lockscan computes the CVSS v3.0/3.1 base score itself (tested against NVD's calculator). Without a vector it falls back to the database's own label (GitHub's `MODERATE` and so on).
- **Borrowed ratings.** The Go vulnerability database publishes no severity at all, by policy. For records with no usable rating, lockscan looks up their GHSA or CVE aliases and borrows that rating, marking the row with `*` and recording the source (`severity_from` in JSON) so it never claims a rating the advisory doesn't carry. On the test fixtures this took unrated findings from 23 to 8; the 8 left are recent Go advisories nobody has rated yet.
- **Alias merging.** The same issue is often published as `GHSA-…`, `PYSEC-…` or `GO-…`, plus a `CVE-…`. Findings for one installed package are merged with union-find over IDs and aliases, keeping the best-rated record and folding in the others' IDs and fix versions. On the fixtures, 64 raw findings became 48 distinct issues.

## Dogfooding

On my four public projects that have lockfiles (npm, uv, Gradle), lockscan found the Tomcat/Jackson issues above and nothing else.

## Tests

`go test -race ./...` runs with no network: parser fixtures for every format, CVSS scores checked against NVD, alias merging, and an `httptest` fake of the OSV API covering batching past 1,000 packages, pagination, retries, non-retryable 404s, the cache, alias enrichment, and deadline handling. CI also scans this repo with its own Action.

## Limits

- `FIXED IN` lists every fixed version OSV gives, across release lines (e.g. `11.0.25, 10.1.58, 9.0.121`); pick the one on your line. When advisories merge, upgrade to the highest one shown.
- CVSS v4 vectors aren't scored yet; those rows use the label or an alias's rating.
- Only what's pinned is checked. `requirements.txt` ranges and Maven/Gradle builds without a lockfile need resolving first.

MIT License.
