# Darth Scanner — Web & Server Security Scanner

A conventional Python security scanner for websites and server software you own or are explicitly authorized to assess. **No AI, LLMs, or generative analysis.** Detection is implemented through deterministic HTTP/TLS checks, passive software fingerprints, local CVE data, and bounded fuzzing.

> No scanner can guarantee a fixed number of vulnerabilities. Bug-Free Sniffle reports observed weaknesses and candidate CVE matches with evidence; it never invents findings to reach a target count.

## Version 1.0.0 capabilities

### 1. Coverage-guided route and parameter research

The new `research` command:
- Crawls a bounded number of pages and extracts query-bearing links from already-fetched same-origin HTML.
- Finds existing query parameter names without submitting forms or executing scripts.
- Skips URLs containing parameter names that look like credentials, tokens, sessions, secrets, or signatures.
- Distributes a shared mutation budget across discovered endpoints and parameters.
- Uses only the existing low-rate, benign GET mutation corpus and exact-host authorization scope.
- Stops at the scope request budget; no redirects are followed and no non-GET methods are sent.
- Writes each tested endpoint, parameter, benign mutation value, baseline hashes, and response hashes to JSON so a suspicious case can be reconstructed.

Example:
```powershell
darth-scanner research --target "https://your-authorized-host.example/" --scope ".\\scope.json" --acknowledge-authorization --max-pages 12 --max-targets 30 --max-cases 32 --output ".\\darth-research-report.json"
notepad .\\darth-research-report.json
```

This mode only tests query URLs found in same-origin links and pages. It does not infer hidden routes or submit HTML forms. A GET endpoint can still be state-changing if an application is incorrectly designed; only run this against systems where this bounded testing is authorized.

To replay one exact benign mutation recorded in the JSON report, use its `endpoint_url`, `parameter`, and `case` fields:
```powershell
darth-scanner replay --url "https://your-authorized-host.example/search?q=hello" --param "q" --case "empty" --scope ".\\scope.json" --acknowledge-authorization --output ".\\darth-replay-report.json"
notepad .\\darth-replay-report.json
```
Replay accepts only named values from the built-in benign corpus and sends exactly one GET request.

### 2. Website security checks

- Bounded same-origin HTML crawling. Forms are never submitted and JavaScript is never executed.
- HTTP security headers: CSP, HSTS, MIME sniffing protection, Referrer-Policy, Permissions-Policy, and clickjacking controls.
- CSP analysis: unsafe-inline, unsafe-eval, wildcard script sources, missing object-src, base-uri, and frame-ancestors.
- CORS observations: wildcard origins, null origins, and credential-policy combinations.
- Cookie analysis: Secure, HttpOnly, SameSite, SameSite=None without Secure, and __Host-/__Secure- prefix rules.
- Cache-control review when responses set cookies.
- HTML checks: mixed content, password forms using GET or non-HTTPS actions, cross-origin password form actions, external scripts without SRI, and target-blank links without opener isolation.
- Redirect checks: HTTPS-to-HTTP downgrade redirects and cross-origin redirects. Redirects are never followed and an external redirect is not automatically labelled an open redirect.
- Authentication check: Basic authentication advertised over plaintext HTTP.
- Error and information disclosure: directory-index signatures, common debug pages, stack traces, database error messages, and server 5xx responses.
- HTTP method discovery through OPTIONS. TRACE, PUT, DELETE, and CONNECT are reported only when advertised; the scanner does not invoke these methods.

### 3. Exposed configuration and backup discovery

The scanner sends **HEAD requests only** to a bounded list of likely sensitive paths, such as:

- Environment files and local/production variants.
- Git, Subversion, and Mercurial metadata.
- Private SSH key filenames.
- Common application configuration backups.
- SQL dump and backup archive filenames.
- PHP diagnostic page and common operating-system metadata.

It records only response status and headers such as Content-Type and Content-Length. It does **not** download, parse, save, or display file contents. If a server returns a generic HTML fallback for every path, the result is marked low-confidence and requires manual verification. HEAD support varies by server; a negative HEAD result does not prove that a file is absent or inaccessible through GET.

### 4. TLS and certificate assessment

- Verified certificate-chain and hostname handshake.
- Certificate expiration and near-expiration checks.
- Protocol-specific handshakes for TLS 1.0, 1.1, 1.2, and 1.3.
- Reports when deprecated TLS 1.0 or TLS 1.1 accepts a handshake.
- A restricted handshake against selected legacy cipher families (RC4, 3DES/DES, NULL, export-grade, anonymous, and MD5-based suites).
- Records the negotiated protocol and cipher suite.

The local Python/OpenSSL build may not include obsolete cipher implementations. If a legacy cipher cannot be offered by the scanner itself, that cipher test is reported as not observable rather than a clean result. Protocol negotiation is based on the scanner's TLS implementation and network path; this is not a complete cryptographic compliance certification. TLS guidance reference: [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final). NIST announced a review of this publication in May 2026; this scanner reports observed capabilities rather than claiming formal compliance.

### 5. Server and software fingerprints

Versioned response-header fingerprints now include nginx, Apache HTTP Server, PHP, Microsoft IIS, OpenSSL, OpenResty, Caddy, lighttpd, HAProxy, Envoy, Traefik, Eclipse Jetty, Apache Tomcat, Gunicorn, Uvicorn, Varnish Cache, and Node.js.

Fingerprints are based on publicly returned headers and can be hidden, spoofed, or altered by reverse proxies. A missing fingerprint does not mean that software is absent. Use a trusted software inventory or SBOM for better coverage.

### 6. CVE intelligence and CVSS severity

- Matches CPE 2.3 software inventory against a local NVD 2.0 JSON feed.
- Uses NVD affected CPE criteria and numeric dotted-version boundaries where supported.
- Includes CVE ID, English description, CVSS version, base score, vector, severity, matched software/version evidence, and NVD/advisory links.
- Uses detected software fingerprints and optional user-provided inventory.

CVSS severity bands:
- **Critical:** 9.0–10.0 (CVSS v3.x/v4.0)
- **High:** 7.0–8.9
- **Medium:** 4.0–6.9
- **Low:** 0.1–3.9

CVSS v2 has no Critical tier; scores 7.0–10.0 are High.

**CVE matches are candidates, not proof of exposure.** A product banner may be spoofed, NVD configuration expressions can require additional platform conditions, and vendors sometimes backport fixes without changing the upstream version string. Verify the exact vendor build, platform conditions, and advisory before treating a match as exploitable.

### 7. Adaptive differential fuzzing

- Fuzz one exact query parameter or use `--param "*"` to cover up to 8 existing parameters in the supplied URL.
- Uses up to 32 total bounded, benign values across parameters, including type, encoding, Unicode, and length-boundary cases.
- Captures a per-parameter baseline and compares status, response-body hash, content type, redirect Location, response size, latency, diagnostic signatures, and input reflection.
- Every observation includes the baseline hash and structured anomaly flags in JSON.
- One request at a time with the scope's minimum delay and shared request budget. No forms, uploads, credentials, redirect following, exploit payloads, or state-changing methods.
- A changed response is only a lead: dynamic pages, personalization, and cache behavior can cause harmless differences. Reproduce and inspect manually.

### 8. Response-behavior and parser-ambiguity research

The scanner now passively inspects response bodies already collected by the bounded crawler for:
- Duplicate JSON object member names, which can be interpreted differently by different parsers.
- Successful JSON responses that contain HTML, malformed JSON, or inconsistent media types.
- Successful responses containing generic exception/diagnostic signatures.
- Evidence is limited to the anomaly description; response bodies, JSON values, and duplicate member names are not copied into findings.

These checks add protocol and parser-differential coverage without sending additional requests. A duplicate key or media-type mismatch is a bug candidate, not automatically a security vulnerability. Confirm how the actual application, API gateway, and downstream consumers parse the response.

### 9. Multi-language local source review

The `audit-code` command performs deterministic static analysis of local Python source files you own. It does not execute your application or any code it scans. It looks for review leads such as:

- Dynamic code execution through eval/exec.
- Potential unsafe pickle/dill/marshal and YAML deserialization.
- Shell-enabled subprocess calls and OS shell APIs.
- SQL statements assembled with f-strings or concatenation.
- Dynamically supplied HTTP request URLs that may need SSRF controls.
- Dynamic filesystem paths that need traversal review.
- Disabled TLS certificate verification.
- Hard-coded credential-like assignments (values are redacted in findings).
- Legacy MD5/SHA-1 hashing.

These are heuristic findings, not confirmed zero-days. Static analysis cannot prove whether input is attacker-controlled or whether a vulnerable path is reachable. The current source auditor supports Python only; other languages are not silently treated as audited.

An unknown vulnerability can also be investigated through the bounded `fuzz` command on an explicitly authorized endpoint. It compares responses and flags behavior changes for manual review. This is black-box anomaly research, not coverage-guided binary fuzzing, and does not automatically exploit or prove a flaw.

### 8. Browser-side XSS and source review indicators\n\nThe scanner passively inspects HTML already fetched by the bounded crawler. It looks for inline event handlers, `javascript:` URLs, source-and-sink co-occurrence in inline scripts (for example, browser-controlled URL sources alongside HTML-string sinks), and same-origin source-map references. It never executes JavaScript, injects payloads, or fetches source maps. These findings are review leads: co-occurrence is not proof of data flow or exploitable XSS.\n\n### 9. Detailed findings and JSON reporting

Every finding can include:
- Stable finding ID.
- Description, impact, affected URL/component, and observed evidence.
- Severity, qualitative confidence, and a numeric confidence score.
- CWE identifier(s) with MITRE references where mapped.
- CVE identifier(s), CVSS version, score, and vector where applicable.
- Remediation summary and practical remediation steps.

Each scan writes a single UTF-8 `darth-report.json` file designed to open cleanly in Notepad. It contains findings, evidence, coverage totals, scanned page/resource metadata, and optional CVE matches. The scanner does not generate HTML or CSV reports.

## Install

Requires Python 3.11+. The scanner runtime uses only the Python standard library.

### Windows PowerShell

```powershell
git clone https://github.com/Screwyougucci/bug-free-sniffle.git
cd bug-free-sniffle
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
Copy-Item scope.example.json scope.json
notepad scope.json
```

### Linux / macOS

```bash
git clone https://github.com/Screwyougucci/bug-free-sniffle.git
cd bug-free-sniffle
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cp scope.example.json scope.json
```

Edit `scope.json`: set `authorized` to `true` only after confirming permission, and replace the example hostname with the exact hostname you are authorized to test. The example file defaults to `authorized: false`.

## Run a website scan

```powershell
darth-scanner scan --target https://example.test --scope scope.json --acknowledge-authorization
```

By default, this creates one JSON report. Override its path with `--output`.

## Run a scan with CVE matching

Download an NVD 2.0 JSON feed from the official [NVD data feeds page](https://nvd.nist.gov/vuln/data-feeds), then pass its path:

```powershell
darth-scanner scan --target https://example.test --scope scope.json --acknowledge-authorization --nvd-json .\nvdcve-2.0-recent.json
```

To check additional installed components not visible in response headers, prepare a CPE inventory such as `asset-inventory.example.json` and add `--inventory .\asset-inventory.json`.

You can also run the CVE matcher separately without sending any network requests:

```powershell
darth-scanner cve --inventory .\asset-inventory.json --nvd-json .\nvdcve-2.0-recent.json
```

## Run the bounded fuzzer

Use a specific GET URL containing the parameter to be mutated. Prefer a staging application or local test service:

```powershell
darth-scanner fuzz --url "https://example.test/search?q=baseline&page=1" --param "*" --scope scope.json --acknowledge-authorization --max-cases 32
```

The fuzzer sends one baseline request plus up to 32 bounded benign mutations. It records response hashes, response metadata, error signatures, and whether the input appears verbatim in the response. It does not execute SQL injection or XSS payloads. All observations require manual review.

## Scope file

```json
{
  "authorized": true,
  "allowed_hosts": ["example.test"],
  "max_pages": 30,
  "max_requests": 50,
  "request_delay_seconds": 1.0,
  "timeout_seconds": 8
}
```

Host matching is exact: adding `example.test` does not authorize `api.example.test`. Add every authorized host explicitly. Do not put credentials, session cookies, or secrets in this file. Real `scope.json` files are ignored by Git.

## Run local zero-day research checks

Run the static audit against a local Python project you own:

```powershell
darth-scanner audit-code --path . --max-files 1000
```

This creates `darth-source-report.json`. The audit skips virtual environments, dependency folders, build outputs, and files larger than 2 MB. It never executes source files and redacts credential-like literal values.

Treat results as code-review leads. Confirm reachability, input control, authentication boundaries, and impact before reporting a vulnerability. A true zero-day requires a previously unknown flaw, reproducible evidence, impact validation, and responsible disclosure. No scanner can promise to discover one or guarantee a number of findings.

## Finding quality

- **Finding:** a concrete observed weakness or misconfiguration.
- **Observation:** information disclosure or a hardening opportunity.
- **Candidate vulnerability:** a version/CPE match to a published CVE; verify the vendor advisory, configuration, and patch status.
- **Candidate exposure:** a HEAD response indicates a sensitive-looking path may be reachable; confirm internally without exposing the contents.
- **Fuzz anomaly:** a response difference that needs manual reproduction.

The scanner does not automatically exploit findings. It is designed to identify candidates and produce evidence for authorized security review. Version 0.7.0 adds adaptive multi-parameter differential fuzzing and deeper passive browser-side JavaScript review but does not claim to prove or exploit zero-days.

## Tests

```powershell
python -m unittest discover -s tests -v
darth-scanner --help
darth-scanner scan --help
darth-scanner cve --help
darth-scanner audit-code --help
```

GitHub Actions tests Python 3.11, 3.12, and 3.13.

## License

MIT


### 10. Zero-day research mode (local source audit)

The `audit-code` command now supports local source trees containing:
- **Python:** AST-based checks for dynamic execution, unsafe deserialization, shell execution, SQL construction, SSRF-sensitive URL use, dynamic file paths, disabled TLS verification, weak hashes, and hard-coded credentials.
- **JavaScript / TypeScript:** heuristic checks for dynamic evaluation, shell APIs, TLS verification disabled, and query construction patterns.
- **PHP:** heuristic checks for dynamic evaluation, shell APIs, unsafe unserialization, TLS settings, SQL construction, and credential-like assignments.
- **Java:** heuristic checks for dynamic evaluation, process execution, native object deserialization, TLS settings, and query construction.
- **Go:** heuristic checks for process execution, TLS verification disabled, and query construction.
- **Rust:** heuristic checks for dynamic evaluation/process execution patterns and query construction.

Python checks use syntax-tree analysis. Other languages use line-oriented pattern matching, so they can miss multiline flows and may produce false positives. All results require manual data-flow review; this is not a substitute for language-native SAST, compiler analysis, dependency scanning, or testing.



### 11. Differential response normalization and triage scoring

Fuzz observations now include both raw and normalized response hashes. Normalization masks common volatile request IDs, UUIDs, timestamps, and long hexadecimal identifiers so routine per-request changes are less likely to dominate comparisons. A heuristic anomaly score prioritizes combinations such as server errors, status changes, redirect changes, media-type changes, diagnostic signatures, large response changes, and input reflection.

The score is a triage priority, **not** a probability of vulnerability. Normalization is intentionally conservative and can mask meaningful fields or fail to recognize application-specific dynamic values. Every high-priority observation should be reproduced and inspected manually.

### 12. JavaScript source-to-sink review

Same-origin JavaScript review now adds a lightweight assignment-to-sink heuristic: it can follow a directly assigned browser-controlled variable (for example, a URL fragment or query string) into nearby HTML-string DOM or dynamic-code sinks. It recognizes a few common sanitizer assignments but is not a full JavaScript parser or taint engine. It can miss aliases, cross-function flows, framework abstractions, and sanitizers; findings remain low-confidence review leads.


## Version 1.2.0 — any explicitly authorized target and evidence-first reports

Darth Scanner is not tied to a particular domain. For each assessment, edit
`scope.json` and list the exact hostnames you are authorized to test. The same
scanner can then assess a different client, staging system, or bug-bounty asset
by changing the target and scope file. Exact hostname matching remains enabled:
subdomains are not automatically included. Add each permitted hostname explicitly,
and keep the scope within the program's written rules.

Example scope for a program that explicitly permits two assets:

```json
{
  "authorized": true,
  "allowed_hosts": ["app.example.test", "api.example.test"],
  "max_pages": 30,
  "max_requests": 50,
  "request_delay_seconds": 1.0,
  "timeout_seconds": 8
}
```

### Evidence and reproduction

Research reports now include a `reproduction_evidence` array. Each record preserves
the exact endpoint (with credential-like query values redacted), GET method,
parameter, built-in benign case name, baseline and observed HTTP status, response
sizes, content type, latency, raw and normalized SHA-256 hashes, anomaly score,
and a copy/paste replay command. Replay sends exactly one named benign GET test.
The report also states when a server-side source location is unavailable: black-box
HTTP responses cannot reveal the server's source file or line number.

For code you are authorized to inspect locally, use `audit-code`. Source findings
are static review leads and should be checked against the exact file and line in
your local checkout. A remote black-box finding must not be assigned an invented
source path or line number. When source code is unavailable, report the affected
route, parameter, request/response evidence, and reproduction steps instead.

### Bug-bounty PoC quality

A PoC should be a minimal, repeatable demonstration of the observed behavior, not
an exploit payload generator. Start with the baseline request, change one input,
record the response difference, and explain the security impact only when it is
demonstrated. The scanner's generated replay recipe is deliberately limited to
its named benign test corpus. It does not generate account-takeover, data-theft,
destructive, persistence, or unauthorized-access payloads. Follow each program's
scope, rate limits, and disclosure rules.


## Version 1.3.0 — passive server-side audit

The research command now adds a server-side diagnostic review of responses already fetched within the configured scope. It looks for:
- Database error and SQL driver diagnostics that may disclose internal implementation details.
- Framework and language stack traces.
- Server-side template-engine diagnostics.
- Absolute filesystem paths in client-visible error output.
- Benign input variations that produce HTTP 5xx responses, recorded as low-confidence robustness leads.

These checks do **not** execute SQL, shell commands, template directives, path traversal, SSRF callbacks, or authentication bypasses. They do not submit forms or send state-changing HTTP methods. No additional requests are made by the passive response checks.

A matching database error is evidence of diagnostic disclosure, **not proof of SQL injection**. A 5xx response is an input-handling lead, **not proof of command injection or remote code execution**. SSRF, IDOR, authentication bypass, and authorization-boundary testing require a controlled test environment, test accounts, and explicit permission; they are not claimed as detected by this passive module.

Findings are written into the existing JSON report under `findings`, with category `server-side`, evidence, CWE mapping, confidence, and remediation. Review server logs and reproduce findings in a staging environment before reporting them as vulnerabilities.


### Version 1.4.0 — expanded passive server-side review

The normal `scan` command now runs the server-side audit against every already-fetched HTML response and every same-origin JavaScript response. The audit adds:
- Framework and runtime debug-page signatures (including common Werkzeug, Django, Symfony, Spring, and ASP.NET diagnostic pages).
- Debug-tooling response headers such as debug tokens and framework toolbar indicators.
- Explicit server software version disclosure in `Server` and `X-Powered-By` headers.
- Uncaught runtime error signatures, alongside database diagnostics, stack traces, template errors, and internal filesystem paths.
- CWE mapping, bounded evidence excerpts, confidence scores, and practical remediation guidance.

These checks are passive: they do not send additional requests or exploit payloads. Version banners are informational, not proof that the identified software is vulnerable. Debug-page signatures require manual validation, and no finding proves code execution, SQL injection, SSRF, IDOR, or unauthorized data access.


## Version 1.5.0 — continuous server watch and Sigma-style log review

### Continuous watch mode

The new `watch` command repeatedly runs the existing bounded web/server scan. It does not stop when it finds a security issue: it prints each previously unseen finding immediately, saves it, then continues with the next scheduled cycle.

- Default interval: 300 seconds; minimum: 60 seconds.
- Default duration: unlimited cycles until you press Ctrl+C.
- `--max-cycles N` is available for a finite test; `0` means unlimited.
- Stable finding IDs prevent the same issue from being announced repeatedly.
- A state file stores previously seen IDs and accumulated findings. Re-run the same command to resume.
- Each scan cycle still obeys the exact-host allowlist, authorization acknowledgement, request budget, timeout, and request delay in the scope file.
- The latest individual scan is saved separately from the accumulated watch report.

Example (PowerShell):

```powershell
darth-scanner watch `
  --target "https://your-authorized-host.example/" `
  --scope ".\scope.json" `
  --acknowledge-authorization `
  --interval-seconds 300 `
  --output ".\darth-watch-report.json" `
  --state ".\darth-watch-state.json"

notepad .\darth-watch-report.json
```

Stop with Ctrl+C. To resume, run the same command again with the same state file. For a short test, add `--max-cycles 2`. Continuous mode is intentionally not a high-speed loop: every pass is a bounded scan, and the interval cannot be set below 60 seconds.

### Sigma-style local server-log review

The new `audit-logs` command applies built-in Sigma-inspired detections to a local text or JSONL server log. It performs no network requests. Initial rules flag patterns associated with authentication failures, traversal probes, SQL injection probes, command-injection probes, SSRF/private-address attempts, and debug/stack-trace disclosure.

```powershell
darth-scanner audit-logs --path ".\server.log" --output ".\darth-sigma-report.json"
notepad .\darth-sigma-report.json
```

These are lightweight built-in Sigma-style rules, not a full Sigma YAML engine. Log matches show that a pattern appeared in a log line; they do not prove the request succeeded or that a vulnerability exists. Review the corresponding application and reverse-proxy logs before drawing conclusions. The reader has file-size and line-count limits and does not modify the source log.


## Version 1.6.0 — API and web metadata inventory

The standard `scan` command now reserves a small part of its existing request budget to inspect same-origin metadata resources:

- `/robots.txt` and `/sitemap.xml`
- `/.well-known/security.txt` and `/security.txt`
- `/openapi.json`, `/swagger.json`, and `/api-docs`

When an OpenAPI/Swagger JSON document is publicly available, Darth Scanner inventories documented paths and HTTP methods. It also extracts same-origin sitemap URLs and same-origin Sitemap directives from robots.txt. The JSON report includes an `api_inventory` section and coverage counts; the local HTML dashboard shows API path and metadata-resource totals.

**Important limits:** this is passive inventory, not API exploitation. The scanner never invokes operations listed in an API schema, never follows external sitemap links, and never expands discovered paths into additional requests. All metadata requests are same-origin and count against the existing per-scan request budget. The crawler reserves capacity for metadata discovery and the existing exposure/method checks, so the number of HTML pages may be slightly lower on scans with a tight request budget. If the budget is already consumed, API discovery is skipped and the report explains why.


## Version 1.7.0 — subtle API schema weakness review

Darth Scanner now reviews any OpenAPI document it already discovers, without invoking documented API operations. It looks for small but security-relevant specification details:

- Sensitive-looking routes (such as account, user, billing, role, token, export, and admin paths) that have no effective OpenAPI security requirement.
- Operations that explicitly set an empty security list and therefore override inherited global security.
- API keys documented in query parameters, where credentials can leak into browser history, referrers, and logs.
- Plaintext HTTP server URLs in the API specification.
- HTTP Basic authentication declarations that deserve transport and credential-lifecycle review.

These are intentionally conservative schema-review candidates. A missing OpenAPI security declaration does **not** prove the live endpoint is unauthenticated; gateways or application middleware may enforce access controls outside the schema. A sensitive-looking path may also be intentionally public. Verify with the service owner and approved test accounts before classifying a finding as a vulnerability.

The review is passive, adds no network requests, does not send payloads, and does not call API operations. It analyzes only metadata already fetched within the existing same-origin request budget. Reports include the exact documented method/path and remediation guidance, but never API key values.


## Version 1.8.0 — subtle cache and CORS edge cases

The normal passive HTTP review now adds two small but useful checks without making extra requests:

- **Shared-cache exposure candidate:** flags HTTP 200 responses on sensitive-looking account, profile, billing, order, session, export, or administrative paths when Cache-Control includes `public` or `s-maxage` without `private` or `no-store`. This is a candidate only; actual impact depends on whether the response contains user-specific material and how the CDN/cache keys requests.
- **CORS cache variation:** flags a concrete `Access-Control-Allow-Origin` response that omits `Vary: Origin`. This matters when the server dynamically selects an allowed origin; a static single-origin policy may not require it.

The checks intentionally do not flag public caching on ordinary public routes, and they accept `Vary: Origin` case-insensitively. They analyze headers from responses already fetched within the existing scope and request budget. They do not probe other origins, attempt cache poisoning, or retrieve another user's data.


## Version 1.9.0 — deeper JavaScript source-to-sink review

The same-origin JavaScript review now follows simple local variable assignments and aliases in source order. It recognizes additional browser-controlled inputs, including message event data and values read through `URLSearchParams` or `URL.searchParams`, then checks whether those values reach selected HTML-string DOM or dynamic-code sinks.

A visible reassignment through a small set of recognized sanitizer functions breaks the simple taint chain. This is deliberately conservative and is **not** a full JavaScript parser or taint engine: it does not understand function calls, branches, object properties, inter-module flows, framework abstractions, or every sanitizer. Findings remain low-confidence review candidates; verify the exact code path and sanitizer behavior manually. No JavaScript is executed and no payloads are sent.


## Version 2.0.0 — Python request-to-sink vulnerability research

The local `audit-code` command now performs a bounded AST-based data-flow pass for Python in addition to the existing source-pattern checks. It follows simple assignments from common web request inputs (Flask/Django/FastAPI-style request fields and FastAPI parameter helpers) into selected sensitive operations:

- SQL execution calls (`execute`, `executemany`, and `raw`) — CWE-89 candidates.
- Outbound HTTP clients and URL openers — SSRF candidates (CWE-918).
- File open/download operations — path traversal candidates (CWE-22).
- Process APIs — command-injection candidates (CWE-78).
- Dynamic template compilation — template-injection candidates (CWE-94).
- Native object deserializers — unsafe-deserialization candidates (CWE-502).

Unlike the earlier checks that flagged any dynamic URL or path expression, these new findings require a recognizable request-input source and a simple local assignment path to a sink. Constant SQL and constant URLs are not flagged by this data-flow pass. The analysis is intentionally conservative and does not model all function calls, branches, interprocedural flows, framework wrappers, validation, or sanitizer semantics. Findings remain low-confidence review candidates, not proof of exploitable vulnerabilities. No source code is executed and no network requests are made.



## Version 2.1.0 — Multi-language request-to-sink research

The local `audit-code` command now adds bounded source-to-sink review for JavaScript, TypeScript, PHP, Java, and Go, alongside the Python AST pass. It recognizes common web-request input patterns, follows simple same-file local assignments, and looks for nearby database query, outbound request, filesystem, process, dynamic-template, and deserialization operations.

This additional pass is line-oriented and heuristic. It does not fully parse these languages, understand lexical scopes or control flow, follow function boundaries, or prove that validation and sanitization are absent. It can miss flows split across lines and can produce false positives when identifiers are reused. Findings are low-confidence review candidates, not validated vulnerabilities. The scanner does not execute source code or send network requests during source review.


## Version 2.2.0 — Project-wide Python call-graph research

The `audit-code` workflow now includes a bounded project-level Python analysis pass. It indexes functions across the scanned Python files, resolves straightforward local and imported helper names, builds conservative parameter-to-sink and parameter-to-return summaries, and checks whether request-derived arguments cross function boundaries into sensitive operations.

This pass is intentionally bounded and conservative. It does not execute code, resolve arbitrary dynamic dispatch, fully interpret relative imports, model every branch or closure, or establish runtime reachability. Call-graph results are low-confidence leads requiring review. The existing per-file checks remain enabled.


## Version 2.3.0 — Cross-function multi-language dataflow

The project-level source review now builds bounded function summaries for JavaScript, TypeScript, PHP, Java, and Go. It looks for request-derived values passed into uniquely-resolved helper functions whose parameters reach database, outbound-request, filesystem, process, template, or deserialization operations. It also follows straightforward helper return flows and conservatively retains taint across branch assignments.

This is lexical, path-insensitive analysis—not a full parser, compiler dataflow engine, or proof of exploitability. It intentionally avoids guessing when helper names are ambiguous. Complex syntax, nested functions, callbacks, dynamic dispatch, imports, aliases, and sanitizers may be missed or misread. Findings remain low-confidence review candidates and require manual validation. No source is executed and no network traffic is generated.
