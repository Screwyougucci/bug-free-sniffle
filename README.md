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


### Static JavaScript API route discovery (v1.1 research)

The `research` command can now inspect a small, bounded set of same-origin JavaScript
files already linked from crawled pages. It does **not** execute scripts. It extracts
only literal URL arguments from unambiguous `fetch(url)` (single-argument GET),
`axios.get(url)`, and `XMLHttpRequest.open("GET", url)` patterns. Only same-origin
URLs with existing, non-sensitive query parameters are eligible for the existing
benign GET fuzzer. Dynamic URL construction, POST/PUT/PATCH/DELETE calls, external
hosts, and credential-like parameter names are ignored. Script fetches consume the
same scope request budget and leave a small reserve for fuzzing. This is static
pattern matching: it can miss routes and can produce candidates that need review.


## Version 1.2.0 — evidence-first reproduction

Research reports include redacted reproduction evidence for benign GET observations:
baseline and observed status, response hashes, response size, content type, latency,
anomaly score, and a one-case replay command. Credential-like query values are
redacted. Black-box HTTP results do not identify server source files or line numbers;
use `audit-code` on an authorized local checkout for source locations. Response
differences are triage evidence, not proof of a vulnerability. Replay remains limited
to one named benign case and the active exact-host authorization scope.
