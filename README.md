# Darth Scanner — Web & Server Security Scanner

## Version 0.26.0 — managed multi-tool assessment

Darth Scanner now includes an in-app **INSTALL / UPDATE TOOLS** manager and **FULL TOOLCHAIN** assessment. The installer downloads official Windows x64 release archives for ffuf, Subfinder, httpx, Katana, and Nuclei from each project's GitHub releases. It requires the publisher's checksum manifest and rejects archives whose SHA-256 does not match. It extracts only the expected executable into `%LOCALAPPDATA%\\DarthScanner\\tools\\bin`; no system PATH edits are made.

The long-running coordinator runs Subfinder for passive subdomain discovery only when the existing subdomain option is enabled, then probes the authorized host set with httpx, crawls with Katana, and performs GET-only path discovery with ffuf. ffuf uses a small built-in benign path list, a 2 requests/second rate limit, two workers, and a 3-minute per-host limit; Katana is depth-limited to 3 and rate-limited to 2 requests/second. Discovered subdomains are actively checked only when the user explicitly enables subdomain mode and confirms authorization for the root domain and all subdomains. Host count is capped at 25 and active hosts per cycle at 10.

The assessment runs in 30-minute cycles for a user-selected duration of 1–24 hours. Each completed cycle writes a checkpoint and separate tool outputs under the target's `toolchain/cycle-NNNN` folder. Pressing Stop terminates the active tool process and saves the last completed cycle; starting the toolchain again for the same target resumes from that checkpoint if the original session has time remaining. Reports are local to the PC.

Nuclei is installed with the other tools but is **off by default**. If explicitly enabled, the coordinator selects only `misconfig`, `exposure`, and `ssl` template tags, excludes known intrusive/fuzz/DoS/brute-force tags, and limits request rate and concurrency. Nuclei matches are still candidates requiring manual validation, not proof of a working exploit. The toolchain does not run credential attacks, upload tests, destructive payloads, or denial-of-service tests. It does not automatically run ZAP's browser-based client spider; that remains a separate action because it can execute client-side JavaScript and interact with page controls. ZAP continues to be installed separately and requires Java 17+.

All tools are third-party software; their licenses and release cadence remain with their respective maintainers. The installer is Windows x64 only in this release. A missing or unpublished official checksum manifest causes installation to fail closed rather than downloading an unverifiable executable.

## Version 0.25.0 — OWASP ZAP scanning engine

Darth Scanner now integrates the official **OWASP Zed Attack Proxy (ZAP)** engine instead of relying only on its in-house HTTP checks. Use **OWASP ZAP ENGINE** in the desktop app to run ZAP's traditional spider, its browser-based Client Spider when the installed ZAP build has that add-on available, and ZAP's passive vulnerability rules. ZAP alerts are normalized into Darth's finding registry and saved to `zap-engine/latest-report.json`; discovered URLs and lifecycle history are saved with the target.

**Install prerequisite:** ZAP must currently be installed separately. Click **GET ZAP** in the app or visit https://www.zaproxy.org/download/. Windows installations require Java 17 or newer. If Darth Scanner cannot locate `zap.bat`, set the Windows user environment variable `DARTH_ZAP_PATH` to the full path of `zap.bat`, then restart the app. The engine is started locally as a daemon on `127.0.0.1` with a random per-run API key; the API is not exposed to other computers. Darth Scanner shuts down the daemon after the scan.

Passive crawling and passive rules are the default. The browser-based Client Spider executes client-side JavaScript and can interact with page navigation or controls, so use a staging copy when those interactions could change data. The **Enable active scan** option is off by default and requires a second confirmation; active scanning sends test requests and may affect fragile or production services. Keep scans within systems you own or are explicitly authorized to assess. A ZAP alert is a finding to validate, not automatic proof of a working exploit. Reports omit raw request/response bodies and redact common secret values. This first integration uses the installed ZAP engine; automatic first-run engine download/management is a follow-up, not included in 0.25.0.

## Version 0.24.0

The desktop app's **DEEP CRAWL** action now performs a full, bounded discovery pass followed by the full security-analysis profile. It can review up to 150 URL resources and 350 HTTP requests per run, with the configured 0.5-second delay. It discovers URLs from nested HTML links, iframe sources, robots.txt Sitemap directives, XML sitemap indexes and URL sets, same-origin JavaScript assets, and static API/route strings in those scripts. Query routes are kept distinct; fragments and duplicate URLs are removed. The crawler remains same-origin and obeys the explicit authorized scope and shared request budget. Common state-changing paths such as logout, delete, checkout, and unsubscribe are skipped.

The full-scan findings are now imported into the same persistent finding registry used by the desktop dashboard, so results from DEEP CRAWL appear in the findings table and detail inspector instead of only being written to a separate JSON file. The Stop button cancels subsequent requests.

This is an HTTP crawler, not a headless browser: it does not execute client-side JavaScript, click controls, submit forms, follow redirects, or send non-GET requests. JavaScript route discovery is static analysis of downloaded source. Missing/weak security headers remain hardening advice, not vulnerability findings. Suspicious behavior is not called a confirmed exploit without appropriate validation.

Missing or weak security headers and similar configuration advice are classified as hardening observations, shown separately from candidate vulnerabilities, excluded from actionable-candidate totals, and never assigned CVSS. Candidate findings still require validation; a static pattern or response anomaly is not automatically an exploit.

## Version 0.22.0

Darth Scanner now has a GitHub source-review workflow. In the desktop app, paste a repository URL into **GITHUB REPOSITORY** for a manual review, or leave it blank and choose **GITHUB CODE AUDIT** to discover repository links from the website landing page. The app displays the discovered candidates and selects the first one; you must separately confirm that you are authorized to inspect that repository before source files are fetched. The last JSON report is saved beside that website's local scan history and can be opened with **VIEW REPORT**.

The new audit-github CLI command performs bounded, read-only static review of source files in public GitHub repositories. It checks for credential patterns, dynamic execution, unsafe deserialization, shell invocation, risky SQL construction, disabled TLS verification, DOM injection sinks, permissive CORS, and path traversal patterns. Findings include repository URL, file path, exact line number, redacted excerpt, CWE, confidence estimate, and remediation. Dependency manifests are inventoried, but this first pass does not claim complete dependency CVE matching. No repository code is executed and no files are modified. Public unauthenticated scans review up to 40 files; a locally configured read-only GITHUB_TOKEN allows up to 180 files and private-repository access. Set the token in the Windows user environment; never paste it into the scanner UI or a report. Only review repositories you own or are explicitly authorized to inspect.

## Version 0.21.0

Fuzz Lab now automatically repeats one promising benign GET observation when the shared request budget allows. The repeat check records its HTTP status, response size, elapsed time, SHA-256 digest, and which original signal(s) reappeared. Each per-finding report includes a structured, sanitized proof-of-concept record with the original observation and automatic verification result. A repeatable observation is not an automatically confirmed exploit; owner-side impact validation remains required. Only one repeat request is reserved per campaign, the total remains capped at 24 requests, and the UI limits the campaign to seven parameters so the verification budget is preserved. Response bodies and raw fuzz values are never written to disk.

## Version 0.20.0



Fuzz Lab now classifies response anomalies into separate, cautious vulnerability-pattern hypotheses and writes one standalone JSON evidence report per candidate under the target's local `fuzz/findings` folder, plus an `index.json`. Reports include sanitized GET request details, baseline/response hashes and metadata, signal type, confidence, safe reproduction and validation steps, and explicit limitations. Reflection is not labelled XSS, redirects are not labelled open redirects without destination validation, and timing/size anomalies are not treated as denial-of-service proof. Response bodies and raw test values are never stored; CVSS is not assigned to unconfirmed fuzz hypotheses.

## Version 0.18.0

Fuzz Lab now uses feedback-guided scheduling. After every bounded GET case, it updates the priority of remaining benign input families based on observed response signals (for example, reflection guides encoding/context cases, diagnostic changes guide structured/type cases, and timing or response-size outliers guide bounded length cases). It also explores under-tested families when a case produces no signal. The schedule is deterministic, explainable, and stays inside the existing request/time limits; it does not generate exploit payloads or increase the request budget.

## Version 0.17.0

Fuzz reports now include evidence-based exploitability triage. The engine groups benign fuzz signals into cautious vulnerability hypotheses (for example, input-triggered server errors, diagnostic disclosure, reflected input requiring context review, and unusual response behavior). It also carries forward candidate CVE and static-review findings with safe validation guidance. Each assessment includes its supporting hashes, observed status, confidence, estimated severity, potential impact, and non-destructive next steps. These are unconfirmed leads—not working exploits, proof of compromise, or CVSS scores unless a matched CVE supplies one. No additional exploit payloads are sent.

## Version 0.16.0

Professional fuzzing now discovers query parameters automatically (or accepts repeated `--param` selectors), selects benign test cases based on observed input types, samples a repeated baseline, and records per-case hashes, response metadata, anomaly signals, score, confidence, and safe reproduction steps. It shares the authorization scope request budget across parameters, rate-limits requests, redacts secret-like query values in reports, and never stores response bodies or raw fuzz values. It remains read-only GET fuzzing; it does not submit forms or use exploit payloads.

## Version 0.15.0

Finding details now include a sanitized, repeatable proof-of-concept record for observed HTTP conditions: capture time, read-only GET method, redacted request URL, response status, elapsed time, response size, selected security-relevant response headers, and a SHA-256 digest of the response body. The body itself, cookies, authorization headers, and common secret-bearing query values are not retained. Reproduction steps explain how to repeat the same read-only request and compare the result. These are verification steps for observed behavior, not exploit payloads or proof that a condition is exploitable. Evidence metadata is persisted in finding history and included in JSON scan reports. Windows now prefers Per-Monitor DPI Awareness V2, with legacy fallbacks, for sharper rendering across mixed-DPI monitors.

## Version 0.14.0

The desktop findings table now shows official NVD CVSS base scores beside severity, and finding details retain the CVSS vector. A score is shown only when an applicable CVE record supplies one; other observations are marked N/A rather than assigned a made-up CVSS rating. The Windows desktop app now requests per-monitor DPI awareness and scales Tk fonts to the active display DPI for sharper text and controls on high-resolution screens.

A conventional Python security scanner for websites and server software you own or are explicitly authorized to assess. **No AI, LLMs, or generative analysis.** Detection is implemented through deterministic HTTP/TLS checks, passive software fingerprints, local CVE data, and bounded fuzzing.

> No scanner can guarantee a fixed number of vulnerabilities. Bug-Free Sniffle reports observed weaknesses and candidate CVE matches with evidence; it never invents findings to reach a target count.

## Version 0.13.0 capabilities

Version 0.13.0 adds recursive subdomain discovery with a domain tree and configurable bounds. Version 0.8.0 adds content-aware adaptive watch. Version 0.8.1 adds persistent discovery identities: stable target, resource, behavior, evidence, test, and finding IDs, plus lifecycle tracking for new, recurring, changed, and resolved findings. Watch history stores only metadata and finding evidence summaries, not response bodies, cookies, or credentials. A finding is marked resolved only after a complete applicable check round finishes without observing it. It selects one focused analysis per cycle, learns which checks apply from response metadata, remembers completed checks and unique finding IDs, and resets its check queue when the response changes. It stays on the exact authorized target and uses only the bounded web GET/crawl path; it does not rotate into host-wide TLS, HTTP-method, or sensitive-path probes. The minimum watch interval is 30 seconds.



### 1. Website security checks

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

### 2. Exposed configuration and backup discovery

The scanner sends **HEAD requests only** to a bounded list of likely sensitive paths, such as:

- Environment files and local/production variants.
- Git, Subversion, and Mercurial metadata.
- Private SSH key filenames.
- Common application configuration backups.
- SQL dump and backup archive filenames.
- PHP diagnostic page and common operating-system metadata.

It records only response status and headers such as Content-Type and Content-Length. It does **not** download, parse, save, or display file contents. If a server returns a generic HTML fallback for every path, the result is marked low-confidence and requires manual verification. HEAD support varies by server; a negative HEAD result does not prove that a file is absent or inaccessible through GET.

### 3. TLS and certificate assessment

- Verified certificate-chain and hostname handshake.
- Certificate expiration and near-expiration checks.
- Protocol-specific handshakes for TLS 1.0, 1.1, 1.2, and 1.3.
- Reports when deprecated TLS 1.0 or TLS 1.1 accepts a handshake.
- A restricted handshake against selected legacy cipher families (RC4, 3DES/DES, NULL, export-grade, anonymous, and MD5-based suites).
- Records the negotiated protocol and cipher suite.

The local Python/OpenSSL build may not include obsolete cipher implementations. If a legacy cipher cannot be offered by the scanner itself, that cipher test is reported as not observable rather than a clean result. Protocol negotiation is based on the scanner's TLS implementation and network path; this is not a complete cryptographic compliance certification. TLS guidance reference: [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final). NIST announced a review of this publication in May 2026; this scanner reports observed capabilities rather than claiming formal compliance.

### 4. Server and software fingerprints

Versioned response-header fingerprints now include nginx, Apache HTTP Server, PHP, Microsoft IIS, OpenSSL, OpenResty, Caddy, lighttpd, HAProxy, Envoy, Traefik, Eclipse Jetty, Apache Tomcat, Gunicorn, Uvicorn, Varnish Cache, and Node.js.

Fingerprints are based on publicly returned headers and can be hidden, spoofed, or altered by reverse proxies. Automatic CVE matching is limited to products and versions the scanner can identify this way; a missing fingerprint does not mean that software is absent. Use a trusted software inventory or SBOM for better coverage.

### 5. CVE intelligence and CVSS severity

- Automatically queries the NVD CVE API 2.0 for detected CPE 2.3 product/version fingerprints.
- Caches NVD results locally for 24 hours and performs at most one uncached product lookup per 30-second adaptive scan cycle to respect public API rate limits.
- The desktop app includes an option to disable automatic NVD lookups; an optional NVD API key can be supplied through the `NVD_API_KEY` environment variable.
- Also supports matching a trusted CPE 2.3 software inventory against a local NVD 2.0 JSON feed.
- Uses NVD affected CPE criteria and numeric dotted-version boundaries where supported.
- Includes the exact CVE ID, English description, CVSS version, base score, vector, severity, affected component, observed source URL, matched software/version evidence, and NVD/advisory links.
- Uses detected software fingerprints and optional user-provided inventory.

CVSS severity bands:
- **Critical:** 9.0–10.0 (CVSS v3.x/v4.0)
- **High:** 7.0–8.9
- **Medium:** 4.0–6.9
- **Low:** 0.1–3.9

CVSS v2 has no Critical tier; scores 7.0–10.0 are High.

**CVE matches are candidates, not proof of exposure.** A product banner may be spoofed, NVD configuration expressions can require additional platform conditions, and vendors sometimes backport fixes without changing the upstream version string. Verify the exact vendor build, platform conditions, and advisory before treating a match as exploitable.

### 6. Fuzzing

- Feedback-guided case scheduling: each response influences which remaining benign input family runs next; signal-to-family mappings and exploration behavior are covered by tests.
- Vulnerability-pattern triage creates separate JSON evidence reports for diagnostic disclosure, input-triggered server errors, reflected-input context review, redirect behavior, media-type changes, unusual latency, response growth, and HTTP status changes. These are unconfirmed leads with safe validation guidance.
- Adaptive GET query-parameter fuzzing; discovers up to 8 parameters from the supplied URL by default, or accepts repeated `--param` selectors.
- Chooses a deterministic benign corpus based on the original input shape (numeric, boolean, UUID-like, or general text), including type, encoding, Unicode, whitespace, and bounded length boundaries.
- Samples the baseline twice, then compares status, Content-Type, response size, response timing, diagnostic signatures, and input reflection.
- Each case records a sanitized request URL, test-input SHA-256 (not the raw value), baseline and response hashes, response headers from a small allowlist, anomaly signals, score, confidence, timestamp, and safe reproduction steps.
- Uses one request at a time, the configured minimum delay, and the same scope-wide request budget. It never follows redirects, submits forms, guesses credentials, uploads files, stores response bodies, or sends exploit payloads.
- Signals are triage leads only. Reflection is not automatically XSS, a 5xx response is not automatically a vulnerability, and timing differences require repeat validation.

### 7. Zero-day research mode (local source audit)

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

An unknown robustness issue can also be investigated through the bounded `fuzz` command on an explicitly authorized endpoint. It compares repeated baselines against adaptive benign mutations and records evidence for manual review. This is black-box HTTP parameter fuzzing, not coverage-guided binary fuzzing, and does not automatically exploit or prove a flaw. Example: `darth-scanner fuzz --url https://example.test/search?q=hello&page=1 --scope scope.json --acknowledge-authorization --max-cases 12` automatically tests the discovered query parameters. Use `--param q --param page` to select exact parameters.

### 8. Browser-side XSS and source review indicators\n\nThe scanner passively inspects HTML already fetched by the bounded crawler. It looks for inline event handlers, `javascript:` URLs, source-and-sink co-occurrence in inline scripts (for example, browser-controlled URL sources alongside HTML-string sinks), and same-origin source-map references. It never executes JavaScript, injects payloads, or fetches source maps. These findings are review leads: co-occurrence is not proof of data flow or exploitable XSS.\n\n### 9. Recursive subdomain discovery

- Opt-in passive Certificate Transparency discovery using crt.sh, expanded breadth-first across nested labels (for example, `api.shop.example.com`).
- Configurable maximum depth (1–8, default 5) and DNS-verified host count (1–100, default 25).
- Each discovered hostname must resolve exclusively to globally routable addresses before it is accepted as a candidate.
- The report records each hostname, depth, nearest discovered parent, and DNS verification status; the desktop app provides a Domain Tree view.
- A 15-minute in-process cache avoids repeating the same CT queries on every adaptive watch cycle. Active HTTP checks still share the existing request/page budgets and require authorization for the entire root domain and all its subdomains.

CT/DNS discovery is not proof of ownership. Names are candidates, DNS can change, and the user must have authorization for the entire root-domain boundary before enabling active checks.

### 10. Detailed findings and JSON reporting

Every finding can include:
- Stable finding ID plus separate target, resource, behavior, evidence, and test IDs.
- Description, impact, affected URL/component, and observed evidence.
- Severity, qualitative confidence, and a numeric confidence score.
- CWE identifier(s) with MITRE references where mapped.
- CVE identifier(s), CVSS version, score, and vector where applicable.
- Remediation summary and practical remediation steps.

Each scan writes a single UTF-8 `darth-report.json` file designed to open cleanly in Notepad. It contains findings, evidence, coverage totals, scanned page/resource metadata, and optional CVE matches. The scanner does not generate HTML or CSV reports.

## Desktop dashboard (Windows, Linux, macOS with Tk support)

Darth Scanner 0.9.0 includes a persistent local desktop dashboard. It lets you enter a website URL, start or stop an adaptive watch, launch the dedicated HTTP Fuzz Lab, review unique findings, inspect each finding's IDs/evidence/history, and reopen the same saved target history after restarting the app. The app uses Python's built-in Tkinter; no web server or third-party GUI package is required. On Windows, launch it with `darth-scanner-app` from PowerShell after installation.

The app prompts you to confirm that you own the site or have explicit permission before starting. It creates a separate local scope for the exact hostname entered (not its subdomains), uses bounded read-only web checks, and keeps reports/history under `%LOCALAPPDATA%\\DarthScanner`. Continuous watch runs until you press **STOP** or close the app. The minimum interval is 30 seconds. Entering a URL does not itself grant permission to scan it.

### Standalone Windows executable

A Windows x64 portable build is produced by the `Windows desktop build` GitHub Actions workflow. Download `DarthScanner-Windows-x64.zip` from the repository's Releases page, extract the entire ZIP, and run `DarthScanner.exe`. Keep `DarthScannerEngine.exe` beside it; the GUI launches that bundled engine for watch cycles. No Python installation is required. The app stores reports and history under `%LOCALAPPDATA%\\DarthScanner`. The first run may show a Windows SmartScreen warning because the executable is not code-signed; only run builds downloaded from this repository. The workflow also retains a downloadable Actions artifact for 90 days. Tagged GitHub Releases are the persistent download location.

For running from source instead, install with `py -3 -m pip install -e .` and launch `darth-scanner-app`.

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

## Continuous adaptive watch

For a target you own or are explicitly authorized to assess, run adaptive analysis until you press Ctrl+C:

```powershell
darth-scanner watch --target https://your-authorized-host.example --scope scope.json --acknowledge-authorization --output-dir darth-watch-reports --interval 30
```

Each cycle performs one focused, read-only analysis selected from the previous response: headers/CSP, cookies, CORS metadata, redirect metadata, HTML patterns, passive browser-side indicators, same-origin JavaScript static review, or software fingerprinting. Checks that do not apply to the observed content are skipped. The scheduler remembers completed checks for the current response fingerprint and starts a new round after applicable checks finish; a changed response resets the queue. It writes one timestamped JSON report per cycle and stores history and the finding lifecycle registry in `history.json`. It never submits forms, executes JavaScript, injects exploit payloads, invokes unsafe HTTP methods, probes unrelated paths, or follows links outside the exact origin. The minimum interval is 30 seconds. Stop with Ctrl+C.

Run a single focused analysis manually with `darth-scanner scan --target ... --scope scope.json --acknowledge-authorization --profile web --focus headers`. Available focuses: `headers`, `cookies`, `cors`, `redirects`, `html`, `browser`, `javascript`, and `fingerprint`. Use `--focus all` for the combined web analysis.

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
darth-scanner fuzz --url "https://example.test/search?q=baseline" --param q --scope scope.json --acknowledge-authorization --max-cases 32
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

The scanner does not automatically exploit findings. It is designed to identify candidates and produce evidence for authorized security review. Version 0.5.0 adds passive browser-side XSS indicators but does not claim to prove or exploit zero-days.

## Professional evidence analysis (0.20.0)

Fuzz Lab uses feedback-guided benign input families, repeated baselines, bounded GET-only requests, and response hashes. A single anomalous response is kept as a low-confidence lead; it is not promoted to a confirmed exploit. The campaign correlates observations only when they share the same host, path, and query parameter, then writes a separate `correlations/index.json` report with contributing evidence hashes and safe owner-validation steps. Correlation sends no extra requests and never claims an exploit chain is confirmed.

Published CVE findings retain the NVD/CNA CVSS score, version, and vector. CVSS 3.1 vectors are independently recalculated as a consistency check; mismatches are flagged instead of silently changing the published score. CVSS 4.0 scores remain sourced from NVD/CNA. A CVSS base score describes the vulnerability, not the likelihood that a particular target is exploitable. Unconfirmed fuzz hypotheses do not receive invented CVSS scores.

Finding details show the exact client-visible response URL, line number, and sanitized source excerpt when the relevant HTML/JavaScript or text is present in the fetched response. This is not the server's private source tree. To identify server-side file paths and line numbers, provide the authorized source repository or a source-code audit target.

All validation remains non-destructive and scoped: no shell execution, credential attacks, auth bypass, data extraction, destructive payloads, or denial-of-service testing.

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
