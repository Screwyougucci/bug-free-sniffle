# Darth Scanner — Web & Server Security Scanner

A conventional Python security scanner for websites and server software you own or are explicitly authorized to assess. **No AI, LLMs, or generative analysis.** Detection is implemented through deterministic HTTP/TLS checks, passive software fingerprints, local CVE data, and bounded fuzzing.

> No scanner can guarantee a fixed number of vulnerabilities. Bug-Free Sniffle reports observed weaknesses and candidate CVE matches with evidence; it never invents findings to reach a target count.

## Version 0.9.1 capabilities

Version 0.8.0 adds content-aware adaptive watch. Version 0.8.1 adds persistent discovery identities: stable target, resource, behavior, evidence, test, and finding IDs, plus lifecycle tracking for new, recurring, changed, and resolved findings. Watch history stores only metadata and finding evidence summaries, not response bodies, cookies, or credentials. A finding is marked resolved only after a complete applicable check round finishes without observing it. It selects one focused analysis per cycle, learns which checks apply from response metadata, remembers completed checks and unique finding IDs, and resets its check queue when the response changes. It stays on the exact authorized target and uses only the bounded web GET/crawl path; it does not rotate into host-wide TLS, HTTP-method, or sensitive-path probes. The minimum watch interval is 30 seconds.



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

Fingerprints are based on publicly returned headers and can be hidden, spoofed, or altered by reverse proxies. A missing fingerprint does not mean that software is absent. Use a trusted software inventory or SBOM for better coverage.

### 5. CVE intelligence and CVSS severity

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

### 6. Fuzzing

- A conservative GET query-parameter fuzzer with 32 bounded, benign mutation values and anomaly evidence.
- One request at a time, fixed minimum delay, bounded request count, and no redirects, form submissions, credential guessing, uploads, or exploit payload execution.
- Status changes, 5xx responses, diagnostic signatures, content-type changes, response hashes, input reflection, large response-size changes, and slow responses are recorded as triage signals, not confirmed vulnerabilities.

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

An unknown vulnerability can also be investigated through the bounded `fuzz` command on an explicitly authorized endpoint. It compares responses and flags behavior changes for manual review. This is black-box anomaly research, not coverage-guided binary fuzzing, and does not automatically exploit or prove a flaw.

### 8. Browser-side XSS and source review indicators\n\nThe scanner passively inspects HTML already fetched by the bounded crawler. It looks for inline event handlers, `javascript:` URLs, source-and-sink co-occurrence in inline scripts (for example, browser-controlled URL sources alongside HTML-string sinks), and same-origin source-map references. It never executes JavaScript, injects payloads, or fetches source maps. These findings are review leads: co-occurrence is not proof of data flow or exploitable XSS.\n\n### 9. Detailed findings and JSON reporting

Every finding can include:
- Stable finding ID plus separate target, resource, behavior, evidence, and test IDs.
- Description, impact, affected URL/component, and observed evidence.
- Severity, qualitative confidence, and a numeric confidence score.
- CWE identifier(s) with MITRE references where mapped.
- CVE identifier(s), CVSS version, score, and vector where applicable.
- Remediation summary and practical remediation steps.

Each scan writes a single UTF-8 `darth-report.json` file designed to open cleanly in Notepad. It contains findings, evidence, coverage totals, scanned page/resource metadata, and optional CVE matches. The scanner does not generate HTML or CSV reports.

## Desktop dashboard (Windows, Linux, macOS with Tk support)

Darth Scanner 0.9.0 includes a persistent local desktop dashboard. It lets you enter a website URL, start or stop an adaptive watch, review unique findings, inspect each finding's IDs/evidence/history, and reopen the same saved target history after restarting the app. The app uses Python's built-in Tkinter; no web server or third-party GUI package is required. On Windows, launch it with `darth-scanner-app` from PowerShell after installation.

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
