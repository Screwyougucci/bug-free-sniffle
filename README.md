# Bug-Free Sniffle — Web & Server Security Scanner

A conventional Python security scanner for websites and server software you own or are explicitly authorized to assess. **This project does not use AI, LLMs, or generative analysis.** Detection is implemented through deterministic checks, HTTP response inspection, software fingerprints, CVE databases, and bounded fuzzing.

> No scanner can guarantee a fixed number of vulnerabilities. Bug-Free Sniffle reports observed weaknesses and candidate CVE matches with evidence; it never invents findings to reach a target count.

## Version 0.2.0 capabilities

### Website and server checks

- Bounded same-origin HTML crawling. Forms are never submitted and JavaScript is never executed.
- HTTP security headers: CSP, HSTS, MIME sniffing protection, Referrer-Policy, Permissions-Policy, and clickjacking controls.
- CSP analysis: unsafe-inline, unsafe-eval, wildcard script sources, missing object-src, base-uri, and frame-ancestors.
- CORS observations: wildcard origins, null origins, and invalid wildcard/credential combinations.
- Cookie analysis: Secure, HttpOnly, SameSite, SameSite=None without Secure, and __Host-/__Secure- prefix rules.
- Cache-control review when responses set cookies.
- HTML checks: mixed content, password forms using GET or non-HTTPS actions, cross-origin password form actions, external scripts without SRI, and target-blank links without opener isolation.
- Response checks for directory-index signatures, common debug pages, stack traces, database error disclosures, and server 5xx responses.
- TLS certificate trust and expiry checks.
- Passive server version fingerprinting from Server, X-Powered-By, and Via response headers for known products including nginx, Apache HTTP Server, PHP, Microsoft IIS, OpenSSL, and OpenResty.

### CVE intelligence and severity

- Matches CPE 2.3 software inventory against a local NVD 2.0 JSON feed.
- Uses NVD's published affected CPE criteria and version boundaries where those are numeric dotted versions.
- Includes CVE ID, English description, CVSS version, base score, vector, qualitative severity, matching CPE evidence, and NVD/advisory references.
- Supports auto-detected server banner fingerprints plus a manually supplied inventory for software not exposed in response headers.

CVSS severity bands:
- **Critical:** 9.0–10.0 (CVSS v3.x/v4.0)
- **High:** 7.0–8.9
- **Medium:** 4.0–6.9
- **Low:** 0.1–3.9

CVSS v2 has no Critical tier; scores 7.0–10.0 are High.

**CVE matches are candidates, not proof of exposure.** A product banner may be spoofed, NVD configuration expressions can require additional platform conditions, and vendors sometimes backport fixes without changing the upstream version string. Verify the exact vendor build, complete configuration, and advisory before treating a match as exploitable.

### Fuzzing and reports

- A conservative GET query-parameter fuzzer with 20 bounded, benign mutation values.
- One request at a time, fixed minimum delay, bounded request count, and no redirects, form submissions, credential guessing, uploads, or exploit payload execution.
- JSON reports include a stable finding ID, description, impact, evidence, CWE identifiers and references where mapped, affected component, severity, confidence, remediation steps, CVSS metadata, references, scan coverage, page status totals, and software inventory.
- Findings are sorted by severity and CVSS score; duplicate finding IDs are collapsed.

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

```bash
python -m darthscanner scan --target https://example.test --scope scope.json --acknowledge-authorization
```

The default report is `darth-report.json`.

## Run a scan with CVE matching

Download an NVD 2.0 JSON feed from the official <https://nvd.nist.gov/vuln/data-feeds> page. Then pass the feed path:

```bash
python -m darthscanner scan \
  --target https://example.test \
  --scope scope.json \
  --acknowledge-authorization \
  --nvd-json ./nvdcve-2.0-recent.json
```

Only software versions visible in response headers can be fingerprinted automatically. To check additional installed components, prepare a CPE inventory such as `asset-inventory.example.json` and add `--inventory ./asset-inventory.json`.

You can also run the CVE matcher separately against an inventory and local NVD feed without sending any network requests:

```bash
python -m darthscanner cve \
  --inventory ./asset-inventory.json \
  --nvd-json ./nvdcve-2.0-recent.json
```

The default CVE-only report is `darth-cve-report.json`.

## Software inventory format

Each component should include a CPE 2.3 identifier. Example:

```json
{
  "components": [
    {
      "name": "nginx",
      "version": "1.18.0",
      "cpe": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    }
  ]
}
```

Use exact vendor/product identifiers from the software vendor or an SBOM. The sample inventory contains illustrative versions only; it does not describe your actual server.

## Run the bounded fuzzer

Use a specific GET URL containing the parameter to be mutated. Prefer a staging application or local test service:

```bash
python -m darthscanner fuzz \
  --url 'https://example.test/search?q=baseline' \
  --param q \
  --scope scope.json \
  --acknowledge-authorization \
  --max-cases 20
```

The fuzzer sends one baseline request plus up to 20 benign mutations. It does not execute SQL injection or XSS payloads. Unusual 5xx responses, status changes, large response-size changes, and slow responses are triage signals requiring manual review—not confirmed vulnerabilities.

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

## Finding quality

- **Finding:** a concrete observed weakness or misconfiguration.
- **Observation:** information disclosure or a hardening opportunity.
- **Candidate vulnerability:** a version/CPE match to a published CVE; verify the vendor advisory, configuration, and patch status.
- **Fuzz anomaly:** a response difference that needs manual reproduction.

Where applicable, findings include CWE identifiers linked to the MITRE CWE definitions. CVE matches include CVSS version, base score, vector, and severity.

No automatic exploit execution is included. Always validate findings before assigning real-world risk.

## Tests

```bash
python -m unittest discover -s tests -v
darth-scanner --help
darth-scanner scan --help
darth-scanner cve --help
```

GitHub Actions tests Python 3.11, 3.12, and 3.13.

## Roadmap

- [x] Strict target scope and request budget
- [x] Same-origin bounded crawler
- [x] Expanded HTTP, cookie, HTML, TLS, debug/error, and directory-index checks
- [x] Passive software version fingerprinting
- [x] Offline NVD/CPE CVE matching with CVSS ratings
- [x] Detailed JSON reports, CWE mappings, and coverage summaries
- [x] Bounded GET parameter fuzzer
- [ ] More server product fingerprints and version parsing
- [ ] Additional TLS protocol/cipher observations
- [ ] HTML report viewer and CSV export
- [ ] More integration fixtures and false-positive regression tests

## License

MIT
