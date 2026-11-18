# Bug-Free Sniffle — Web Security Scanner

A scope-controlled web security assessment tool for systems you own or are explicitly authorized to test.

> **No scanner can guarantee a fixed number of vulnerabilities.** Bug-Free Sniffle reports observed issues with evidence and confidence; it never invents findings to reach a target count.

## Current capabilities

- Same-origin, bounded HTML crawling. Forms are never submitted and JavaScript is never executed.
- HTTP checks: CSP presence and risky directives, HSTS presence and short max-age, MIME sniffing protection, Referrer-Policy, Permissions-Policy, CORS wildcard behavior, cache behavior for cookie-setting responses, and server technology banners.
- Cookie checks: Secure, HttpOnly, SameSite, SameSite=None without Secure.
- HTML checks: mixed-content references, password forms using GET, password forms resolving to non-HTTPS actions, cross-origin scripts without Subresource Integrity, and target-blank links without opener isolation.
- TLS certificate trust and expiry checks.
- A conservative **GET query-parameter fuzzer** using benign empty, numeric, boundary-length, whitespace, Unicode, and reserved-character values.
- JSON reports containing evidence, severity, confidence, remediation, page inventory, and fuzz anomalies.
- Exact-host allowlisting, explicit authorization acknowledgement, bounded requests, request delays, timeouts, and no automatic redirect following.

These are detection checks and review signals—not a promise of 50 exploitable bugs. A well-secured site may produce zero vulnerability findings. The safe fuzzer does not attempt SQL injection, XSS execution, authentication bypass, data extraction, or denial of service.

## Install

Requires Python 3.11+; runtime uses only the Python standard library.

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

## Run a passive scan

```bash
python -m darthscanner scan --target https://example.test --scope scope.json --acknowledge-authorization
```

The report is written to `darth-report.json` by default. You can choose another path with `--output`.

## Run the safe fuzzer

Use a specific GET URL containing the parameter to be mutated. Run it against a staging system or a local test app:

```bash
python -m darthscanner fuzz \
  --url 'https://example.test/search?q=baseline' \
  --param q \
  --scope scope.json \
  --acknowledge-authorization
```

The fuzzer sends one request at a time, uses the configured delay (minimum 0.5 seconds), defaults to 9 mutations plus one baseline request, and limits a run to at most 20 mutations. It does not follow redirects, submit forms, brute-force credentials, upload files, or access other hosts. Unusual 5xx responses, status changes, large response-size changes, or slow responses are reported as **triage signals**, not confirmed vulnerabilities.

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

## Findings are not all vulnerabilities

- **Finding**: a concrete observed weakness or misconfiguration.
- **Observation**: information disclosure or a hardening opportunity.
- **Fuzz anomaly**: a response difference that requires manual reproduction and review.

No exploit execution is included. Always validate findings manually and review application/server logs before assigning severity.

## Test

```bash
python -m unittest discover -s tests -v
python -m darthscanner --help
```

GitHub Actions runs the unit tests on Python 3.11, 3.12, and 3.13.

## Roadmap

- [x] Exact-host scope enforcement and request budget
- [x] Same-origin bounded crawler
- [x] Passive HTTP, cookie, HTML, and TLS checks
- [x] Safe GET query-parameter fuzzing
- [x] JSON evidence reports
- [ ] OpenAPI inventory and schema-aware non-destructive API fuzzing
- [ ] Local CVE feed import and cautious software-version matching
- [ ] HTML report viewer
- [ ] Additional regression fixtures and integration tests

## License

MIT
