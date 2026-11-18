# Bug-Free Sniffle — Web Security Scanner

A scope-controlled web security assessment tool for systems you own or are explicitly authorized to test.

> **No scanner can guarantee a fixed number of vulnerabilities.** This project reports evidence-backed findings and coverage counts. It never invents findings to satisfy a target.

## What it does

- Same-origin, bounded HTML link crawling.
- Passive checks for HTTP security headers, cookie flags, TLS certificate validity, and server-banner disclosure.
- A deliberately conservative **GET query-parameter fuzzer** for robustness testing. It uses benign boundary, encoding, whitespace, Unicode, and type-like values; it does not attempt exploitation, authentication bypass, data extraction, or denial of service.
- JSON reports with evidence, severity, confidence, and remediation.
- Exact-host scope allowlisting, explicit authorization acknowledgement, request ceilings, timeouts, and a minimum request interval.
- Unit tests and CI.

## Quick start

Requires Python 3.11+; no third-party packages are required.

1. Copy `scope.example.json` to `scope.json`.
2. Set `authorized` to `true` only after confirming you have permission.
3. Add the exact hostname(s) you are permitted to assess.
4. Run a passive scan:

```bash
python -m darthscanner scan --target https://example.test --scope scope.json --acknowledge-authorization
```

Run the safe query fuzzer against a specific GET URL and parameter:

```bash
python -m darthscanner fuzz \
  --url 'https://example.test/search?q=baseline' \
  --param q \
  --scope scope.json \
  --acknowledge-authorization
```

Use only a staging target or a local lab for fuzzing. The fuzzer defaults to at most 20 requests, one request at a time, with a minimum 1-second delay. It will not follow redirects, submit forms, or send requests to hosts outside the exact allowlist.

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

Do not include credentials, session cookies, or secrets in scope files. Keep real scope files out of source control.

## Fuzzing safety model

The fuzzer:
- Uses GET only and mutates only the named query parameter.
- Uses short, non-exploit test strings and small boundary values.
- Caps the number of requests at 20 by default and 30 absolutely.
- Enforces at least 0.5 seconds between requests.
- Does not follow redirects, crawl discovered links, brute-force credentials, or upload files.
- Records response status, length, and elapsed time as **anomalies**, not proof of a vulnerability.

Do not run it against third-party systems without written authorization. For invasive testing, use a purpose-built lab and a separately reviewed test plan.

## Finding quality

A scanner alert is not automatically an exploitable vulnerability. Each report distinguishes:
- **Finding**: a concrete observed issue, such as a missing security header.
- **Observation**: a version/banner or behavior worth investigating.
- **Fuzz anomaly**: an unusual response that requires manual review.

No automatic exploit execution is included.

## Development

```bash
python -m unittest discover -s tests -v
python -m darthscanner --help
```

## Roadmap

- [x] Strict scope enforcement and request budget
- [x] Same-origin bounded crawler
- [x] Passive HTTP and TLS checks
- [x] Safe GET parameter fuzzing
- [x] JSON report output
- [ ] OpenAPI document inventory and schema-aware non-destructive fuzzing
- [ ] Local CVE feed import and software inventory matching
- [ ] HTML report viewer
- [ ] Additional regression fixtures

## License

MIT
