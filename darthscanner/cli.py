"""Command-line interface."""
from __future__ import annotations

import argparse
from collections import Counter
import sys

from . import __version__
from .checks import inspect_html, inspect_http
from .crawler import crawl
from .cve import load_inventory, load_nvd_feed, match_cves
from .fingerprint import fingerprint_response
from .fuzzer import observations_to_dict, run_fuzz
from .http_client import SafeHttpClient
from .report import write_report
from .scope import ScopeError, load_scope, require_authorization
from .tls_checks import inspect_tls


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="darth-scanner",
        description="A conventional, scope-controlled web and server security scanner. No AI components.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="crawl same-origin pages and run passive checks")
    scan.add_argument("--target", required=True, help="starting http(s) URL")
    scan.add_argument("--scope", default="scope.json", help="authorization scope JSON")
    scan.add_argument("--acknowledge-authorization", action="store_true")
    scan.add_argument("--nvd-json", help="optional local NVD 2.0 JSON feed for CVE matching")
    scan.add_argument("--inventory", help="optional CPE inventory JSON to add to discovered software")
    scan.add_argument("--output", default="darth-report.json")

    fuzz = commands.add_parser("fuzz", help="run bounded, benign GET query-parameter fuzzing")
    fuzz.add_argument("--url", required=True, help="specific GET URL containing the parameter")
    fuzz.add_argument("--param", required=True, help="exact query parameter name to mutate")
    fuzz.add_argument("--scope", default="scope.json")
    fuzz.add_argument("--acknowledge-authorization", action="store_true")
    fuzz.add_argument("--max-cases", type=int, default=9, help="1-20 benign mutations")
    fuzz.add_argument("--output", default="darth-fuzz-report.json")

    cve = commands.add_parser("cve", help="match a software inventory against a local NVD 2.0 JSON feed")
    cve.add_argument("--inventory", required=True, help="JSON inventory containing CPE 2.3 component identifiers")
    cve.add_argument("--nvd-json", required=True, help="local NVD 2.0 JSON feed")
    cve.add_argument("--output", default="darth-cve-report.json")
    return parser


def _print_finding_summary(findings) -> None:
    counts = Counter(item.severity for item in findings)
    order = ("critical", "high", "medium", "low", "info")
    summary = ", ".join(f"{level}: {counts[level]}" for level in order if counts[level])
    print(f"Findings: {len(findings)}" + (f" ({summary})" if summary else ""))
    for item in findings:
        if item.category == "cve":
            rating = f"CVSS {item.cvss_version or 'n/a'} {item.cvss_score:.1f}" if item.cvss_score is not None else "CVSS unscored"
            print(f"  [{item.severity.upper()}] {item.title} — {rating}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "cve":
            components = load_inventory(args.inventory)
            feed = load_nvd_feed(args.nvd_json)
            findings = match_cves(components, feed)
            software = [component.to_dict() for component in components]
            write_report(args.output, target=args.inventory, requests_made=0,
                         pages=[], findings=findings, software_components=software)
            print(f"Loaded {len(components)} software component(s) and {len(feed)} CVE record(s).")
            _print_finding_summary(findings)
            print(f"Detailed report: {args.output}")
            return 0

        scope = load_scope(args.scope)
        require_authorization(scope, args.acknowledge_authorization)

        if args.command == "scan":
            scope.validate_url(args.target)
            client = SafeHttpClient(scope)
            responses = crawl(args.target, scope, client)
            findings = []
            components_by_cpe = {}
            for response in responses:
                findings.extend(inspect_http(response))
                findings.extend(inspect_html(response))
                for component in fingerprint_response(response):
                    components_by_cpe[component.cpe] = component
            findings.extend(inspect_tls(args.target, scope))

            if args.inventory:
                for component in load_inventory(args.inventory):
                    components_by_cpe[component.cpe] = component
            components = list(components_by_cpe.values())

            if args.nvd_json:
                feed = load_nvd_feed(args.nvd_json)
                cve_findings = match_cves(components, feed)
                findings.extend(cve_findings)
                print(f"CVE matching: {len(components)} component(s) against {len(feed)} NVD record(s).")

            pages = [
                {"url": r.url, "status": r.status, "response_bytes": len(r.body),
                 "elapsed_seconds": round(r.elapsed_seconds, 3), "error": r.error}
                for r in responses
            ]
            software = [component.to_dict() for component in components]
            write_report(args.output, target=args.target, requests_made=client.requests_made,
                         pages=pages, findings=findings, software_components=software)
            print(f"Scanned {len(responses)} page(s); {client.requests_made} request(s).")
            print(f"Software fingerprints: {len(components)}")
            _print_finding_summary(findings)
            print(f"Detailed report: {args.output}")
            return 0

        if args.max_cases < 1 or args.max_cases > 20:
            raise ValueError("--max-cases must be between 1 and 20.")
        scope.validate_url(args.url)
        client = SafeHttpClient(scope, max_requests=min(scope.max_requests, args.max_cases + 1))
        observations = run_fuzz(args.url, args.param, scope, client, args.max_cases)
        write_report(args.output, target=args.url, requests_made=client.requests_made,
                     pages=[], findings=[], fuzz_observations=observations_to_dict(observations))
        anomalies = sum("no notable" not in item.note for item in observations)
        print(f"Fuzzed {args.param!r} with {len(observations)} benign mutation(s).")
        print(f"Observations requiring review: {anomalies}")
        print("These are robustness signals, not confirmed vulnerabilities.")
        print(f"Report: {args.output}")
        return 0
    except (ScopeError, ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
