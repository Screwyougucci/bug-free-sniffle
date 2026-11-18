"""Command-line interface."""
from __future__ import annotations

import argparse
from collections import Counter
import sys

from . import __version__
from .checks import inspect_html, inspect_http
from .crawler import crawl
from .fuzzer import observations_to_dict, run_fuzz
from .http_client import SafeHttpClient
from .report import write_report
from .scope import ScopeError, load_scope, require_authorization
from .tls_checks import inspect_tls


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="darth-scanner",
        description="Scope-controlled, non-destructive web security assessment.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="crawl same-origin pages and run passive checks")
    scan.add_argument("--target", required=True, help="starting http(s) URL")
    scan.add_argument("--scope", default="scope.json", help="authorization scope JSON")
    scan.add_argument("--acknowledge-authorization", action="store_true")
    scan.add_argument("--output", default="darth-report.json")

    fuzz = commands.add_parser("fuzz", help="run bounded, benign GET query-parameter fuzzing")
    fuzz.add_argument("--url", required=True, help="specific GET URL containing the parameter")
    fuzz.add_argument("--param", required=True, help="exact query parameter name to mutate")
    fuzz.add_argument("--scope", default="scope.json")
    fuzz.add_argument("--acknowledge-authorization", action="store_true")
    fuzz.add_argument("--max-cases", type=int, default=9, help="1-20 benign mutations")
    fuzz.add_argument("--output", default="darth-fuzz-report.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        scope = load_scope(args.scope)
        require_authorization(scope, args.acknowledge_authorization)
        if args.command == "scan":
            scope.validate_url(args.target)
            client = SafeHttpClient(scope)
            responses = crawl(args.target, scope, client)
            findings = []
            for response in responses:
                findings.extend(inspect_http(response))
                findings.extend(inspect_html(response))
            findings.extend(inspect_tls(args.target, scope))
            pages = [
                {"url": r.url, "status": r.status, "response_bytes": len(r.body),
                 "elapsed_seconds": round(r.elapsed_seconds, 3), "error": r.error}
                for r in responses
            ]
            write_report(args.output, target=args.target, requests_made=client.requests_made,
                         pages=pages, findings=findings)
            counts = Counter(f.severity for f in findings)
            print(f"Scanned {len(responses)} page(s); {client.requests_made} request(s).")
            print(f"Findings: {len(findings)} | " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
            print(f"Report: {args.output}")
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
