"""Command-line interface for the deterministic scanner."""
from __future__ import annotations

import argparse
from dataclasses import replace
from collections import Counter
import sys
from urllib.parse import urlsplit

from . import __version__
from .checks import inspect_html, inspect_http
from .browser_audit import inspect_browser_code
from .js_research import extract_same_origin_script_urls, inspect_javascript_source
from .crawler import crawl
from .discovery import discover_query_targets
from .cve import load_inventory, load_nvd_feed, match_cves
from .exposure import probe_sensitive_paths
from .fingerprint import fingerprint_response
from .fuzzer import observations_to_dict, replay_case, run_fuzz_many
from .http_client import SafeHttpClient
from .method_checks import inspect_http_methods
from .report import write_report
from .response_audit import inspect_response_behavior
from .scope import ScopeError, load_scope, require_authorization
from .polyglot_audit import audit_source
from .tls_checks import inspect_tls


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="darth-scanner",
        description="A deterministic, scope-controlled web and server security scanner. No AI components.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="crawl a site, check server/TLS settings, and inspect exposure paths")
    scan.add_argument("--target", required=True, help="starting http(s) URL")
    scan.add_argument("--scope", default="scope.json", help="authorization scope JSON")
    scan.add_argument("--acknowledge-authorization", action="store_true")
    scan.add_argument("--nvd-json", help="optional local NVD 2.0 JSON feed for CVE matching")
    scan.add_argument("--inventory", help="optional CPE inventory JSON to add to discovered software")
    scan.add_argument("--output", default="darth-report.json", help="JSON report output")

    fuzz = commands.add_parser("fuzz", help="run bounded, benign GET query-parameter fuzzing")
    fuzz.add_argument("--url", required=True, help="specific GET URL containing the parameter")
    fuzz.add_argument("--param", required=True, help="exact query parameter name, or * to fuzz all existing query parameters (maximum 8)")
    fuzz.add_argument("--scope", default="scope.json")
    fuzz.add_argument("--acknowledge-authorization", action="store_true")
    fuzz.add_argument("--max-cases", type=int, default=16, help="1-32 total benign mutations across selected parameters")
    fuzz.add_argument("--output", default="darth-fuzz-report.json")

    research = commands.add_parser(
        "research",
        help="discover same-origin query routes and run bounded coverage-guided GET robustness tests",
    )
    research.add_argument("--target", required=True, help="starting URL on the authorized host")
    research.add_argument("--scope", default="scope.json")
    research.add_argument("--acknowledge-authorization", action="store_true")
    research.add_argument("--max-pages", type=int, default=12, help="maximum pages to crawl before fuzzing (1-40)")
    research.add_argument("--max-targets", type=int, default=30, help="maximum discovered query URLs (1-50)")
    research.add_argument("--max-cases", type=int, default=32, help="maximum benign mutations total (1-32)")
    research.add_argument("--output", default="darth-research-report.json")

    replay = commands.add_parser(
        "replay",
        help="repeat one named benign fuzz case exactly once for confirmation",
    )
    replay.add_argument("--url", required=True, help="original query URL from a research report")
    replay.add_argument("--param", required=True, help="query parameter name")
    replay.add_argument("--case", required=True, help="named benign case from the JSON report")
    replay.add_argument("--scope", default="scope.json")
    replay.add_argument("--acknowledge-authorization", action="store_true")
    replay.add_argument("--output", default="darth-replay-report.json")

    cve = commands.add_parser("cve", help="match a software inventory against a local NVD 2.0 JSON feed")
    cve.add_argument("--inventory", required=True, help="JSON inventory containing CPE 2.3 component identifiers")
    cve.add_argument("--nvd-json", required=True, help="local NVD 2.0 JSON feed")
    cve.add_argument("--output", default="darth-cve-report.json")

    audit = commands.add_parser(
        "audit-code",
        help="statically inspect local source files for security bug candidates",
    )
    audit.add_argument("--path", required=True, help="local source file or directory (Python, JavaScript/TypeScript, PHP, Java, Go, Rust)")
    audit.add_argument("--max-files", type=int, default=1000, help="maximum supported source files to inspect (1-10000)")
    audit.add_argument("--output", default="darth-source-report.json")
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


def _write_bundle(args, *, target: str, requests_made: int, pages: list[dict],
                  findings: list, software: list[dict] | None = None,
                  fuzz_observations: list[dict] | None = None,
                  exposure_paths_checked: int = 0, tls_probes: int = 0,
                  source_files_reviewed: int = 0, source_files_skipped: int = 0) -> dict:
    """Write the single Notepad-friendly JSON report."""
    return write_report(
        args.output,
        target=target,
        requests_made=requests_made,
        pages=pages,
        findings=findings,
        fuzz_observations=fuzz_observations,
        software_components=software,
        exposure_paths_checked=exposure_paths_checked,
        tls_probes=tls_probes,
        source_files_reviewed=source_files_reviewed,
        source_files_skipped=source_files_skipped,
    )

def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "audit-code":
            if not 1 <= args.max_files <= 10000:
                raise ValueError("--max-files must be between 1 and 10000.")
            findings, reviewed, skipped = audit_source(args.path, max_files=args.max_files)
            _write_bundle(
                args,
                target=str(args.path),
                requests_made=0,
                pages=[],
                findings=findings,
                source_files_reviewed=reviewed,
                source_files_skipped=skipped,
            )
            print(f"Supported source files reviewed: {reviewed}; skipped: {skipped}.")
            print("Python uses AST analysis; other languages use conservative pattern matching. These are review leads, not proof of a zero-day or exploitability.")
            _print_finding_summary(findings)
            print(f"JSON: {args.output}")
            return 0

        if args.command == "cve":
            components = load_inventory(args.inventory)
            feed = load_nvd_feed(args.nvd_json)
            findings = match_cves(components, feed)
            software = [component.to_dict() for component in components]
            _write_bundle(args, target=args.inventory, requests_made=0,
                          pages=[], findings=findings, software=software)
            print(f"Loaded {len(components)} software component(s) and {len(feed)} CVE record(s).")
            _print_finding_summary(findings)
            print(f"JSON: {args.output}")
            return 0

        scope = load_scope(args.scope)
        require_authorization(scope, args.acknowledge_authorization)

        if args.command == "replay":
            scope.validate_url(args.url)
            client = SafeHttpClient(scope, max_requests=1)
            observation = replay_case(args.url, args.param, args.case, scope, client)
            _write_bundle(
                args, target=args.url, requests_made=client.requests_made,
                pages=[], findings=[], fuzz_observations=[observation],
            )
            print(f"Replayed benign case {args.case!r} for parameter {args.param!r}.")
            print(f"HTTP status: {observation['status']}; response bytes: {observation['response_bytes']}.")
            print("Compare the response hash with the original research report; one replay is not proof of a vulnerability.")
            print(f"JSON: {args.output}")
            return 0

        if args.command == "research":
            if not 1 <= args.max_pages <= 40:
                raise ValueError("--max-pages must be between 1 and 40.")
            if not 1 <= args.max_targets <= 50:
                raise ValueError("--max-targets must be between 1 and 50.")
            if not 1 <= args.max_cases <= 32:
                raise ValueError("--max-cases must be between 1 and 32.")
            scope.validate_url(args.target)
            client = SafeHttpClient(scope)
            research_scope = replace(scope, max_pages=min(scope.max_pages, args.max_pages))
            responses = crawl(args.target, research_scope, client)
            targets = discover_query_targets(responses, scope, max_targets=args.max_targets)
            observations = []
            mutations = 0
            for target in targets:
                if mutations >= args.max_cases:
                    break
                remaining_requests = client.max_requests - client.requests_made
                remaining_mutations = args.max_cases - mutations
                if remaining_requests < 2 or remaining_mutations < 1:
                    break
                parameters = list(target["parameters"])
                selected_count = min(8, len(parameters), remaining_requests // 2, remaining_mutations)
                if selected_count < 1:
                    continue
                selected = parameters[:selected_count]
                mutation_budget = min(remaining_mutations, remaining_requests - selected_count)
                if mutation_budget < selected_count:
                    selected = selected[:mutation_budget]
                    mutation_budget = len(selected)
                if not selected:
                    continue
                try:
                    batch = run_fuzz_many(
                        str(target["url"]), selected, scope, client, mutation_budget
                    )
                except ValueError:
                    continue
                observations.extend(batch)
                mutations += len(batch)

            pages = [
                {"url": response.url, "status": response.status,
                 "response_bytes": len(response.body),
                 "elapsed_seconds": round(response.elapsed_seconds, 3),
                 "error": response.error, "resource_type": "html-or-linked-resource"}
                for response in responses
            ]
            _write_bundle(
                args, target=args.target, requests_made=client.requests_made,
                pages=pages, findings=[],
                fuzz_observations=observations_to_dict(observations),
            )
            anomaly_count = sum(item.anomaly_score >= 20 for item in observations)
            print(f"Discovered {len(targets)} same-origin query URL(s) across {len(responses)} crawled page(s).")
            print(f"Coverage-guided tests: {mutations} benign mutations across {len({item.endpoint_url for item in observations})} endpoint(s) and {len({(item.endpoint_url, item.parameter) for item in observations})} parameter(s).")
            print(f"High-priority anomaly signals (score >= 20): {anomaly_count}; total HTTP requests: {client.requests_made}.")
            print("Scores prioritize unusual behavior; they are not vulnerability probabilities or proof of exploitability.")
            print(f"JSON: {args.output}")
            return 0

        if args.command == "scan":
            scope.validate_url(args.target)
            client = SafeHttpClient(scope)
            responses = crawl(args.target, scope, client)
            findings = []
            components_by_cpe = {}
            script_urls = []
            for response in responses:
                findings.extend(inspect_http(response))
                findings.extend(inspect_html(response))
                findings.extend(inspect_response_behavior(response))
                findings.extend(inspect_browser_code(response))
                script_urls.extend(extract_same_origin_script_urls(response))
                for component in fingerprint_response(response):
                    components_by_cpe[component.cpe] = component

            # Review a bounded number of same-origin JavaScript files. Keep at least
            # 20 requests available for the existing exposure/method checks.
            script_budget = max(0, min(12, client.max_requests - client.requests_made - 20))
            script_responses = []
            seen_scripts = set()
            for script_url in script_urls:
                if len(script_responses) >= script_budget or script_url in seen_scripts:
                    break
                seen_scripts.add(script_url)
                try:
                    scope.validate_url(script_url)
                except ValueError:
                    continue
                script_response = client.get(script_url)
                if script_response.status is None or script_response.status >= 400:
                    continue
                content_type = script_response.headers.get("content-type", "").lower()
                if "javascript" not in content_type and not urlsplit(script_url).path.lower().endswith((".js", ".mjs")):
                    continue
                script_responses.append(script_response)
                findings.extend(inspect_javascript_source(script_url, script_response.text))

            tls_probes = 0
            if urlsplit(args.target).scheme.lower() == "https":
                findings.extend(inspect_tls(args.target, scope))
                tls_probes = 6

            before_exposure = client.requests_made
            findings.extend(probe_sensitive_paths(args.target, scope, client, max_paths=18))
            exposure_paths_checked = client.requests_made - before_exposure

            findings.extend(inspect_http_methods(args.target, scope, client))

            if args.inventory:
                for component in load_inventory(args.inventory):
                    components_by_cpe[component.cpe] = component
            components = list(components_by_cpe.values())

            if args.nvd_json:
                feed = load_nvd_feed(args.nvd_json)
                findings.extend(match_cves(components, feed))
                print(f"CVE matching: {len(components)} component(s) against {len(feed)} NVD record(s).")

            pages = [
                {"url": r.url, "status": r.status, "response_bytes": len(r.body),
                 "elapsed_seconds": round(r.elapsed_seconds, 3), "error": r.error,
                 "resource_type": "html"}
                for r in responses
            ]
            pages.extend(
                {"url": r.url, "status": r.status, "response_bytes": len(r.body),
                 "elapsed_seconds": round(r.elapsed_seconds, 3), "error": r.error,
                 "resource_type": "javascript"}
                for r in script_responses
            )
            software = [component.to_dict() for component in components]
            _write_bundle(
                args, target=args.target, requests_made=client.requests_made,
                pages=pages, findings=findings, software=software,
                exposure_paths_checked=exposure_paths_checked, tls_probes=tls_probes,
            )
            print(f"Scanned {len(responses)} HTML page(s) and statically reviewed {len(script_responses)} same-origin JavaScript file(s); {client.requests_made} HTTP request(s).")
            print(f"Exposure paths checked: {exposure_paths_checked}; TLS probes attempted: {tls_probes}.")
            print(f"Software fingerprints: {len(components)}")
            _print_finding_summary(findings)
            print(f"JSON: {args.output}")
            return 0

        if args.max_cases < 1 or args.max_cases > 32:
            raise ValueError("--max-cases must be between 1 and 32.")
        scope.validate_url(args.url)
        client = SafeHttpClient(scope, max_requests=min(scope.max_requests, args.max_cases + (8 if args.param == "*" else 1)))
        observations = run_fuzz_many(args.url, ["*"] if args.param == "*" else [args.param], scope, client, args.max_cases)
        _write_bundle(
            args, target=args.url, requests_made=client.requests_made, pages=[],
            findings=[], fuzz_observations=observations_to_dict(observations),
        )
        anomalies = sum("no notable" not in item.note for item in observations)
        print(f"Fuzzed parameter selection {args.param!r} with {len(observations)} benign mutation(s).")
        print(f"Observations requiring review: {anomalies}")
        print(f"Distinct response bodies: {sum(item.response_changed for item in observations)}; location changes: {sum(item.location_changed for item in observations)}; 5xx responses: {sum(item.server_error for item in observations)}.")
        print("These are robustness signals, not confirmed vulnerabilities.")
        print(f"JSON: {args.output}")
        return 0
    except (ScopeError, ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
