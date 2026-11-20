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
from .api_discovery import discover_static_get_targets
from .cve import load_inventory, load_nvd_feed, match_cves
from .exposure import probe_sensitive_paths
from .fingerprint import fingerprint_response
from .fuzzer import observations_to_dict, replay_case, run_fuzz_many
from .http_client import SafeHttpClient
from .method_checks import inspect_http_methods
from .report import write_report
from .response_audit import inspect_response_behavior
from .server_side_audit import inspect_server_response, inspect_server_fuzz_observations
from .scope import ScopeError, load_scope, require_authorization
from .polyglot_audit import audit_source
from .tls_checks import inspect_tls
from .watch import run_watch
from .sigma_audit import audit_log_file
from .metadata_discovery import discover_api_resources


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

    watch = commands.add_parser("watch", help="continuously rescan an authorized host and alert on new findings")
    watch.add_argument("--target", required=True)
    watch.add_argument("--scope", default="scope.json")
    watch.add_argument("--acknowledge-authorization", action="store_true")
    watch.add_argument("--interval-seconds", type=int, default=300)
    watch.add_argument("--max-cycles", type=int, default=0, help="0 means unlimited cycles in this run")
    watch.add_argument("--output", default="darth-watch-report.json")
    watch.add_argument("--state", default="darth-watch-state.json")

    logs = commands.add_parser("audit-logs", help="review a local text or JSONL server log; no network traffic")
    logs.add_argument("--path", required=True)
    logs.add_argument("--output", default="darth-sigma-report.json")

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
                  source_files_reviewed: int = 0, source_files_skipped: int = 0,
                  api_inventory: dict | None = None) -> dict:
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
        api_inventory=api_inventory,
    )

def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "audit-logs":
            import json
            from pathlib import Path
            result = audit_log_file(args.path)
            Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Sigma-style rules loaded: {result['rules_loaded']}; log lines reviewed: {result['lines_reviewed']}; matches: {len(result['matches'])}.")
            for item in result["matches"]:
                print(f"  [{item['level'].upper()}] {item['title']} (line {item['line']}, {item['rule_id']})")
            print("Log matches are investigation leads, not proof of successful exploitation.")
            print(f"JSON: {args.output}")
            return 0

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

        if args.command == "watch":
            if args.interval_seconds < 60:
                raise ValueError("--interval-seconds must be at least 60.")
            if args.max_cycles < 0:
                raise ValueError("--max-cycles cannot be negative.")
            scope.validate_url(args.target)
            return run_watch(
                target=args.target, scope=args.scope,
                acknowledged=args.acknowledge_authorization,
                interval=args.interval_seconds, output=args.output,
                state_path=args.state, max_cycles=args.max_cycles,
            )


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

            # Static API route discovery: fetch a small number of same-origin scripts
            # already linked by crawled pages, without executing JavaScript. Preserve
            # request budget for actual fuzzing and only queue literal GET URLs.
            script_urls = []
            for page in responses:
                script_urls.extend(extract_same_origin_script_urls(page, limit=12))
            script_responses = []
            seen_scripts = set()
            script_budget = min(8, max(0, client.max_requests - client.requests_made - 4))
            api_targets = []
            for script_url in script_urls:
                if len(script_responses) >= script_budget:
                    break
                if script_url in seen_scripts:
                    continue
                seen_scripts.add(script_url)
                try:
                    scope.validate_url(script_url)
                    script_response = client.get(script_url)
                except (ValueError, RuntimeError):
                    continue
                if script_response.status is None or script_response.status >= 400:
                    continue
                content_type = script_response.headers.get("content-type", "").lower()
                if "javascript" not in content_type and not urlsplit(script_url).path.lower().endswith((".js", ".mjs", ".cjs")):
                    continue
                script_responses.append(script_response)
                api_targets.extend(discover_static_get_targets(
                    script_url, script_response.text, scope,
                    max_targets=max(1, args.max_targets - len(targets)),
                ))

            # Merge page links and statically discovered API routes without duplicates.
            seen_target_urls = {str(item["url"]) for item in targets}
            for item in api_targets:
                if str(item["url"]) not in seen_target_urls and len(targets) < args.max_targets:
                    targets.append(item)
                    seen_target_urls.add(str(item["url"]))

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
            pages.extend(
                {"url": response.url, "status": response.status,
                 "response_bytes": len(response.body),
                 "elapsed_seconds": round(response.elapsed_seconds, 3),
                 "error": response.error, "resource_type": "javascript-static-review"}
                for response in script_responses
            )
            fuzz_data = observations_to_dict(observations)
            server_findings = []
            for response in responses:
                server_findings.extend(inspect_server_response(response))
            server_findings.extend(inspect_server_fuzz_observations(fuzz_data))
            report = _write_bundle(
                args, target=args.target, requests_made=client.requests_made,
                pages=pages, findings=server_findings, fuzz_observations=fuzz_data,
            )
            # Add reproducible, redacted evidence without overstating black-box findings.
            from .evidence import build_reproduction_evidence
            import json
            from pathlib import Path
            report["reproduction_evidence"] = build_reproduction_evidence(fuzz_data)
            report["authorization_scope"] = {
                "allowed_hosts": list(scope.allowed_hosts),
                "host_matching": "exact hostname; subdomains require explicit entries",
                "authorized": scope.authorized,
            }
            Path(args.output).write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            anomaly_count = sum(item.anomaly_score >= 20 for item in observations)
            print(f"Discovered {len(targets)} same-origin query URL(s) across {len(responses)} crawled page(s) and {len(script_responses)} static JavaScript file(s); {len(api_targets)} API route candidate(s) came from literal GET calls.")
            print(f"Coverage-guided tests: {mutations} benign mutations across {len({item.endpoint_url for item in observations})} endpoint(s) and {len({(item.endpoint_url, item.parameter) for item in observations})} parameter(s).")
            print(f"High-priority anomaly signals (score >= 20): {anomaly_count}; total HTTP requests: {client.requests_made}.")
            print("Scores prioritize unusual behavior; they are not vulnerability probabilities or proof of exploitability.")
            print(f"JSON: {args.output}")
            return 0

        if args.command == "scan":
            scope.validate_url(args.target)
            client = SafeHttpClient(scope)
            scan_scope = replace(scope, max_pages=min(scope.max_pages, max(1, scope.max_requests - 27)))
            responses = crawl(args.target, scan_scope, client)
            api_budget = min(7, max(0, client.max_requests - client.requests_made - 20))
            api_inventory = (discover_api_resources(args.target, scope, client, max_resources=api_budget)
                             if api_budget else {"resources": [], "api_endpoints": [],
                                                 "sitemap_urls_discovered": [],
                                                 "robots_sitemaps_discovered": [],
                                                 "note": "Skipped: request budget reserve preserved."})
            findings = []
            components_by_cpe = {}
            script_urls = []
            for response in responses:
                findings.extend(inspect_http(response))
                findings.extend(inspect_html(response))
                findings.extend(inspect_response_behavior(response))
                findings.extend(inspect_server_response(response))
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
                findings.extend(inspect_server_response(script_response))

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
                api_inventory=api_inventory,
            )
            print(f"Scanned {len(responses)} HTML page(s) and statically reviewed {len(script_responses)} same-origin JavaScript file(s); {client.requests_made} HTTP request(s).")
            print(f"Exposure paths checked: {exposure_paths_checked}; TLS probes attempted: {tls_probes}.")
            print(f"Software fingerprints: {len(components)}")
            print(f"API paths inventoried: {len(api_inventory.get('api_endpoints', []))}; metadata resources checked: {len(api_inventory.get('resources', []))}.")
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
