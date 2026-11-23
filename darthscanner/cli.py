"""Command-line interface for the deterministic scanner."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import sys
from urllib.parse import urlsplit

from . import __version__
from .checks import inspect_html, inspect_http
from .browser_audit import inspect_browser_code
from .js_research import extract_same_origin_script_urls, inspect_javascript_source
from .crawler import crawl
from .cve import load_inventory, load_nvd_feed, match_cves
from .cve_online import lookup_cves_for_components
from .exposure import probe_sensitive_paths
from .fingerprint import fingerprint_response
from .fuzzer import discover_query_parameters, observations_to_dict, run_fuzz_suite, sanitize_url
from .http_client import SafeHttpClient
from .method_checks import inspect_http_methods
from .report import write_report
from .scope import ScopeError, load_scope, require_authorization
from .source_audit import audit_python_source
from .github_audit import audit_github_repository
from .tls_checks import inspect_tls
from .watch import run_watch
from .subdomains import discover_subdomain_tree


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
    scan.add_argument("--no-cve-lookup", action="store_true", help="disable automatic NVD CVE lookup")
    scan.add_argument("--inventory", help="optional CPE inventory JSON to add to discovered software")
    scan.add_argument("--output", default="darth-report.json", help="JSON report output")
    scan.add_argument("--profile", choices=("full", "web", "tls", "exposure", "methods"), default="full", help="select one bounded analysis profile")
    scan.add_argument("--focus", choices=("all", "headers", "cookies", "cors", "redirects", "html", "browser", "javascript", "fingerprint"), default="all", help="run one analysis category on the fetched response")

    watch = commands.add_parser("watch", help="continuously choose applicable focused web analyses")
    watch.add_argument("--target", required=True, help="starting http(s) URL")
    watch.add_argument("--scope", default="scope.json", help="authorization scope JSON")
    watch.add_argument("--acknowledge-authorization", action="store_true")
    watch.add_argument("--output-dir", default="darth-watch-reports", help="directory for per-cycle JSON reports and history")
    watch.add_argument("--interval", type=int, default=30, help="seconds between adaptive checks (minimum 30)")
    watch.add_argument("--cycles", type=int, help="optional number of profiles to run; default is unlimited")
    watch.add_argument("--no-cve-lookup", action="store_true", help="disable automatic NVD CVE lookup")

    fuzz = commands.add_parser("fuzz", help="run bounded, benign GET query-parameter fuzzing")
    fuzz.add_argument("--url", required=True, help="specific GET URL containing the parameter")
    fuzz.add_argument("--param", action="append", help="query parameter to mutate; repeat to select multiple (default: discover from URL)")
    fuzz.add_argument("--scope", default="scope.json")
    fuzz.add_argument("--acknowledge-authorization", action="store_true")
    fuzz.add_argument("--max-cases", type=int, default=12, help="1-32 benign mutations per parameter, shared request budget applies")
    fuzz.add_argument("--max-params", type=int, default=8, help="maximum automatically discovered query parameters (1-16)")
    fuzz.add_argument("--output", default="darth-fuzz-report.json")

    cve = commands.add_parser("cve", help="match a software inventory against a local NVD 2.0 JSON feed")
    cve.add_argument("--inventory", required=True, help="JSON inventory containing CPE 2.3 component identifiers")
    cve.add_argument("--nvd-json", required=True, help="local NVD 2.0 JSON feed")
    cve.add_argument("--output", default="darth-cve-report.json")

    audit = commands.add_parser(
        "audit-code",
        help="statically inspect local Python source for security bug candidates",
    )
    audit.add_argument("--path", required=True, help="local Python file or source directory")
    audit.add_argument("--max-files", type=int, default=1000, help="maximum Python files to inspect (1-10000)")
    audit.add_argument("--output", default="darth-source-report.json")

    github_audit = commands.add_parser("audit-github", help="statically inspect an authorized GitHub repository without executing its code")
    github_audit.add_argument("--repo", required=True, help="GitHub repository URL (owner/repository)")
    github_audit.add_argument("--max-files", type=int, help="maximum source files (40 public, 180 with GITHUB_TOKEN)")
    github_audit.add_argument("--output", default="darth-github-source-report.json")
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
                  cve_lookup_status: dict | None = None,
                  domain_discovery: dict | None = None) -> dict:
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
        cve_lookup_status=cve_lookup_status,
        domain_discovery=domain_discovery,
    )

def main(argv: list[str] | None = None, stop_event=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "audit-code":
            if not 1 <= args.max_files <= 10000:
                raise ValueError("--max-files must be between 1 and 10000.")
            findings, reviewed, skipped = audit_python_source(args.path, max_files=args.max_files)
            _write_bundle(
                args,
                target=str(args.path),
                requests_made=0,
                pages=[],
                findings=findings,
                source_files_reviewed=reviewed,
                source_files_skipped=skipped,
            )
            print(f"Python source files reviewed: {reviewed}; skipped: {skipped}.")
            print("These are static-review leads, not proof of a zero-day or exploitability.")
            _print_finding_summary(findings)
            print(f"JSON: {args.output}")
            return 0

        if args.command == "audit-github":
            findings, summary = audit_github_repository(args.repo, max_files=args.max_files)
            _write_bundle(args, target=summary["repository_url"], requests_made=0, pages=[], findings=findings,
                          source_files_reviewed=summary["files_reviewed"], source_files_skipped=summary["files_skipped"])
            print(f"GitHub repository: {summary['repository']} ({summary['access_mode']}).")
            print(f"Source files reviewed: {summary['files_reviewed']}; skipped: {summary['files_skipped']}; bytes: {summary['bytes_reviewed']}.")
            print("Repository code was not executed or modified. Static matches are unconfirmed review leads.")
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

        if args.command == "watch":
            return run_watch(
                target=args.target,
                scope_path=args.scope,
                acknowledge_authorization=args.acknowledge_authorization,
                output_dir=args.output_dir,
                interval=args.interval,
                cycles=args.cycles,
            )

        scope = load_scope(args.scope)
        require_authorization(scope, args.acknowledge_authorization)

        if args.command == "scan":
            scope.validate_url(args.target)
            client = SafeHttpClient(scope, stop_event=stop_event)
            profile = args.profile
            responses = []
            discovered_subdomains = []
            if profile in {"full", "web"}:
                if scope.include_subdomains:
                    discovered_subdomains = discover_subdomain_tree(
                        scope.root_domain or "",
                        max_depth=scope.max_subdomain_depth,
                        limit=scope.max_subdomain_hosts,
                        timeout=scope.timeout_seconds,
                    )
                    print(
                        f"Recursive passive discovery found {len(discovered_subdomains)} DNS-verified host(s) "
                        f"(depth <= {scope.max_subdomain_depth}, host limit {scope.max_subdomain_hosts})."
                    )
                    for item in discovered_subdomains:
                        print(f"  {'  ' * max(0, item['depth'] - 1)}└─ {item['host']} (depth {item['depth']})")
                    print("Names are CT candidates verified by public DNS; active checks remain inside the authorized root-domain boundary.")
                host_targets = [args.target]
                scheme = urlsplit(args.target).scheme.lower()
                host_targets.extend(f"{scheme}://{item['host']}/" for item in discovered_subdomains)
                for host_target in host_targets:
                    remaining_pages = scope.max_pages - len(responses)
                    remaining_requests = client.max_requests - client.requests_made
                    if remaining_pages <= 0 or remaining_requests <= 0:
                        break
                    try:
                        scope.validate_url(host_target)
                    except ScopeError:
                        continue
                    responses.extend(crawl(host_target, scope, client, max_pages=remaining_pages))
            findings = []
            components_by_cpe = {}
            script_urls = []
            focus = args.focus
            http_focus_categories = {
                "headers": {"http-headers", "csp", "information", "server-error", "debug", "directory-listing", "authentication"},
                "cookies": {"cookies", "cache"},
                "cors": {"cors"},
                "redirects": {"redirect"},
            }
            for response in responses:
                if focus == "all" or focus in http_focus_categories:
                    observed = inspect_http(response)
                    if focus == "all":
                        findings.extend(observed)
                    else:
                        allowed = http_focus_categories[focus]
                        findings.extend(item for item in observed if item.category in allowed)
                if focus in {"all", "html"}:
                    findings.extend(inspect_html(response))
                if focus in {"all", "browser"}:
                    findings.extend(inspect_browser_code(response))
                # URL extraction is passive parsing only and helps the adaptive
                # scheduler decide whether a JavaScript review is applicable.
                script_urls.extend(extract_same_origin_script_urls(response))
                content_type = response.headers.get("content-type", "").lower()
                if focus in {"all", "javascript"} and (
                    "javascript" in content_type
                    or urlsplit(response.url).path.lower().endswith((".js", ".mjs"))
                ):
                    findings.extend(inspect_javascript_source(response.url, response.text))
                if focus in {"all", "fingerprint"}:
                    for component in fingerprint_response(response):
                        components_by_cpe[component.cpe] = component

            # Only the JavaScript focus fetches script resources. It remains
            # same-origin and is constrained by the scope request budget.
            reserve = 20 if profile == "full" and focus == "all" else 0
            script_budget = max(0, min(12, client.max_requests - client.requests_made - reserve)) if focus in {"all", "javascript"} and profile in {"full", "web"} else 0
            script_responses = []
            seen_scripts = {item.url for item in responses}
            for script_url in script_urls:
                if len(script_responses) >= script_budget:
                    break
                if script_url in seen_scripts:
                    continue
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
                if focus in {"all", "javascript"}:
                    findings.extend(inspect_javascript_source(script_url, script_response.text))

            tls_probes = 0
            if profile in {"full", "tls"} and urlsplit(args.target).scheme.lower() == "https":
                findings.extend(inspect_tls(args.target, scope))
                tls_probes = 6

            before_exposure = client.requests_made
            if profile in {"full", "exposure"}:
                findings.extend(probe_sensitive_paths(args.target, scope, client, max_paths=18))
            exposure_paths_checked = client.requests_made - before_exposure

            if profile in {"full", "methods"}:
                findings.extend(inspect_http_methods(args.target, scope, client))

            if args.inventory:
                for component in load_inventory(args.inventory):
                    components_by_cpe[component.cpe] = component
            components = list(components_by_cpe.values())

            cve_lookup_status = None
            if args.nvd_json:
                feed = load_nvd_feed(args.nvd_json)
                findings.extend(match_cves(components, feed))
                cve_lookup_status = {"source": "Local NVD JSON feed", "components_seen": len(components), "records_loaded": len(feed)}
                print(f"CVE matching: {len(components)} component(s) against {len(feed)} NVD record(s).")
            elif not args.no_cve_lookup and components and profile in {"full", "web"} and focus in {"all", "fingerprint"}:
                cve_findings, cve_lookup_status = lookup_cves_for_components(components, max_network_lookups=1)
                findings.extend(cve_findings)
                print(
                    "NVD CVE lookup: "
                    f"{cve_lookup_status['components_checked']}/{cve_lookup_status['components_seen']} component(s) checked; "
                    f"{len(cve_findings)} candidate CVE match(es); "
                    f"{cve_lookup_status['network_lookups']} network lookup(s), "
                    f"{cve_lookup_status['cache_hits']} cache hit(s)."
                )
                for error in cve_lookup_status["errors"]:
                    print(f"NVD lookup unavailable: {error}")

            pages = []
            for r in responses:
                content_type = r.headers.get("content-type", "").lower()
                resource_type = "html" if "text/html" in content_type else (
                    "javascript" if "javascript" in content_type else (
                        "svg" if "image/svg+xml" in content_type or r.url.lower().split("?", 1)[0].endswith(".svg") else (
                            "json" if "json" in content_type else "other"
                        )
                    )
                )
                safe_headers = "\\n".join(f"{key}:{value}" for key, value in sorted(r.headers.items()) if key != "set-cookie")
                fingerprint_material = f"{r.status}|set-cookie={bool(r.headers.get('set-cookie'))}|".encode("utf-8") + r.body + safe_headers.encode("utf-8", errors="replace")
                response_fingerprint = sha256(fingerprint_material).hexdigest()
                pages.append({
                    "url": r.url, "status": r.status, "response_bytes": len(r.body),
                    "elapsed_seconds": round(r.elapsed_seconds, 3), "error": r.error,
                    "resource_type": resource_type, "content_type": content_type,
                    "has_set_cookie": bool(r.headers.get("set-cookie")),
                    "has_cors_headers": any(key.startswith("access-control-") for key in r.headers),
                    "has_redirect": bool(r.headers.get("location")) or (r.status is not None and 300 <= r.status < 400),
                    "script_count": len(script_urls), "response_fingerprint": response_fingerprint,
                })
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
                cve_lookup_status=cve_lookup_status,
                domain_discovery={
                    "enabled": scope.include_subdomains,
                    "root_domain": scope.root_domain,
                    "max_depth": scope.max_subdomain_depth,
                    "max_hosts": scope.max_subdomain_hosts,
                    "hosts": discovered_subdomains,
                },
            )
            print(f"Profile: {profile}; focus: {focus}. Reviewed {len(responses)} page/resource response(s) and {len(script_responses)} same-origin JavaScript file(s); {client.requests_made} HTTP request(s).")
            print(f"Exposure paths checked: {exposure_paths_checked}; TLS probes attempted: {tls_probes}.")
            print(f"Software fingerprints: {len(components)}")
            _print_finding_summary(findings)
            print(f"JSON: {args.output}")
            return 0

        if args.max_cases < 1 or args.max_cases > 32:
            raise ValueError("--max-cases must be between 1 and 32.")
        if not 1 <= args.max_params <= 16:
            raise ValueError("--max-params must be between 1 and 16.")
        scope.validate_url(args.url)
        parameters = args.param or discover_query_parameters(args.url, args.max_params)
        if not parameters:
            raise ValueError("The URL has no query parameters to fuzz. Add a query parameter or pass --param.")
        client = SafeHttpClient(scope, max_requests=scope.max_requests)
        observations = run_fuzz_suite(args.url, parameters, scope, client, args.max_cases)
        report_target = sanitize_url(args.url)
        _write_bundle(
            args, target=report_target, requests_made=client.requests_made, pages=[],
            findings=[], fuzz_observations=observations_to_dict(observations),
        )
        anomalies = sum(bool(item.signal_types) for item in observations)
        print(f"Fuzzed {len(set(item.parameter for item in observations))} parameter(s) with {len(observations)} benign mutation(s).")
        print(f"Requests used: {client.requests_made}/{client.max_requests}; repeated baselines: enabled.")
        print(f"Observations requiring review: {anomalies}")
        print("Anomalies are triage leads, not confirmed vulnerabilities; response bodies and raw test values are not saved.")
        print(f"JSON: {args.output}")
        return 0
    except (ScopeError, ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
