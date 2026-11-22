"""Vulnerability-pattern triage and per-candidate fuzz evidence reports.

This module analyzes only existing bounded GET observations. It does not send
requests, retain response bodies, or turn anomalies into confirmed exploits.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit


def _safe_url(value: str) -> str:
    parts = urlsplit(str(value or ""))
    if not parts.scheme or not parts.netloc:
        return ""
    # Fuzzer already redacts secret query values; retain that sanitized query.
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _candidate_specs(signals: set[str]) -> list[dict]:
    specs = []
    if "new-diagnostic-signature" in signals:
        specs.append({
            "category": "error-information-disclosure",
            "title": "Possible error-detail information disclosure",
            "severity_estimate": "medium",
            "hypothesis": "A benign input variation introduced a diagnostic signature absent from the baseline. This may expose framework or internal error details; it does not prove injection, data access, or code execution.",
            "impact": "Potential disclosure of implementation or database error details.",
            "validation": [
                "Repeat the same benign GET case once within the approved scope and configured rate.",
                "Compare the response hash and baseline hash.",
                "Ask the application owner to confirm whether stack traces or internal details were returned to an unauthenticated client.",
                "Use an approved redacted excerpt if the owner needs content-level confirmation; do not collect secrets or user data.",
            ],
        })
    if "new-server-error" in signals:
        specs.append({
            "category": "input-triggered-server-error",
            "title": "Input variation triggered a server error",
            "severity_estimate": "medium",
            "hypothesis": "A benign value caused a new 5xx response compared with the baseline. This may indicate an unhandled input path; one 5xx is not proof of denial of service or code execution.",
            "impact": "Possible reliability or exception-handling weakness.",
            "validation": [
                "Repeat once at the configured rate and verify the baseline endpoint remains healthy.",
                "Correlate the UTC timestamp and response hash with application logs.",
                "Have the owner determine whether the exception affects availability, integrity, or confidentiality.",
            ],
        })
    if "input-reflection" in signals:
        specs.append({
            "category": "reflected-input-context-review",
            "title": "User-controlled input reflected in response",
            "severity_estimate": "low",
            "hypothesis": "The test value appeared in the response. Reflection alone is not XSS; output context and context-appropriate encoding must be reviewed.",
            "impact": "Client-side injection is only plausible if unsafe HTML, attribute, script, or URL context and missing encoding are independently confirmed.",
            "validation": [
                "Review the reflection location in an authorized browser or local test fixture.",
                "Identify whether it appears in HTML text, an attribute, JavaScript, CSS, or JSON context.",
                "Verify context-appropriate output encoding without injecting script, event-handler, or executable payloads.",
            ],
        })
    if "redirect" in signals:
        specs.append({
            "category": "redirect-behavior-review",
            "title": "Input variation changed redirect behavior",
            "severity_estimate": "info",
            "hypothesis": "The mutated request returned a redirect. The destination was not followed or captured, so this is not evidence of an open redirect.",
            "impact": "Potential redirect-policy weakness only if the application uses untrusted input to select an unvalidated external destination.",
            "validation": [
                "Have the owner inspect the Location header in server-side or approved browser tooling.",
                "Verify destinations are restricted to documented same-origin or allowlisted destinations.",
                "Do not follow untrusted redirect destinations during automated validation.",
            ],
        })
    if "content-type-change" in signals:
        specs.append({
            "category": "content-type-behavior-review",
            "title": "Input variation changed response media type",
            "severity_estimate": "info",
            "hypothesis": "The response Content-Type differed from baseline. This may be expected content negotiation; inspect whether the application consistently declares and protects the actual response format.",
            "impact": "Incorrect media-type handling may contribute to content interpretation issues in some client contexts, but the signal alone does not prove script execution.",
            "validation": [
                "Compare the baseline and mutated Content-Type values.",
                "Ask the owner whether the parameter is documented to select a response format.",
                "Verify the response declares its actual media type and applies appropriate browser protections.",
            ],
        })
    if "timing-outlier" in signals:
        specs.append({
            "category": "input-dependent-latency-review",
            "title": "Input variation produced unusual response latency",
            "severity_estimate": "info",
            "hypothesis": "The response was slower than the repeated baseline. Network variance, cache state, and server load can cause this; it is not proof of blind injection or denial of service.",
            "impact": "Potential inefficient input-handling path; operational impact is unconfirmed.",
            "validation": [
                "Compare a small number of measurements during a quiet test window.",
                "Correlate client timings with server-side traces and logs.",
                "Stop if latency or error rates increase; do not increase input sizes or request volume.",
            ],
        })
    if "large-response-delta" in signals:
        specs.append({
            "category": "input-dependent-response-growth",
            "title": "Input variation produced a larger response",
            "severity_estimate": "info",
            "hypothesis": "The response grew substantially relative to baseline. This may be normal pagination or content variation and does not establish resource exhaustion.",
            "impact": "Possible unexpected response generation; resource impact is unconfirmed.",
            "validation": [
                "Compare response byte counts and documented parameter behavior.",
                "Ask the owner to correlate the timestamp with application logs.",
                "Do not increase input sizes or repeat requests to stress the service.",
            ],
        })
    if "status-change" in signals:
        specs.append({
            "category": "input-dependent-status-review",
            "title": "Input variation changed HTTP status",
            "severity_estimate": "info",
            "hypothesis": "The HTTP status differed from baseline. This may reflect ordinary validation or routing behavior and is not proof of an authorization bypass.",
            "impact": "Unexpected input handling; security impact has not been established.",
            "validation": [
                "Compare baseline and mutated status codes.",
                "Review the documented parameter contract and expected validation responses.",
                "If access-control behavior is implicated, have the owner validate it using approved test accounts and a staging environment.",
            ],
        })
    return specs


def build_fuzz_finding_reports(observations: list[dict], output_dir: str | Path) -> list[dict]:
    """Write one standalone JSON evidence report for each classified fuzz signal."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    reports: list[dict] = []
    for item in observations:
        signals = set(item.get("signal_types") or [])
        if not signals or "unstable-baseline" in signals:
            continue
        target = _safe_url(item.get("request_url", ""))
        for spec in _candidate_specs(signals):
            material = "|".join((
                target, str(item.get("parameter") or ""), str(item.get("case") or ""),
                spec["category"], str(item.get("response_sha256") or ""),
            ))
            report_id = sha256(material.encode("utf-8")).hexdigest()[:20]
            confidence = str(item.get("confidence") or "low")
            if confidence not in {"low", "medium", "high"}:
                confidence = "low"
            if spec["severity_estimate"] == "info":
                confidence = "low"
            evidence = {
                "method": "GET",
                "request_url": target,
                "parameter": str(item.get("parameter") or ""),
                "case_name": str(item.get("case") or ""),
                "input_sha256": str(item.get("input_sha256") or ""),
                "baseline_status": item.get("baseline_status"),
                "response_status": item.get("status"),
                "baseline_response_bytes": int(item.get("baseline_bytes") or 0),
                "response_bytes": int(item.get("response_bytes") or 0),
                "size_delta_bytes": int(item.get("size_delta_bytes") or 0),
                "elapsed_seconds": item.get("elapsed_seconds"),
                "timing_ratio": item.get("timing_ratio"),
                "baseline_sha256": str(item.get("baseline_sha256") or ""),
                "response_sha256": str(item.get("response_sha256") or ""),
                "response_content_type": str(item.get("content_type") or "")[:200],
                "allowlisted_response_headers": dict(item.get("response_headers") or {}),
                "observed_signals": sorted(signals),
                "captured_at_utc": str(item.get("capture_time_utc") or ""),
                "response_body_saved": False,
                "raw_test_value_saved": False,
            }
            report = {
                "schema_version": "1.0",
                "report_id": report_id,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "source": "Darth Scanner Fuzz Lab",
                "classification": "unconfirmed-vulnerability-hypothesis",
                **spec,
                "confidence": confidence,
                "exploitability": "not_confirmed",
                "requires_human_confirmation": True,
                "target": target,
                "evidence": evidence,
                "proof_of_concept": {
                    "title": "Non-destructive, repeatable HTTP proof",
                    "request_method": "GET",
                    "request_url": target,
                    "parameter": str(item.get("parameter") or ""),
                    "case_name": str(item.get("case") or ""),
                    "input_sha256_only": str(item.get("input_sha256") or ""),
                    "initial_observation": {
                        "status": item.get("status"),
                        "response_sha256": str(item.get("response_sha256") or ""),
                        "response_bytes": int(item.get("response_bytes") or 0),
                        "baseline_status": item.get("baseline_status"),
                        "baseline_sha256": str(item.get("baseline_sha256") or ""),
                    },
                    "automatic_verification": dict(item.get("automatic_verification") or {
                        "attempted": False, "outcome": "not-run",
                        "note": "Automatic repeatability verification was not run for this observation."
                    }),
                    "interpretation": "A repeated signal demonstrates repeatability of an HTTP observation only. It does not prove exploitability, impact, or authorization to access data.",
                },
                "safe_reproduction_steps": list(item.get("reproduction_steps") or []) + spec["validation"],
                "limitations": [
                    "A response anomaly is not proof of exploitability.",
                    "No response body or raw fuzz input is retained in this report.",
                    "CVSS is not assigned to an unconfirmed fuzz hypothesis.",
                    "Validate only within written authorization and preferably in staging.",
                ],
            }
            path = destination / f"{report_id}.json"
            path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            report["report_path"] = str(path)
            reports.append(report)
    index = {
        "tool": "Darth Scanner",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "report_count": len(reports),
        "reports": [
            {"report_id": item["report_id"], "category": item["category"],
             "title": item["title"], "severity_estimate": item["severity_estimate"],
             "confidence": item["confidence"], "file": f'{item["report_id"]}.json'}
            for item in reports
        ],
        "note": "All entries are unconfirmed hypotheses requiring human validation.",
    }
    (destination / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
    return reports
