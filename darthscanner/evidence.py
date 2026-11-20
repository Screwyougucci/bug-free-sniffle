"""Reproducible, redacted evidence bundles for benign black-box fuzz observations."""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .discovery import _sensitive_name


def redact_url(url: str) -> str:
    """Redact credential-like query values before reporting a URL."""
    parts = urlsplit(url)
    pairs = [
        (name, "[REDACTED]" if _sensitive_name(name) else value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def build_reproduction_evidence(observations: list[dict]) -> list[dict]:
    """Create one bounded replay recipe per recorded benign fuzz observation."""
    evidence = []
    for item in observations:
        endpoint = str(item.get("endpoint_url", ""))
        parameter = str(item.get("parameter", ""))
        case = str(item.get("case", ""))
        if not endpoint or not parameter or not case:
            continue
        safe_url = redact_url(endpoint)
        command = (
            "darth-scanner replay "
            f"--url {json.dumps(safe_url)} "
            f"--param {json.dumps(parameter)} "
            f"--case {json.dumps(case)} "
            "--scope scope.json --acknowledge-authorization "
            "--output darth-replay-report.json"
        )
        evidence.append({
            "kind": "benign_get_fuzz_reproduction",
            "method": "GET",
            "endpoint_url": safe_url,
            "parameter": parameter,
            "case": case,
            "mutation_value": "[REDACTED]" if _sensitive_name(parameter) else item.get("mutation_value", ""),
            "baseline": {
                "http_status": item.get("baseline_status"),
                "response_sha256": item.get("baseline_sha256", ""),
                "normalized_response_sha256": item.get("baseline_normalized_sha256", ""),
            },
            "observed": {
                "http_status": item.get("status"),
                "response_bytes": item.get("response_bytes"),
                "response_sha256": item.get("response_sha256", ""),
                "normalized_response_sha256": item.get("normalized_response_sha256", ""),
                "content_type": item.get("content_type", ""),
                "elapsed_seconds": item.get("elapsed_seconds"),
                "anomaly_score": item.get("anomaly_score", 0),
                "note": item.get("note", ""),
            },
            "source_location": {
                "available": False,
                "reason": "Black-box HTTP testing cannot identify server-side source files or lines; use audit-code on an authorized local checkout.",
            },
            "reproduction_command": command,
            "limitations": [
                "Replay uses one named benign corpus case and sends exactly one GET request.",
                "Response differences are evidence of behavior, not proof of security impact.",
                "Dynamic content may change hashes between runs.",
                "Replay only against hosts in the active authorization scope.",
            ],
        })
    return evidence
