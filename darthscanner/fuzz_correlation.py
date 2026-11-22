"""Correlate related fuzz observations without sending additional requests.

Correlations are triage hypotheses, not exploit chains or confirmed findings.
Only observations for the same normalized host, path, and query parameter join.
"""
from __future__ import annotations

from hashlib import sha256
from urllib.parse import urlsplit


def _scope_key(item: dict) -> tuple[str, str, str]:
    parts = urlsplit(str(item.get("request_url") or ""))
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    parameter = str(item.get("parameter") or "")
    return host, path, parameter


def correlate_fuzz_observations(observations: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str, str], list[dict]] = {}
    for item in observations or []:
        if "unstable-baseline" in (item.get("signal_types") or []):
            continue
        key = _scope_key(item)
        if key[0] and key[2] and item.get("signal_types"):
            groups.setdefault(key, []).append(item)

    correlations = []
    for (host, path, parameter), items in sorted(groups.items()):
        signals = {signal for item in items for signal in (item.get("signal_types") or [])}
        if len(items) < 2 or len(signals) < 2:
            continue
        if {"new-server-error", "new-diagnostic-signature"} <= signals:
            category = "input-error-handling-and-diagnostic-disclosure"
            title = "Related input-error and diagnostic-disclosure signals"
            rationale = "Separate benign cases for the same parameter produced both a new server error and a diagnostic signature. Review exception handling and client-visible error detail together; this does not establish injection or code execution."
            validation = [
                "Compare the individual case hashes and UTC timestamps with application logs.",
                "Confirm whether diagnostic details were actually exposed to an unauthenticated client.",
                "Review server-side exception handling and ensure generic client errors are returned.",
            ]
        elif {"input-reflection", "new-diagnostic-signature"} <= signals:
            category = "reflected-input-and-error-context-review"
            title = "Related input-reflection and diagnostic signals"
            rationale = "The same parameter showed reflected input and a diagnostic response in separate observations. Review output encoding and exception handling independently; reflection is not proof of XSS."
            validation = [
                "Inspect the exact reflected response context using a local fixture or owner-provided source.",
                "Verify context-appropriate output encoding without executable payloads.",
                "Review whether diagnostic content is exposed to clients.",
            ]
        elif {"timing-outlier", "large-response-delta"} <= signals:
            category = "input-dependent-processing-review"
            title = "Related latency and response-growth signals"
            rationale = "The same parameter produced both unusual latency and response growth. This may be ordinary application behavior; it does not prove resource exhaustion or denial of service."
            validation = [
                "Correlate the captured timestamps with server-side traces and expected response behavior.",
                "Stop testing if latency or error rates increase; do not increase payload sizes or request volume.",
            ]
        elif {"status-change", "redirect"} <= signals:
            category = "input-dependent-routing-review"
            title = "Related status and redirect behavior signals"
            rationale = "The same parameter changed status and produced a redirect. This does not prove an open redirect or authorization bypass."
            validation = [
                "Have the owner inspect the Location header and verify destinations against a strict allowlist.",
                "Review the documented parameter contract and expected routing behavior.",
            ]
        else:
            continue
        evidence_ids = sorted({
            str(item.get("response_sha256") or "")
            for item in items if item.get("response_sha256")
        })
        material = "|".join((host, path, parameter, category, *evidence_ids))
        correlations.append({
            "correlation_id": sha256(material.encode("utf-8")).hexdigest()[:20],
            "classification": "correlated-unconfirmed-hypothesis",
            "category": category,
            "title": title,
            "target_host": host,
            "path": path,
            "parameter": parameter,
            "observation_count": len(items),
            "contributing_signals": sorted(signals),
            "evidence_hashes": evidence_ids,
            "confidence": "medium" if len(evidence_ids) >= 2 else "low",
            "severity_estimate": "review-required",
            "cvss_score": None,
            "exploitability": "not_confirmed",
            "requires_human_confirmation": True,
            "rationale": rationale,
            "safe_validation_steps": validation,
            "limitations": [
                "Correlation uses only existing observations and sends no network requests.",
                "Signals do not establish a working exploit or vulnerability chain.",
                "No CVSS is assigned to this unconfirmed hypothesis.",
            ],
        })
    return correlations
