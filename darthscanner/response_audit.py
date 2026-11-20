"""Protocol and parser-behavior checks for already-fetched responses.

These checks are passive: they inspect response bytes already obtained by the
bounded crawler. They do not send additional requests or claim exploitability.
"""
from __future__ import annotations

import json
import re

from .checks import Finding


class _DuplicateKey(Exception):
    pass


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def inspect_response_behavior(response) -> list[Finding]:
    """Find response-format inconsistencies and parser-ambiguity candidates."""
    if response.status is None or not response.body:
        return []

    findings: list[Finding] = []
    content_type = response.headers.get("content-type", "").lower()
    body = response.body[:1_000_000]
    stripped = body.lstrip()
    is_json_type = "json" in content_type
    looks_json = stripped.startswith((b"{", b"["))
    looks_html = stripped[:256].lower().startswith((b"<!doctype html", b"<html", b"<head", b"<body"))
    is_success = 200 <= response.status < 300

    def add(title: str, severity: str, confidence: str, kind: str,
            description: str, impact: str, evidence: str, remediation: str,
            cwe: str, score: int) -> None:
        findings.append(Finding(
            category="response-behavior",
            title=title,
            severity=severity,
            confidence=confidence,
            url=response.url,
            kind=kind,
            description=description,
            impact=impact,
            evidence=evidence,
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation],
            confidence_score=score,
        ))

    if is_success and is_json_type and looks_html:
        add(
            "Successful JSON response contains an HTML document",
            "low", "high", "protocol-inconsistency",
            "The response advertises a JSON media type but its body begins with an HTML document.",
            "Clients may parse or render an unexpected representation; security impact depends on how downstream consumers handle it.",
            f"HTTP {response.status}; Content-Type is {content_type.split(';', 1)[0]}; body begins with an HTML document.",
            "Return a representation matching the declared media type and ensure error pages use an appropriate status and content type.",
            "CWE-436", 65,
        )

    if is_success and not is_json_type and looks_json and ("text/html" in content_type):
        add(
            "HTML media type contains a JSON-looking response",
            "info", "high", "protocol-inconsistency",
            "The response is labelled as HTML but begins with a JSON object or array.",
            "Representation mismatches can cause client-side parser differences and unexpected rendering behavior.",
            f"HTTP {response.status}; Content-Type is {content_type.split(';', 1)[0]}; body begins with JSON syntax.",
            "Set an accurate Content-Type and use X-Content-Type-Options: nosniff where appropriate.",
            "CWE-436", 65,
        )

    if is_success and is_json_type:
        try:
            text = body.decode("utf-8")
            json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        except _DuplicateKey:
            add(
                "JSON object contains duplicate member names",
                "medium", "high", "parser-ambiguity",
                "A JSON object contains the same member name more than once.",
                "Different JSON parsers may keep the first or last value, creating interpretation differences in authorization, validation, or signature workflows.",
                "Duplicate JSON member names were detected; member names and values are intentionally omitted.",
                "Reject duplicate JSON keys at the trust boundary and ensure all components use consistent strict parsing.",
                "CWE-436", 75,
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            add(
                "Successful response advertises JSON but is not valid UTF-8 JSON",
                "low", "high", "protocol-inconsistency",
                "A successful response declares a JSON media type but could not be parsed as UTF-8 JSON.",
                "Clients may disagree on error handling or fall back to unsafe parsing behavior.",
                f"HTTP {response.status}; JSON media type declared; strict UTF-8 JSON parsing failed (response body omitted).",
                "Return valid UTF-8 JSON or use an appropriate error status and media type.",
                "CWE-436", 70,
            )

    if is_success and re.search(
        rb"(?i)(?:traceback \(most recent call last\)|"
        rb"uncaught exception|fatal error:|stack trace:|"
        rb"sqlstate\[|syntax error at or near|"
        rb"exception in thread)",
        body,
    ):
        add(
            "Successful response contains a diagnostic or exception signature",
            "medium", "medium", "error-disclosure-candidate",
            "A response with a success status contains text commonly associated with an unhandled exception or diagnostic page.",
            "Detailed exception output can disclose internal paths, framework details, query structure, or implementation information.",
            "A generic diagnostic signature was detected in a successful response; response contents are not copied into the report.",
            "Return a generic client error and keep stack traces and diagnostics in access-controlled server logs.",
            "CWE-209", 55,
        )

    return findings
