"""Adaptive, low-rate black-box robustness fuzzer for authorized GET endpoints.

Only benign type, boundary, and encoding mutations are sent. The engine never
submits forms, uploads files, follows redirects, or sends exploit strings.
Anomalies are reproducible triage leads, not confirmed vulnerabilities.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .http_client import SafeHttpClient
from .scope import Scope


_SECRET_PARTS = ("token", "auth", "password", "passwd", "secret", "api_key",
                 "apikey", "access_key", "session", "credential", "code")
_HEADER_ALLOWLIST = {
    "content-type", "content-length", "server", "cache-control",
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
}
_DIAGNOSTICS = (
    b"traceback (most recent call last)", b"stack trace:",
    b"werkzeug debugger", b"sqlstate[", b"you have an error in your sql syntax",
    b"laravel ignition", b"unhandled exception", b"internal server error",
)


@dataclass
class FuzzObservation:
    parameter: str
    case: str
    status: int | None
    response_bytes: int
    elapsed_seconds: float
    note: str
    baseline_status: int | None = None
    response_sha256: str = ""
    content_type: str = ""
    input_reflected: bool = False
    case_family: str = "general"
    input_sha256: str = ""
    request_url: str = ""
    baseline_bytes: int = 0
    baseline_sha256: str = ""
    size_delta_bytes: int = 0
    timing_ratio: float | None = None
    signal_types: list[str] = field(default_factory=list)
    anomaly_score: int = 0
    confidence: str = "low"
    capture_time_utc: str = ""
    response_headers: dict = field(default_factory=dict)
    reproduction_steps: list[str] = field(default_factory=list)


def sanitize_url(url: str) -> str:
    """Redact secret-like query values before a URL enters a report."""
    parts = urlsplit(str(url))
    pairs = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        secret = any(part in key.lower() for part in _SECRET_PARTS)
        pairs.append((key, "[REDACTED]" if secret else value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def discover_query_parameters(url: str, max_params: int = 8) -> list[str]:
    """Return unique, non-empty query parameter names in URL order."""
    if not 1 <= max_params <= 20:
        raise ValueError("max_params must be between 1 and 20.")
    names = []
    for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
        if len(names) >= max_params:
            break
    return names


def mutate_query_parameter(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    matches = sum(1 for key, _ in pairs if key == parameter)
    if matches != 1:
        raise ValueError(f"Expected exactly one query parameter named {parameter!r}; found {matches}.")
    updated = [(key, value if key == parameter else old) for key, old in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), ""))


def _variants(original: str) -> list[tuple[str, str, str]]:
    """Select a deterministic, benign corpus based on the observed input type."""
    numeric = bool(re.fullmatch(r"[+-]?\d+(?:\.\d+)?", original.strip()))
    boolean = original.strip().lower() in {"true", "false", "yes", "no", "0", "1"}
    uuid_like = bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", original.strip()))
    common = [
        ("empty", "", "boundary"),
        ("zero", "0", "numeric"),
        ("one", "1", "numeric"),
        ("negative-one", "-1", "numeric"),
        ("int32-max", "2147483647", "numeric-boundary"),
        ("int32-min", "-2147483648", "numeric-boundary"),
        ("decimal", "1.5", "numeric-type"),
        ("scientific-notation", "1e6", "numeric-type"),
        ("boolean-true", "true", "boolean"),
        ("boolean-false", "false", "boolean"),
        ("null-like", "null", "type-mismatch"),
        ("short-boundary", "A" * 32, "length-boundary"),
        ("medium-boundary", "A" * 128, "length-boundary"),
        ("bounded-long", "A" * 256, "length-boundary"),
        ("leading-trailing-space", " value ", "whitespace"),
        ("tab-and-newline", "value\tline1
line2", "whitespace"),
        ("unicode", "café-東京-🙂", "unicode"),
        ("combining-unicode", "e\u0301", "unicode"),
        ("reserved-delimiters", "a&b=c?d#e", "encoding"),
        ("percent-literal", "100%25", "encoding"),
        ("json-object-shape", '{"k":"v"}', "structured-type"),
        ("json-array-shape", "[]", "structured-type"),
        ("quoted-text", '"sample text"', "punctuation"),
        ("path-separators", "alpha/beta", "path-shape"),
    ]
    if numeric:
        priority = {"numeric", "numeric-boundary", "numeric-type", "type-mismatch", "boundary", "length-boundary"}
    elif boolean:
        priority = {"boolean", "type-mismatch", "boundary", "numeric", "length-boundary"}
    elif uuid_like:
        priority = {"boundary", "type-mismatch", "unicode", "punctuation", "encoding"}
    else:
        priority = {"boundary", "length-boundary", "whitespace", "unicode", "encoding", "structured-type", "punctuation", "numeric", "boolean", "type-mismatch", "path-shape"}
    ordered = sorted(enumerate(common), key=lambda item: (0 if item[1][2] in priority else 1, item[0]))
    seen = {original}
    result = []
    for _, item in ordered:
        if item[1] in seen:
            continue
        seen.add(item[1])
        result.append(item)
    return result


def _safe_headers(headers: dict) -> dict:
    return {key.lower(): str(value)[:300] for key, value in headers.items()
            if key.lower() in _HEADER_ALLOWLIST}


def _diagnostic_hits(body: bytes) -> list[str]:
    lower = body.lower()
    return [signature.decode("ascii", errors="ignore")
            for signature in _DIAGNOSTICS if signature in lower]


def run_fuzz(url: str, parameter: str, scope: Scope, client: SafeHttpClient,
             max_cases: int = 12, baseline_repeats: int = 2,
             stop_event=None) -> list[FuzzObservation]:
    """Fuzz one existing GET query parameter with a repeated baseline and bounded corpus."""
    scope.validate_url(url)
    if not 1 <= max_cases <= 32:
        raise ValueError("max_cases must be between 1 and 32.")
    if not 1 <= baseline_repeats <= 3:
        raise ValueError("baseline_repeats must be between 1 and 3.")
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    matching = [value for key, value in pairs if key == parameter]
    if len(matching) != 1:
        raise ValueError(f"Expected exactly one query parameter named {parameter!r} in the URL.")
    original = matching[0]
    if client.max_requests - client.requests_made < baseline_repeats + 1:
        raise ValueError("Request budget must allow a baseline and at least one mutation.")
    max_cases = min(max_cases, client.max_requests - client.requests_made - baseline_repeats)

    baseline_samples = []
    for _ in range(baseline_repeats):
        if stop_event and stop_event.is_set():
            break
        baseline_samples.append(client.get(url))
    if not baseline_samples:
        return []
    baseline = baseline_samples[-1]
    statuses = [item.status for item in baseline_samples]
    baseline_stable = len(set(statuses)) == 1
    baseline_elapsed = sorted(item.elapsed_seconds for item in baseline_samples)[len(baseline_samples) // 2]
    baseline_hits = set()
    for item in baseline_samples:
        baseline_hits.update(_diagnostic_hits(item.body))
    baseline_digest = sha256(baseline.body).hexdigest()
    baseline_bytes = len(baseline.body)
    observations: list[FuzzObservation] = []

    for case, value, family in _variants(original)[:max_cases]:
        if (stop_event and stop_event.is_set()) or client.requests_made >= client.max_requests:
            break
        mutated_url = mutate_query_parameter(url, parameter, value)
        response = client.get(mutated_url)
        signals: list[str] = []
        notes: list[str] = []
        score = 0
        if not baseline_stable:
            signals.append("unstable-baseline")
            notes.append("baseline status varied; interpret response differences cautiously")
        if response.status is not None and response.status >= 500 and baseline.status is not None and baseline.status < 500:
            signals.append("new-server-error")
            notes.append(f"server returned {response.status} after a non-5xx baseline")
            score += 45
        elif response.status != baseline.status and baseline_stable:
            signals.append("status-change")
            notes.append(f"status changed from baseline {baseline.status} to {response.status}")
            score += 18
        if response.status is not None and 300 <= response.status < 400:
            signals.append("redirect")
            notes.append("mutation caused a redirect; destination was not followed")
            score += 8
        content_type = response.headers.get("content-type", "")
        baseline_type = baseline.headers.get("content-type", "")
        if content_type != baseline_type:
            signals.append("content-type-change")
            notes.append("response Content-Type changed from baseline")
            score += 12
        size_delta = len(response.body) - baseline_bytes
        if baseline_bytes and len(response.body) > max(4096, baseline_bytes * 5):
            signals.append("large-response-delta")
            notes.append("response grew substantially compared with baseline")
            score += 18
        timing_ratio = round(response.elapsed_seconds / max(baseline_elapsed, 0.001), 2)
        if response.elapsed_seconds > max(3.0, baseline_elapsed * 5):
            signals.append("timing-outlier")
            notes.append("response was substantially slower than the repeated baseline")
            score += 18
        hits = set(_diagnostic_hits(response.body)) - baseline_hits
        if hits:
            signals.append("new-diagnostic-signature")
            notes.append("response introduced a diagnostic/error signature: " + ", ".join(sorted(hits)[:2]))
            score += 35
        reflected = bool(value) and value.encode("utf-8", errors="ignore") in response.body
        if reflected:
            signals.append("input-reflection")
            notes.append("test value appears in response; inspect HTML/JSON context and output encoding")
            score += 10
        if response.status is None:
            signals.append("request-error")
            notes.append("request did not produce an HTTP response")
            score += 5
        score = min(100, score)
        confidence = "high" if score >= 65 and baseline_stable else ("medium" if score >= 30 else "low")
        if not notes:
            notes.append("no notable difference from baseline")
        digest = sha256(response.body).hexdigest()
        safe_request = sanitize_url(mutated_url)
        steps = [
            f"1. Send a read-only GET request to {safe_request}.",
            f"2. Use the same query parameter '{parameter}' with the recorded case '{case}'.",
            "3. Compare status, Content-Type, response size, timing, and SHA-256 with the baseline.",
            "4. Repeat only within the authorized scope and at the configured request rate.",
            "5. Review server-side logs before classifying an anomaly as a vulnerability.",
        ]
        observations.append(FuzzObservation(
            parameter=parameter, case=case, status=response.status,
            response_bytes=len(response.body), elapsed_seconds=round(response.elapsed_seconds, 4),
            note="; ".join(notes), baseline_status=baseline.status,
            response_sha256=digest, content_type=content_type,
            input_reflected=reflected, case_family=family,
            input_sha256=sha256(value.encode("utf-8")).hexdigest(),
            request_url=safe_request, baseline_bytes=baseline_bytes,
            baseline_sha256=baseline_digest, size_delta_bytes=size_delta,
            timing_ratio=timing_ratio, signal_types=signals,
            anomaly_score=score, confidence=confidence,
            capture_time_utc=datetime.now(timezone.utc).isoformat(),
            response_headers=_safe_headers(response.headers),
            reproduction_steps=steps,
        ))
    return observations


def run_fuzz_suite(url: str, parameters: list[str], scope: Scope,
                   client: SafeHttpClient, max_cases: int = 12,
                   stop_event=None) -> list[FuzzObservation]:
    """Fuzz several discovered query parameters while reserving baseline budget."""
    unique = list(dict.fromkeys(parameters))
    if not unique:
        raise ValueError("No query parameters were found. Supply a URL containing query parameters.")
    if len(unique) > 20:
        unique = unique[:20]
    if client.max_requests - client.requests_made < len(unique) * 3:
        raise ValueError("Request budget is too small for at least one baseline and one case per parameter.")
    observations: list[FuzzObservation] = []
    for index, parameter in enumerate(unique):
        if stop_event and stop_event.is_set():
            break
        remaining_params = len(unique) - index - 1
        available = client.max_requests - client.requests_made - (remaining_params * 3)
        cases = min(max_cases, max(1, available - 2))
        observations.extend(run_fuzz(url, parameter, scope, client, cases, baseline_repeats=2, stop_event=stop_event))
    return observations


def observations_to_dict(items: list[FuzzObservation]) -> list[dict]:
    return [asdict(item) for item in items]
