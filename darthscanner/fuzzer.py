"""Low-rate black-box robustness fuzzer for explicitly authorized GET endpoints.

The mutator uses bounded, non-exploit values. Results are anomaly leads, never
proof that a zero-day or exploitable vulnerability exists.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .http_client import SafeHttpClient
from .scope import Scope


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


def _variants() -> list[tuple[str, str]]:
    """Small, benign type/encoding/boundary corpus (maximum value length: 256)."""
    return [
        ("empty", ""),
        ("zero", "0"),
        ("positive-one", "1"),
        ("negative-one", "-1"),
        ("int32-maximum", "2147483647"),
        ("int32-minimum", "-2147483648"),
        ("int64-maximum", "9223372036854775807"),
        ("decimal", "1.5"),
        ("scientific-notation", "1e6"),
        ("boolean-true", "true"),
        ("boolean-false", "false"),
        ("null-like", "null"),
        ("short-boundary", "A" * 32),
        ("medium-boundary", "A" * 128),
        ("bounded-long", "A" * 256),
        ("whitespace", " value with spaces "),
        ("tabs", "\tvalue\t"),
        ("newline", "line1\nline2"),
        ("unicode", "café-東京-🙂"),
        ("combining-unicode", "e\u0301"),
        ("reserved-characters", "a&b=c?d#e"),
        ("percent-literal", "100%25"),
        ("json-object-shape", '{"k":"v"}'),
        ("json-array-shape", "[]"),
        ("quoted-text", '"sample text"'),
        ("single-quoted-text", "'sample text'"),
        ("semicolon", "alpha;beta"),
        ("colon", "alpha:beta"),
        ("path-separators", "alpha/beta"),
        ("dot-segments", "./segment/../item"),
        ("encoded-space", "%20sample%20"),
        ("long-unicode", "界" * 32),
    ]


def mutate_query_parameter(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    matches = sum(1 for key, _ in pairs if key == parameter)
    if matches != 1:
        raise ValueError(f"Expected exactly one query parameter named {parameter!r}; found {matches}.")
    updated = [(key, value if key == parameter else old) for key, old in pairs]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), ""))


def run_fuzz(url: str, parameter: str, scope: Scope, client: SafeHttpClient,
             max_cases: int = 12) -> list[FuzzObservation]:
    scope.validate_url(url)
    if not 1 <= max_cases <= 32:
        raise ValueError("max_cases must be between 1 and 32.")
    if max_cases + 1 > client.max_requests:
        max_cases = max(0, client.max_requests - 1)
    if max_cases < 1:
        raise ValueError("Request budget must allow at least one baseline and one mutation.")
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if sum(1 for key, _ in pairs if key == parameter) != 1:
        raise ValueError(f"Expected exactly one query parameter named {parameter!r} in the URL.")

    baseline = client.get(url)
    observations: list[FuzzObservation] = []
    for case, value in _variants()[:max_cases]:
        if client.requests_made >= client.max_requests:
            break
        mutated_url = mutate_query_parameter(url, parameter, value)
        response = client.get(mutated_url)
        notes: list[str] = []
        if response.status is not None and response.status >= 500:
            notes.append("server returned a 5xx response; review application/server logs")
        if response.status != baseline.status:
            notes.append(f"status changed from baseline {baseline.status} to {response.status}")
        if response.status is not None and 300 <= response.status < 400:
            notes.append("mutation caused a redirect response; destination was not followed")
        if response.headers.get("content-type", "") != baseline.headers.get("content-type", ""):
            notes.append("Content-Type changed from baseline")
        if baseline.body and response.body and len(response.body) > max(4096, len(baseline.body) * 5):
            notes.append("response size increased substantially")
        if baseline.elapsed_seconds > 0 and response.elapsed_seconds > max(3.0, baseline.elapsed_seconds * 5):
            notes.append("response was substantially slower than baseline")
        body_lower = response.body.lower()
        for signature in (
            b"traceback (most recent call last)",
            b"stack trace:",
            b"werkzeug debugger",
            b"sqlstate[",
            b"you have an error in your sql syntax",
            b"laravel ignition",
        ):
            if signature in body_lower:
                notes.append(f"response contains a diagnostic/error signature ({signature.decode('ascii', errors='ignore')})")
                break
        reflected = bool(value) and value.encode("utf-8", errors="ignore") in response.body
        if reflected:
            notes.append("input value appears verbatim in the response; inspect output context and encoding")

        observations.append(FuzzObservation(
            parameter=parameter,
            case=case,
            status=response.status,
            response_bytes=len(response.body),
            elapsed_seconds=round(response.elapsed_seconds, 4),
            note="; ".join(notes) if notes else "no notable response difference",
            baseline_status=baseline.status,
            response_sha256=sha256(response.body).hexdigest(),
            content_type=response.headers.get("content-type", ""),
            input_reflected=reflected,
        ))
    return observations


def observations_to_dict(items: list[FuzzObservation]) -> list[dict]:
    return [asdict(item) for item in items]
