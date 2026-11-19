"""Low-rate black-box robustness fuzzer for explicitly authorized GET endpoints.

The mutator uses bounded, non-exploit values. Results are anomaly leads, never
proof that a zero-day or exploitable vulnerability exists.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import re
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
    response_changed: bool = False
    location_changed: bool = False
    server_error: bool = False
    baseline_sha256: str = ""
    endpoint_url: str = ""
    mutation_value: str = ""
    normalized_response_sha256: str = ""
    baseline_normalized_sha256: str = ""
    anomaly_score: int = 0


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



def normalized_body_hash(body: bytes) -> str:
    """Hash a coarse response shape after masking common volatile values."""
    text = body[:1_000_000].decode("utf-8", errors="replace")
    text = re.sub(r"(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\b", "<UUID>", text)
    text = re.sub(r"\\b20\\d{2}-\\d{2}-\\d{2}[T ][0-9:.+-]+Z?\\b", "<TIMESTAMP>", text)
    text = re.sub(r"(?i)(\\b(?:request[_-]?id|trace[_-]?id|nonce|csrf[_-]?token)\\b\\s*[:=]\\s*)(['\\\"]?)[^'\\\\"\\s,;}]{6,}\\2", r"\\1<VOLATILE>", text)
    text = re.sub(r"\\b[0-9a-f]{24,}\\b", "<HEX>", text, flags=re.I)
    text = re.sub(r"\\s+", " ", text).strip()
    return sha256(text.encode("utf-8")).hexdigest()


def _anomaly_score(*, status_changed: bool, server_error: bool,
                   location_changed: bool, content_type_changed: bool,
                   normalized_changed: bool, large_response: bool,
                   slow_response: bool, diagnostic: bool, reflected: bool) -> int:
    score = 0
    score += 45 if server_error else 0
    score += 20 if status_changed else 0
    score += 15 if location_changed else 0
    score += 10 if content_type_changed else 0
    score += 5 if normalized_changed else 0
    score += 10 if large_response else 0
    score += 5 if slow_response else 0
    score += 20 if diagnostic else 0
    score += 5 if reflected else 0
    return min(100, score)

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
    baseline_hash = sha256(baseline.body).hexdigest()
    baseline_normalized_hash = normalized_body_hash(baseline.body)
    baseline_location = baseline.headers.get("location", "")
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
        diagnostic = False
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
                diagnostic = True
                break
        reflected = bool(value) and value.encode("utf-8", errors="ignore") in response.body
        if reflected:
            notes.append("input value appears verbatim in the response; inspect output context and encoding")

        normalized_hash = normalized_body_hash(response.body)
        status_changed = response.status != baseline.status
        location_changed = response.headers.get("location", "") != baseline_location
        content_type_changed = response.headers.get("content-type", "") != baseline.headers.get("content-type", "")
        large_response = bool(baseline.body and response.body and len(response.body) > max(4096, len(baseline.body) * 5))
        slow_response = bool(baseline.elapsed_seconds > 0 and response.elapsed_seconds > max(3.0, baseline.elapsed_seconds * 5))
        normalized_changed = normalized_hash != baseline_normalized_hash
        score = _anomaly_score(
            status_changed=status_changed,
            server_error=response.status is not None and response.status >= 500,
            location_changed=location_changed,
            content_type_changed=content_type_changed,
            normalized_changed=normalized_changed,
            large_response=large_response,
            slow_response=slow_response,
            diagnostic=diagnostic,
            reflected=reflected,
        )
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
            response_changed=sha256(response.body).hexdigest() != baseline_hash,
            location_changed=response.headers.get("location", "") != baseline_location,
            server_error=response.status is not None and response.status >= 500,
            baseline_sha256=baseline_hash,
            endpoint_url=url,
            mutation_value=value,
            normalized_response_sha256=normalized_hash,
            baseline_normalized_sha256=baseline_normalized_hash,
            anomaly_score=score,
        ))
    return observations


def run_fuzz_many(url: str, parameters: list[str], scope: Scope,
                  client: SafeHttpClient, max_cases: int = 32) -> list[FuzzObservation]:
    """Fuzz multiple existing query parameters with one shared mutation budget."""
    scope.validate_url(url)
    if not 1 <= max_cases <= 32:
        raise ValueError("max_cases must be between 1 and 32.")
    pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    available = list(dict.fromkeys(key for key, _ in pairs))
    selected = available if parameters == ["*"] else parameters
    if not selected:
        raise ValueError("The URL must contain at least one query parameter.")
    if len(selected) > 8:
        raise ValueError("At most 8 distinct parameters can be fuzzed per run.")
    missing = [name for name in selected if name not in available]
    if missing:
        raise ValueError(f"Parameter(s) not present in URL: {', '.join(missing)}.")
    # Each parameter needs one baseline plus at least one mutation.
    remaining = min(max_cases, max(0, client.max_requests - client.requests_made - len(selected)))
    if remaining < len(selected):
        raise ValueError("Request budget must allow one baseline and one mutation per selected parameter.")
    base, extra = divmod(remaining, len(selected))
    results: list[FuzzObservation] = []
    for index, parameter in enumerate(selected):
        budget = base + (1 if index < extra else 0)
        results.extend(run_fuzz(url, parameter, scope, client, budget))
    return results


def observations_to_dict(items: list[FuzzObservation]) -> list[dict]:
    return [asdict(item) for item in items]
