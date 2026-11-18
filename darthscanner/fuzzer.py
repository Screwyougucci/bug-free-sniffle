"""Low-rate, non-destructive GET query-parameter robustness fuzzer."""
from __future__ import annotations

from dataclasses import asdict, dataclass
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


def _variants() -> list[tuple[str, str]]:
    return [
        ("empty", ""),
        ("zero", "0"),
        ("negative-one", "-1"),
        ("short-boundary", "A" * 32),
        ("bounded-long", "A" * 128),
        ("whitespace", " value with spaces "),
        ("unicode", "café-東京-🙂"),
        ("reserved-characters", "a&b=c?d#e"),
        ("percent-literal", "100%25"),
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
             max_cases: int = 9) -> list[FuzzObservation]:
    scope.validate_url(url)
    if not 1 <= max_cases <= 20:
        raise ValueError("max_cases must be between 1 and 20.")
    parts = urlsplit(url)
    if not any(key == parameter for key, _ in parse_qsl(parts.query, keep_blank_values=True)):
        raise ValueError(f"Parameter {parameter!r} is not present in the URL.")

    baseline = client.get(url)
    observations: list[FuzzObservation] = []
    for case, value in _variants()[:max_cases]:
        if client.requests_made >= client.max_requests:
            break
        mutated_url = mutate_query_parameter(url, parameter, value)
        response = client.get(mutated_url)
        notes = []
        if response.status is not None and response.status >= 500:
            notes.append("server returned a 5xx response; review server logs")
        if response.status != baseline.status:
            notes.append(f"status changed from {baseline.status} to {response.status}")
        if baseline.body and response.body and len(response.body) > max(4096, len(baseline.body) * 5):
            notes.append("response size increased substantially")
        if baseline.elapsed_seconds > 0 and response.elapsed_seconds > max(3.0, baseline.elapsed_seconds * 5):
            notes.append("response was substantially slower than baseline")
        observations.append(FuzzObservation(
            parameter, case, response.status, len(response.body), response.elapsed_seconds,
            "; ".join(notes) if notes else "no notable response difference",
        ))
    return observations


def observations_to_dict(items: list[FuzzObservation]) -> list[dict]:
    return [asdict(item) for item in items]
