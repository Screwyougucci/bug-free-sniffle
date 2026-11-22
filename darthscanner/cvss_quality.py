"""CVSS vector quality checks for published CVE metrics.

CVSS is a vulnerability severity score, not proof that a target is exploitable.
Only CVSS 3.1 vectors are independently recalculated here. CVSS 4.0 scores are
preserved as published by NVD/CNA; this module does not invent missing metrics.
"""
from __future__ import annotations

import math
import re

_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27},
           "C": {"N": 0.85, "L": 0.68, "H": 0.50}},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def calculate_cvss31(vector: str) -> float:
    """Calculate the CVSS v3.1 base score from a complete base vector."""
    text = str(vector or "")
    if not text.startswith("CVSS:3.1/"):
        raise ValueError("Only CVSS:3.1 vectors can be recalculated.")
    metrics = {}
    for part in text[len("CVSS:3.1/"):].split("/"):
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            raise ValueError("Malformed or duplicate CVSS metric.")
        metrics[key] = value
    if any(key not in metrics for key in _REQUIRED):
        raise ValueError("CVSS 3.1 base vector is incomplete.")
    if any(metrics[key] not in _METRICS[key] for key in ("AV", "AC", "UI", "S")):
        raise ValueError("CVSS 3.1 vector contains an invalid metric.")
    if metrics["PR"] not in _METRICS["PR"]["U"]:
        raise ValueError("CVSS 3.1 vector contains an invalid PR metric.")
    if any(metrics[key] not in _METRICS["CIA"] for key in ("C", "I", "A")):
        raise ValueError("CVSS 3.1 vector contains an invalid impact metric.")
    scope = metrics["S"]
    av = _METRICS["AV"][metrics["AV"]]
    ac = _METRICS["AC"][metrics["AC"]]
    pr = _METRICS["PR"][scope][metrics["PR"]]
    ui = _METRICS["UI"][metrics["UI"]]
    c = _METRICS["CIA"][metrics["C"]]
    i = _METRICS["CIA"][metrics["I"]]
    a = _METRICS["CIA"][metrics["A"]]
    isc = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope == "U":
        impact = 6.42 * isc
    else:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    return _roundup(base)


def validate_cvss_metric(score, version: str | None, vector: str | None) -> dict:
    """Return provenance and consistency metadata without fabricating a score."""
    result = {
        "source": "NVD/CNA published metric",
        "published_score": score,
        "published_version": version,
        "vector": vector,
        "calculated_score": None,
        "status": "published-score-only",
        "note": "CVSS base severity is not target-specific exploitability or risk.",
    }
    if score is None or not vector:
        result["status"] = "missing-score-or-vector"
        return result
    if str(version or "").startswith("3.1") and str(vector).startswith("CVSS:3.1/"):
        calculated = calculate_cvss31(vector)
        result["calculated_score"] = calculated
        result["status"] = "consistent" if abs(float(score) - calculated) < 0.051 else "score-vector-mismatch"
        if result["status"] == "score-vector-mismatch":
            result["note"] = "Published score and vector-derived CVSS 3.1 base score differ; verify the source record."
    elif str(version or "").startswith("4.0") and str(vector).startswith("CVSS:4.0/"):
        result["status"] = "published-cvss-4.0"
        result["note"] = "CVSS 4.0 is retained from NVD/CNA; no local re-score is attempted."
    return result
