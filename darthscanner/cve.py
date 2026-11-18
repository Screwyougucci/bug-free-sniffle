"""Offline matching of fingerprinted CPEs against NVD 2.0 JSON feeds.

CPE matches are candidate matches. NVD configurations can include platform
conditions and logical operators that require environment-level validation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from pathlib import Path
from typing import Any

from .checks import Finding
from .fingerprint import SoftwareComponent


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str
    score: float | None
    severity: str
    cvss_version: str | None
    vector: str | None
    references: tuple[str, ...]
    criteria: tuple[str, ...]


def severity_from_cvss(score: float | None, supplied: str | None = None) -> str:
    """Map CVSS base score to standard qualitative severity bands."""
    if score is None:
        value = (supplied or "").strip().lower()
        return value if value in {"critical", "high", "medium", "low"} else "info"
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _version_parts(value: str) -> tuple[int, ...] | None:
    """Numeric dotted versions only; avoid guessing about vendor suffixes."""
    text = value.strip().lstrip("vV")
    if not re.fullmatch(r"\d+(?:\.\d+)*", text):
        return None
    return tuple(int(part) for part in text.split("."))


def _cpe_parts(value: str) -> list[str] | None:
    parts = value.split(":")
    if len(parts) < 6 or parts[0:2] != ["cpe", "2.3"]:
        return None
    return parts


def _version_matches(candidate: str, criteria: str, item: dict[str, Any]) -> bool:
    if criteria not in {"*", "-"}:
        return candidate.casefold() == criteria.casefold()
    ranges = {
        "versionStartIncluding": (True, True),
        "versionStartExcluding": (True, False),
        "versionEndIncluding": (False, True),
        "versionEndExcluding": (False, False),
    }
    candidate_parts = _version_parts(candidate)
    if any(key in item for key in ranges):
        if candidate_parts is None:
            return False
        for key, (is_start, inclusive) in ranges.items():
            bound = item.get(key)
            if not bound:
                continue
            bound_parts = _version_parts(str(bound))
            if bound_parts is None:
                return False
            if is_start and (candidate_parts < bound_parts or (not inclusive and candidate_parts == bound_parts)):
                return False
            if not is_start and (candidate_parts > bound_parts or (not inclusive and candidate_parts == bound_parts)):
                return False
    return True


def _cpe_match(candidate: str, item: dict[str, Any]) -> bool:
    criteria = str(item.get("criteria", ""))
    left = _cpe_parts(candidate)
    right = _cpe_parts(criteria)
    if not left or not right:
        return False
    # Match CPE part, vendor, and product exactly. Do not interpret wildcard
    # vendor/product values as a match because that would create noisy alerts.
    for index in (2, 3, 4):
        if left[index].casefold() != right[index].casefold():
            return False
    return _version_matches(left[5], right[5], item)


def _walk_cpe_matches(node: Any):
    if isinstance(node, dict):
        items = node.get("cpeMatch")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("vulnerable") is True:
                    yield item
        for key in ("nodes", "children"):
            nested = node.get(key)
            if isinstance(nested, list):
                for child in nested:
                    yield from _walk_cpe_matches(child)
    elif isinstance(node, list):
        for child in node:
            yield from _walk_cpe_matches(child)


def _score(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    preference = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in preference:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer NVD's own assessment if available, else first CNA metric.
        entries = sorted(entries, key=lambda entry: 0 if entry.get("type") == "Primary" else 1)
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score), str(data.get("version") or key), str(data.get("vectorString") or "") or None, str(data.get("baseSeverity") or entry.get("baseSeverity") or "") or None
    return None, None, None, None


def load_nvd_feed(path: str | Path) -> list[dict[str, Any]]:
    """Load an NVD CVE API 2.0 JSON file or export."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read NVD JSON feed: {exc}") from exc
    records = raw.get("vulnerabilities") if isinstance(raw, dict) else None
    if not isinstance(records, list):
        raise ValueError("NVD file must be a JSON object containing a vulnerabilities array.")
    return [entry["cve"] for entry in records if isinstance(entry, dict) and isinstance(entry.get("cve"), dict)]


def load_inventory(path: str | Path) -> list[SoftwareComponent]:
    """Load a JSON inventory containing a components array with CPE 2.3 entries."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read software inventory: {exc}") from exc
    entries = raw.get("components") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ValueError("Inventory must be a JSON object containing a components array.")
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("cpe"), str):
            continue
        cpe = entry["cpe"]
        if not _cpe_parts(cpe):
            continue
        parts = _cpe_parts(cpe)
        result.append(SoftwareComponent(
            name=str(entry.get("name") or f"{parts[3]} {parts[4]}"),
            version=str(entry.get("version") or parts[5]),
            cpe=cpe,
            source="user-supplied asset inventory",
            confidence="high",
        ))
    return result


def match_cves(components: list[SoftwareComponent], feed: list[dict[str, Any]]) -> list[Finding]:
    """Create detailed candidate CVE findings for CPE/version matches."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for cve in feed:
        cve_id = str(cve.get("id") or "")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue
        descriptions = cve.get("descriptions") or []
        description = next((str(d.get("value")) for d in descriptions
                            if d.get("lang") == "en" and d.get("value")), "No English description in feed.")
        score, cvss_version, vector, supplied_severity = _score(cve)
        severity = severity_from_cvss(score, supplied_severity)
        references = tuple(
            str(ref.get("url")) for ref in cve.get("references", [])
            if isinstance(ref, dict) and ref.get("url")
        )
        config = cve.get("configurations") or []
        candidate_matches = []
        criteria_seen = set()
        for node in config:
            for match in _walk_cpe_matches(node):
                for component in components:
                    if _cpe_match(component.cpe, match):
                        criteria = str(match.get("criteria"))
                        if (component.cpe, criteria) not in criteria_seen:
                            candidate_matches.append((component, criteria))
                            criteria_seen.add((component.cpe, criteria))
        for component, criteria in candidate_matches:
            key = (cve_id, component.cpe)
            if key in seen:
                continue
            seen.add(key)
            range_text = []
            for name in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                if match_value := next((m.get(name) for node in config for m in _walk_cpe_matches(node)
                                        if str(m.get("criteria")) == criteria and m.get(name)), None):
                    range_text.append(f"{name}={match_value}")
            evidence = f"Detected {component.name} {component.version} ({component.cpe}); matched NVD CPE criteria {criteria}."
            if range_text:
                evidence += " Version constraints: " + ", ".join(range_text) + "."
            findings.append(Finding(
                category="cve",
                title=f"{cve_id}: {component.name} {component.version} may be affected",
                severity=severity,
                confidence="medium",
                url="asset-inventory",
                evidence=evidence,
                remediation="Verify the installed vendor build and affected-version range, then upgrade to a vendor-fixed release or apply the vendor mitigation. Check the linked advisory before changing production systems.",
                kind="candidate-vulnerability",
                description=description,
                impact="Potential impact is described by the CVE record. Actual impact depends on the deployed configuration, reachable attack surface, and vendor backports.",
                cvss_score=score,
                cvss_version=cvss_version,
                cvss_vector=vector,
                cve_ids=[cve_id],
                references=[f"https://nvd.nist.gov/vuln/detail/{cve_id}", *references],
                affected_component=f"{component.name} {component.version}",
            ))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda item: (rank.get(item.severity, 5), -(item.cvss_score or 0), item.title))
