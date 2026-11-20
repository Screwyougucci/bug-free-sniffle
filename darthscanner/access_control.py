"""Differential, read-only object authorization verification with two test identities.

The caller must identify an object that should be accessible to the owner identity
only. The module sends at most two same-origin GET requests and never stores bodies
or credentials. A 2xx response for the second identity is a candidate, not proof:
the resource may intentionally be shared or public.
"""
from __future__ import annotations

from hashlib import sha256

from .checks import Finding
from .http_client import SafeHttpClient
from .scope import Scope


def verify_object_access(
    url: str,
    owner_token: str,
    other_token: str,
    scope: Scope,
    client: SafeHttpClient,
) -> dict:
    """Compare owner and non-owner bearer-token access to one caller-designated object."""
    scope.validate_url(url)
    if not owner_token or not other_token:
        raise ValueError("Both owner and other-user bearer tokens are required.")
    if owner_token == other_token:
        raise ValueError("Owner and other-user tokens must be different.")
    if client.max_requests < 2:
        raise ValueError("The active request budget must allow two GET requests.")

    owner = client.get(url, headers={"Authorization": f"Bearer {owner_token}"})
    owner_meta = _metadata(owner)
    if owner.status is None or not 200 <= owner.status < 300:
        return {
            "url": url, "owner": owner_meta, "other": None, "finding": None,
            "note": "Owner identity did not receive a successful response; comparison stopped.",
        }

    other = client.get(url, headers={"Authorization": f"Bearer {other_token}"})
    other_meta = _metadata(other)
    finding = None
    if other.status is not None and 200 <= other.status < 300:
        same_body = bool(owner.body) and sha256(owner.body).digest() == sha256(other.body).digest()
        substantial_body = min(len(owner.body), len(other.body)) >= 32
        score = 90 if same_body and substantial_body else 68
        finding = Finding(
            category="access-control",
            title="Object endpoint is accessible to a second test identity",
            severity="high" if score >= 85 else "medium",
            confidence="high" if score >= 85 else "medium",
            url=url,
            kind="differential-access-control-candidate",
            description=(
                "The designated owner identity and a distinct test identity both received "
                "successful GET responses for an object the operator marked owner-only."
            ),
            impact=(
                "If the second identity is not entitled to this object, this may be a broken "
                "object-level authorization (BOLA/IDOR) vulnerability exposing another user's data."
            ),
            evidence=(
                f"Owner HTTP {owner.status}; second identity HTTP {other.status}; "
                f"response bodies {'match' if same_body else 'differ'} by SHA-256; "
                f"body lengths {len(owner.body)} and {len(other.body)} bytes. "
                "Response bodies and credentials were not retained."
            ),
            remediation=(
                "Enforce object-level authorization on every request using the authenticated "
                "principal and the requested object's ownership or explicit sharing policy."
            ),
            cwe_ids=["CWE-862", "CWE-639"],
            references=[
                "https://cwe.mitre.org/data/definitions/862.html",
                "https://cwe.mitre.org/data/definitions/639.html",
            ],
            remediation_steps=[
                "Confirm the second identity has no legitimate sharing or administrative permission.",
                "Enforce server-side ownership/tenant checks before returning the object.",
                "Add regression tests proving a different user receives 403 or 404.",
            ],
            confidence_score=score,
        )
    note = (
        "Second identity received a successful response. Review whether the resource is intentionally shared."
        if finding else
        "The second identity did not receive a successful response; no cross-identity access candidate was observed."
        if other.status is not None and 400 <= other.status < 500 else
        "Comparison was inconclusive; inspect status and transport metadata."
    )
    return {"url": url, "owner": owner_meta, "other": other_meta,
            "finding": finding, "note": note}


def _metadata(response) -> dict:
    return {
        "status": response.status,
        "response_bytes": len(response.body),
        "response_sha256": sha256(response.body).hexdigest() if response.body else "",
        "elapsed_seconds": round(response.elapsed_seconds, 3),
        "error": response.error,
    }
