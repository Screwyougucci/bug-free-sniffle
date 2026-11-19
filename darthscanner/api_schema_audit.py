"""Passive OpenAPI security review for subtle specification weaknesses.

This module never invokes documented API operations. Findings describe what a
published schema says (or omits), not what the live authorization layer enforces.
"""
from __future__ import annotations

from .checks import Finding


_SENSITIVE_SEGMENTS = {
    "admin", "administrator", "account", "accounts", "user", "users",
    "billing", "payment", "payments", "invoice", "invoices", "role",
    "roles", "permission", "permissions", "token", "tokens", "secret",
    "secrets", "export", "exports", "private", "profile", "profiles",
}
_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def inspect_openapi_schema(spec: dict, source_url: str) -> list[Finding]:
    """Review OpenAPI auth declarations and risky server URL metadata."""
    if not isinstance(spec, dict):
        return []
    findings: list[Finding] = []
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    schemes = schemes if isinstance(schemes, dict) else {}
    global_security = spec.get("security")
    global_security_present = isinstance(global_security, list) and bool(global_security)

    def add(title: str, evidence: str, impact: str, remediation: str,
            severity: str = "low", score: int = 45, cwe: str = "CWE-862") -> None:
        findings.append(Finding(
            category="api-schema-review",
            title=title,
            severity=severity,
            confidence="low",
            url=source_url,
            kind="schema-review-candidate",
            description="A published OpenAPI document contains a security-relevant declaration or omission.",
            impact=impact,
            evidence=evidence,
            remediation=remediation,
            cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation],
            confidence_score=score,
        ))

    servers = spec.get("servers", [])
    if isinstance(servers, list):
        for server in servers[:20]:
            if isinstance(server, dict) and isinstance(server.get("url"), str):
                url = server["url"].strip()
                if url.lower().startswith("http://"):
                    add(
                        "OpenAPI server URL uses plaintext HTTP",
                        "A documented server URL begins with http://; the URL itself is omitted.",
                        "Clients following this server declaration may send API data without transport encryption.",
                        "Use HTTPS server URLs and remove obsolete plaintext endpoints.",
                        "medium", 70, "CWE-319",
                    )

    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return findings
    for path, path_item in list(paths.items())[:5000]:
        if not isinstance(path, str) or not isinstance(path_item, dict):
            continue
        segments = {part.lower() for part in path.strip("/").split("/") if part and not part.startswith("{")}
        sensitive = bool(segments & _SENSITIVE_SEGMENTS)
        for method, operation in path_item.items():
            if method.lower() not in _METHODS or not isinstance(operation, dict):
                continue
            if "security" in operation:
                operation_security = operation.get("security")
                protected = isinstance(operation_security, list) and bool(operation_security)
                explicitly_public = operation_security == []
            else:
                protected = global_security_present
                explicitly_public = False
            if sensitive and not protected:
                suffix = " The operation explicitly overrides inherited security with an empty list." if explicitly_public else ""
                add(
                    "Sensitive-looking API operation has no declared security requirement",
                    f"{method.upper()} {path[:180]} has no effective OpenAPI security requirement.{suffix}",
                    "If the operation handles private or privileged data, an absent schema requirement may indicate an accidentally public endpoint. The runtime may enforce authentication outside the schema.",
                    "Confirm the intended access policy and declare operation-level or global security requirements; independently test authorization with approved test accounts.",
                    "medium", 50, "CWE-862",
                )

    for name, scheme in list(schemes.items())[:200]:
        if not isinstance(scheme, dict):
            continue
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            add(
                "OpenAPI API key is documented in a query parameter",
                f"Security scheme {str(name)[:80]!r} declares type=apiKey and in=query; key values are not present in this report.",
                "Query-string credentials can be retained in browser history, proxy logs, analytics, and referrer data.",
                "Prefer an Authorization header or another approved credential transport; redact secrets from logs and URLs.",
                "low", 60, "CWE-598",
            )
        if scheme.get("type") == "http" and str(scheme.get("scheme", "")).lower() == "basic":
            add(
                "OpenAPI documents HTTP Basic authentication",
                f"Security scheme {str(name)[:80]!r} uses HTTP Basic authentication.",
                "Basic credentials are only protected in transit by TLS and may be exposed if any client uses a plaintext endpoint.",
                "Require HTTPS everywhere and consider a stronger short-lived token-based authentication design.",
                "info", 55, "CWE-522",
            )
    return findings
