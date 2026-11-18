"""Safe HTTP method discovery using OPTIONS only; never sends unsafe methods."""
from __future__ import annotations

from .checks import Finding
from .http_client import SafeHttpClient
from .scope import Scope


def inspect_http_methods(target: str, scope: Scope, client: SafeHttpClient) -> list[Finding]:
    scope.validate_url(target)
    if client.requests_made >= client.max_requests:
        return []
    response = client.options(target)
    if response.status is None:
        return []
    allow = response.headers.get("allow", "")
    methods = {method.strip().upper() for method in allow.split(",") if method.strip()}
    findings: list[Finding] = []
    if "TRACE" in methods:
        findings.append(Finding(
            category="http-methods",
            title="Server advertises the HTTP TRACE method",
            severity="medium",
            confidence="medium",
            url=target,
            evidence=f"OPTIONS returned HTTP {response.status} with Allow: {allow[:300]}. TRACE was advertised but was not invoked.",
            remediation="Disable TRACE at the web server or reverse proxy unless a documented requirement exists. Confirm the effective method policy at the edge and origin.",
            kind="advertised-method",
            description="The server advertises TRACE in its Allow header. This is a configuration signal, not proof that TRACE is exploitable.",
            impact="In some legacy configurations, TRACE can reflect request headers and expose data in browser-assisted attack chains.",
            cwe_ids=["CWE-693"],
            references=["https://cwe.mitre.org/data/definitions/693.html"],
            remediation_steps=["Disable TRACE at the edge and origin.", "Recheck the Allow header after configuration changes."],
        ))
    for method in ("PUT", "DELETE", "CONNECT"):
        if method in methods:
            findings.append(Finding(
                category="http-methods",
                title=f"Server advertises the {method} method",
                severity="info",
                confidence="medium",
                url=target,
                evidence=f"OPTIONS returned HTTP {response.status} with Allow: {allow[:300]}. {method} was advertised but was not invoked.",
                remediation="Confirm this method is required for the endpoint and enforce authentication, authorization, and route-level restrictions.",
                kind="observation",
                description="The server advertises a method that may permit state changes or tunnelling when enabled on an endpoint.",
                impact="No vulnerability is confirmed by an Allow header alone; the route may reject the method or require authorization.",
                cwe_ids=["CWE-749"],
                references=["https://cwe.mitre.org/data/definitions/749.html"],
            ))
    return findings
