"""Passive OpenAPI security review for subtle specification weaknesses.

Findings describe published schema declarations, not runtime authorization behavior.
No API operations are invoked.
"""
from __future__ import annotations
import re
from .checks import Finding

_IDENTITY_PARAM = re.compile(r"(?i)(?:^|[_-])(?:id|uuid|key)$|(?:id|uuid|key)$")
_PRIVILEGE_FIELDS = {
    "admin", "isadmin", "superuser", "issuperuser", "role", "roles",
    "permissions", "permission", "ownerid", "userid", "tenantid",
    "accountid", "organizationid", "orgid", "balance", "creditlimit",
    "subscriptiontier", "planid", "verified", "isverified",
}
_WRITE_METHODS = {"post", "put", "patch"}


def _resolve_local_ref(spec: dict, ref: str):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    current = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current if isinstance(current, dict) else None


def _schema_properties(spec: dict, schema: dict, *, depth: int = 0,
                       seen: set[str] | None = None, prefix: str = ""):
    """Yield bounded property paths, resolving only local OpenAPI references."""
    if depth > 8 or not isinstance(schema, dict):
        return
    seen = set() if seen is None else seen
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:
            return
        target = _resolve_local_ref(spec, ref)
        if target is not None:
            yield from _schema_properties(spec, target, depth=depth + 1,
                                          seen=seen | {ref}, prefix=prefix)
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in list(properties.items())[:250]:
            if not isinstance(name, str) or not isinstance(child, dict):
                continue
            path = f"{prefix}.{name}" if prefix else name
            yield path, name, child
            yield from _schema_properties(spec, child, depth=depth + 1,
                                          seen=seen, prefix=path)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _schema_properties(spec, items, depth=depth + 1,
                                      seen=seen, prefix=f"{prefix}[]")


def _request_body_schema(spec: dict, operation: dict):
    body = operation.get("requestBody")
    if isinstance(body, dict) and isinstance(body.get("$ref"), str):
        body = _resolve_local_ref(spec, body["$ref"])
    if not isinstance(body, dict):
        return []
    content = body.get("content")
    if not isinstance(content, dict):
        return []
    schemas = []
    for media in list(content.values())[:20]:
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            schemas.append(media["schema"])
    return schemas

_SENSITIVE_SEGMENTS={"admin","administrator","account","accounts","user","users","billing","payment","payments","invoice","invoices","role","roles","permission","permissions","token","tokens","secret","secrets","export","exports","private","profile","profiles"}
_METHODS={"get","post","put","patch","delete","options","head"}

def inspect_openapi_schema(spec: dict, source_url: str) -> list[Finding]:
    if not isinstance(spec,dict): return []
    findings=[]
    components=spec.get("components",{})
    schemes=components.get("securitySchemes",{}) if isinstance(components,dict) else {}
    schemes=schemes if isinstance(schemes,dict) else {}
    global_security=spec.get("security")
    global_security_present=isinstance(global_security,list) and bool(global_security)

    def add(title,evidence,impact,remediation,severity="low",score=45,cwe="CWE-862"):
        findings.append(Finding(category="api-schema-review",title=title,severity=severity,
            confidence="low",url=source_url,kind="schema-review-candidate",
            description="A published OpenAPI document contains a security-relevant declaration or omission.",
            impact=impact,evidence=evidence,remediation=remediation,cwe_ids=[cwe],
            references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation],confidence_score=score))
    servers=spec.get("servers",[])
    if isinstance(servers,list):
        for server in servers[:20]:
            if isinstance(server,dict) and isinstance(server.get("url"),str) and server["url"].strip().lower().startswith("http://"):
                add("OpenAPI server URL uses plaintext HTTP",
                    "A documented server URL begins with http://; the URL itself is omitted.",
                    "Clients following this declaration may send API data without transport encryption.",
                    "Use HTTPS server URLs and remove obsolete plaintext endpoints.","medium",70,"CWE-319")
    paths=spec.get("paths",{})
    if not isinstance(paths,dict): return findings
    for path,path_item in list(paths.items())[:5000]:
        if not isinstance(path,str) or not isinstance(path_item,dict): continue
        segments={part.lower() for part in path.strip("/").split("/") if part and not part.startswith("{")}
        sensitive=bool(segments&_SENSITIVE_SEGMENTS)
        for method,operation in path_item.items():
            if not isinstance(method,str) or method.lower() not in _METHODS or not isinstance(operation,dict): continue
            if "security" in operation:
                op_security=operation.get("security")
                protected=isinstance(op_security,list) and bool(op_security)
                explicitly_public=op_security==[]
            else:
                protected=global_security_present
                explicitly_public=False
            if sensitive and not protected:
                suffix=" The operation explicitly overrides inherited security with an empty list." if explicitly_public else ""
                add("Sensitive-looking API operation has no declared security requirement",
                    f"{method.upper()} {path[:180]} has no effective OpenAPI security requirement.{suffix}",
                    "An absent schema requirement may indicate an accidentally public operation; runtime middleware may enforce access controls outside the schema.",
                    "Confirm intended access policy, declare OpenAPI security requirements, and verify authorization with approved test accounts.",
                    "medium",50,"CWE-862")

            identity_params = re.findall(r"\\{([^{}]+)\\}", path)
            object_identifier = any(_IDENTITY_PARAM.search(name.strip()) for name in identity_params)
            if object_identifier and not protected:
                suffix = " The operation explicitly overrides inherited security with an empty list." if explicitly_public else ""
                add("Object-identifier API route has no declared security requirement",
                    f"{method.upper()} {path[:180]} contains an identifier parameter but has no effective OpenAPI security requirement.{suffix}",
                    "An unauthenticated object route may expose records or permit unintended actions. The schema cannot establish whether runtime middleware protects the route.",
                    "Confirm whether the route is intentionally public; otherwise declare authentication and enforce per-object authorization for every identifier.",
                    "medium",55,"CWE-862")

            if method.lower() in _WRITE_METHODS:
                risky_fields = []
                for body_schema in _request_body_schema(spec, operation):
                    for field_path, field_name, field_schema in _schema_properties(spec, body_schema):
                        normalized = re.sub(r"[^a-z0-9]", "", field_name.lower())
                        if normalized in _PRIVILEGE_FIELDS and not field_schema.get("readOnly", False):
                            risky_fields.append(field_path[:120])
                if risky_fields:
                    sample = ", ".join(sorted(set(risky_fields))[:8])
                    add("Write operation accepts privilege-sensitive fields in its request schema",
                        f"{method.upper()} {path[:180]} declares writable fields: {sample}. Values are not inspected.",
                        "If the server binds request fields directly to persistent models, a caller may be able to alter ownership, roles, permissions, balances, or account state.",
                        "Use explicit input DTOs and server-side allowlists; derive ownership and privilege fields from the authenticated principal, not client input.",
                        "medium",60,"CWE-915")
    for name,scheme in list(schemes.items())[:200]:
        if not isinstance(scheme,dict): continue
        if scheme.get("type")=="apiKey" and scheme.get("in")=="query":
            add("OpenAPI API key is documented in a query parameter",
                f"Security scheme {str(name)[:80]!r} declares type=apiKey and in=query; key values are not included.",
                "Query-string credentials can be retained in browser history, proxy logs, analytics, and referrer data.",
                "Prefer an Authorization header or approved credential transport; redact secrets from logs and URLs.",
                "low",60,"CWE-598")
        if scheme.get("type")=="http" and str(scheme.get("scheme","")).lower()=="basic":
            add("OpenAPI documents HTTP Basic authentication",
                f"Security scheme {str(name)[:80]!r} uses HTTP Basic authentication.",
                "Basic credentials rely on TLS and may be exposed if a client uses a plaintext endpoint.",
                "Require HTTPS everywhere and consider short-lived token-based authentication.",
                "info",55,"CWE-522")
    return findings
