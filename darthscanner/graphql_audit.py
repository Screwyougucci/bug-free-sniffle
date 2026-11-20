"""Bounded GraphQL client-operation discovery and introspection schema review.

Client source is parsed as text only. Schema review accepts a locally supplied
introspection document; it never sends GraphQL operations to a target.
"""
from __future__ import annotations

import re
from .checks import Finding

_OPERATION = re.compile(
    r"\\b(query|mutation|subscription)\\s*([A-Za-z_][A-Za-z0-9_]*)?\\s*(?:\\([^{}]*\\))?\\s*\\{",
    re.I,
)
_SENSITIVE = {
    "role", "roles", "admin", "isadmin", "superuser", "ownerid", "userid",
    "tenantid", "permissions", "permission", "balance", "creditlimit",
    "email", "phone", "password", "secret", "token", "apikey",
}
_PAGE_ARGS = {"first", "last", "limit", "take", "page", "pagesize", "offset", "skip", "after", "before"}


def discover_graphql_operations(source_url: str, source: str, max_operations: int = 100) -> list[dict]:
    """Inventory named/anonymous GraphQL operations from bounded JS source text."""
    if not 1 <= max_operations <= 250:
        raise ValueError("max_operations must be between 1 and 250.")
    text = source[:1_000_000]
    found = {}
    for match in _OPERATION.finditer(text):
        kind = match.group(1).lower()
        name = match.group(2) or "(anonymous)"
        start = match.end()
        # Only retain top-level field identifiers; argument values and query text are discarded.
        depth = 1
        i = start
        fields = []
        expect_field = True
        while i < min(len(text), start + 12000) and depth:
            char = text[i]
            if char == "{":
                depth += 1
                expect_field = True
            elif char == "}":
                depth -= 1
                expect_field = False
            elif depth == 1 and (char.isalpha() or char == "_") and (i == 0 or not (text[i-1].isalnum() or text[i-1] == "_")):
                end = i + 1
                while end < len(text) and (text[end].isalnum() or text[end] == "_"):
                    end += 1
                token = text[i:end]
                if token not in {"on"} and token not in fields:
                    fields.append(token)
                i = end - 1
            i += 1
        item = {"source_url": source_url, "operation_type": kind, "operation_name": name[:120],
                "root_field_names": fields[:40], "source_line": text.count("\\n", 0, match.start()) + 1}
        found[(kind, name, tuple(item["root_field_names"]))] = item
        if len(found) >= max_operations:
            break
    return list(found.values())


def _type_name(ref):
    current = ref
    for _ in range(12):
        if not isinstance(current, dict):
            return None
        if current.get("name"):
            return current["name"]
        current = current.get("ofType")
    return None


def inspect_graphql_introspection(document: dict, source_url: str) -> list[Finding]:
    """Review an introspection JSON document for API design risk candidates."""
    if not isinstance(document, dict):
        return []
    data = document.get("data", document)
    schema = data.get("__schema") if isinstance(data, dict) else None
    types = schema.get("types") if isinstance(schema, dict) else None
    if not isinstance(types, list):
        return []
    findings = []
    def add(title, evidence, impact, remediation, cwe, score=55):
        findings.append(Finding(
            category="graphql-schema-review", title=title, severity="medium",
            confidence="low", url=source_url, kind="graphql-schema-candidate",
            description="The supplied GraphQL introspection schema exposes a design pattern worth reviewing; it does not prove runtime exploitability.",
            impact=impact, evidence=evidence, remediation=remediation,
            cwe_ids=[cwe], references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
            remediation_steps=[remediation, "Verify resolver authorization and runtime limits using dedicated test accounts in an authorized environment."],
            confidence_score=score,
        ))
    for type_def in types[:5000]:
        if not isinstance(type_def, dict) or not isinstance(type_def.get("name"), str):
            continue
        type_name = type_def["name"]
        if type_name.startswith("__"):
            continue
        fields = type_def.get("fields")
        if not isinstance(fields, list):
            continue
        for field in fields[:1000]:
            if not isinstance(field, dict) or not isinstance(field.get("name"), str):
                continue
            field_name = field["name"]
            args = field.get("args", [])
            args = args if isinstance(args, list) else []
            arg_names = {a.get("name", "").lower() for a in args if isinstance(a, dict)}
            if type_name == "Mutation":
                sensitive = sorted(a.get("name") for a in args if isinstance(a, dict)
                                   and isinstance(a.get("name"), str)
                                   and a["name"].lower().replace("_", "") in _SENSITIVE)
                if sensitive:
                    add("GraphQL mutation accepts privilege- or identity-sensitive arguments",
                        f"Mutation.{field_name} declares sensitive argument names: {', '.join(sensitive[:8])}. Values are not present in the schema.",
                        "If resolver authorization or field-level allowlisting is incomplete, callers may attempt to alter identity, privilege, or sensitive account data.",
                        "Derive identity and privilege attributes server-side; enforce authorization in each resolver and reject client-controlled privilege fields.",
                        "CWE-915", 60)
            type_ref = field.get("type")
            named_type = _type_name(type_ref)
            is_list = isinstance(type_ref, dict) and (type_ref.get("kind") == "LIST" or isinstance(type_ref.get("ofType"), dict) and type_ref["ofType"].get("kind") == "LIST")
            if type_name == "Query" and is_list and not (arg_names & _PAGE_ARGS):
                add("GraphQL list query declares no pagination argument",
                    f"Query.{field_name} returns a list-like type ({named_type or 'wrapped type'}) and declares no common pagination argument.",
                    "An unrestricted resolver may permit expensive or excessively large responses, increasing denial-of-service and resource-exhaustion risk.",
                    "Enforce server-side maximum result sizes, query depth/complexity budgets, timeouts, and pagination regardless of client arguments.",
                    "CWE-400", 55)
    return findings
