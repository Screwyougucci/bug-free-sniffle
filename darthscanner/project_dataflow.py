"""Bounded cross-function source review for JavaScript/TypeScript, PHP, Java, and Go.

Lexical summaries are deliberately conservative and path-insensitive. No source is
executed and no network traffic is generated. Findings are review candidates.
"""
from __future__ import annotations

from pathlib import Path
import re

from .checks import Finding
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS

_LANGUAGES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java", ".go"}
_IDENT = re.compile(r"[$A-Za-z_][\w$]*")
_SOURCE = re.compile(
    r"(?:req(?:uest)?\.(?:query|body|params|headers|cookies)|ctx\.(?:query|request\.body)|"
    r"location\.(?:search|hash)|URLSearchParams|event\.data|\$_(?:GET|POST|REQUEST|COOKIE|FILES)|"
    r"getParameter\s*\(|getHeader\s*\(|getQueryString\s*\(|getPart\s*\(|"
    r"\.FormValue\s*\(|\.PostForm\.Get\s*\(|\.URL\.Query\(\)\.Get\s*\()", re.I
)
_SINKS = {
    "sql": (re.compile(r"(?:(?:\.|->)(?:executeQuery|executeUpdate|execute|query|exec|raw|QueryContext|ExecContext))\s*\(", re.I), "CWE-89", "Request-derived data may reach a database query through a helper", "Use parameterized queries and bind untrusted values separately from query text."),
    "ssrf": (re.compile(r"(?:fetch|axios\.(?:get|post|request)|https?\.request|http\.request|\.Do\s*\(|http\.(?:Get|Post)|curl_exec)\s*\(", re.I), "CWE-918", "Request-derived data may reach an outbound request through a helper", "Allowlist destination hosts and schemes; validate resolved addresses and redirects."),
    "file": (re.compile(r"(?:\bopen\s*\(|readFile(?:Sync)?\s*\(|file_get_contents\s*\(|writeFile(?:Sync)?\s*\(|new\s+File\s*\(|Paths\.get\s*\(|os\.Open\s*\()", re.I), "CWE-22", "Request-derived data may reach a filesystem operation through a helper", "Canonicalize paths and verify containment within an allowed base directory."),
    "command": (re.compile(r"(?:exec(?:Sync)?|spawn|system|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(", re.I), "CWE-78", "Request-derived data may reach a process operation through a helper", "Avoid shell interpretation; use fixed executables and structured arguments."),
    "template": (re.compile(r"(?:render_template_string|new\s+Template|Template\s*\(|createTemplate|Mustache\.render|\.ExecuteTemplate\s*\()", re.I), "CWE-94", "Request-derived data may reach a dynamic template operation through a helper", "Keep template source trusted and pass untrusted values only as escaped data."),
    "deserialize": (re.compile(r"(?:unserialize|ObjectInputStream|readObject|yaml\.load|gob\.NewDecoder)\s*\(", re.I), "CWE-502", "Request-derived data may reach an unsafe deserializer through a helper", "Use schema-validated data formats and avoid native object deserialization of untrusted input."),
}
_DECLARATIONS = {
    "js": re.compile(r"\bfunction\s*([\w$]+)?\s*\(([^)]*)\)\s*\{|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{"),
    "php": re.compile(r"\bfunction\s+&?([\w$]+)\s*\(([^)]*)\)\s*\{", re.I),
    "java": re.compile(r"\b(?:public|protected|private|static|final|synchronized|\s)+[\w<>?,.\[\]]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+)?\{"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:\([^)]*\)|[\w*\[\].]+)?\s*\{"),
}

def _clean(line: str, language: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith(("//", "/*", "*")) or (language == "php" and stripped.startswith("#")):
        return ""
    return line

def _params(raw: str, language: str) -> list[str]:
    result = []
    for part in raw.split(","):
        part = part.strip().split("=")[0].strip()
        if not part:
            continue
        if language == "go":
            names = _IDENT.findall(part)
            name = names[0] if names else ""
        elif language == "js" and ":" in part:
            name = part.split(":", 1)[0].strip()
        elif language == "php":
            names = _IDENT.findall(part)
            name = names[-1] if names else ""
        else:
            names = _IDENT.findall(part)
            name = names[-1] if names else ""
        if name:
            result.append(name)
    return result

def _functions(lines: list[str], language: str) -> list[dict]:
    pattern = _DECLARATIONS[language]
    result = []
    index = 0
    while index < len(lines):
        match = pattern.search(lines[index])
        if not match:
            index += 1
            continue
        groups = match.groups()
        if language == "js":
            name = groups[0] or groups[2] or "<anonymous>"
            raw_params = groups[1] if groups[1] is not None else (groups[3] or "")
        else:
            name, raw_params = groups[0], groups[1]
        start = index
        depth = lines[index].count("{") - lines[index].count("}")
        body = [lines[index]]
        index += 1
        while index < len(lines) and depth > 0 and len(body) < 3000:
            body.append(lines[index])
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
        if depth <= 0:
            result.append({"name": name, "params": _params(raw_params, language), "start": start + 1, "body": body})
    return result

def _summarize(fn: dict, language: str) -> tuple[dict[str, set[int]], set[int]]:
    params = fn["params"]
    sinks: dict[str, set[int]] = {key: set() for key in _SINKS}
    returns: set[int] = set()
    # Each parameter is analyzed independently. Branches are conservatively
    # unioned: a value assigned on either branch remains a candidate afterwards.
    for parameter_index, parameter in enumerate(params):
        tainted = {parameter}
        for line in fn["body"]:
            clean = _clean(line, language)
            if not clean:
                continue
            property_assignment = re.search(r"([$A-Za-z_]\\w*)\\s*(?:\\.|->)\\s*([$A-Za-z_]\\w*)\\s*=\\s*(.+)", clean)
            if property_assignment:
                owner, _field, expression = property_assignment.groups()
                ids = set(_IDENT.findall(expression))
                if _SOURCE.search(expression) or ids & tainted:
                    tainted.add(owner)
            indexed_assignment = re.search(r"([$A-Za-z_]\\w*)\\s*\\[[^]]+\\]\\s*=\\s*(.+)", clean)
            if indexed_assignment:
                owner, expression = indexed_assignment.groups()
                ids = set(_IDENT.findall(expression))
                if _SOURCE.search(expression) or ids & tainted:
                    tainted.add(owner)
            assignment = re.search(r"(?:\b(?:const|let|var|final|String|int|long)\s+)?([$A-Za-z_]\w*)\s*(?::=|=)\s*(.+)", clean)
            if assignment:
                target, expression = assignment.groups()
                ids = set(_IDENT.findall(expression))
                if _SOURCE.search(expression) or ids & tainted:
                    tainted.add(target)
                # Monotonic union approximates merging both sides of branches.
            ids = set(_IDENT.findall(clean))
            if re.search(r"\breturn\b", clean) and ids & tainted:
                returns.add(parameter_index)
            for category, (pattern, *_rest) in _SINKS.items():
                if pattern.search(clean) and ids & tainted:
                    sinks[category].add(parameter_index)
    return sinks, returns

def _finding(path: Path, line: int, category: str, via: str) -> Finding:
    _, cwe, title, remediation = _SINKS[category]
    number = cwe.split("-")[1]
    return Finding(
        category="source-analysis", title=title, severity="medium", confidence="low",
        url=path.resolve().as_uri(), kind="cross-function-source-to-sink-candidate",
        description="A bounded cross-function source review connected a request-input pattern to a sensitive operation.",
        impact="Lexical summaries do not prove runtime reachability, attacker control, exploitability, or absence of validation.",
        evidence=f"{path}:{line}: possible flow across helper boundary ({via}); source values omitted.",
        remediation=remediation, cwe_ids=[cwe],
        references=[f"https://cwe.mitre.org/data/definitions/{number}.html"],
        affected_component=f"{path.name}:{line}",
        remediation_steps=[remediation, "Review the full call path, scopes, branch conditions, and framework protections."],
        confidence_score=45,
    )

def scan_project_cross_function(root: str | Path, max_files: int = 1000) -> list[Finding]:
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        paths = [root_path]
    elif root_path.is_dir():
        paths = [p for p in root_path.rglob("*") if p.is_file()
                 and p.suffix.lower() in _LANGUAGES
                 and not any(part in SKIP_DIRS for part in p.parts)]
    else:
        return []
    functions = []
    for path in sorted(paths)[:max_files]:
        if path.suffix.lower() not in _LANGUAGES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        language = "js" if path.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"} else path.suffix.lower()[1:]
        for fn in _functions(lines, language):
            fn.update({"path": path, "language": language})
            fn["sink_params"], fn["return_params"] = _summarize(fn, language)
            functions.append(fn)

    by_name: dict[str, list[dict]] = {}
    for fn in functions:
        by_name.setdefault(fn["name"], []).append(fn)

    findings = []
    seen = set()
    for caller in functions:
        tainted: set[str] = set()
        for line_no, line in enumerate(caller["body"], caller["start"]):
            clean = _clean(line, caller["language"])
            if not clean:
                continue
            assignment = re.search(r"(?:\b(?:const|let|var|final|String|int|long)\s+)?([$A-Za-z_]\w*)\s*(?::=|=)\s*(.+)", clean)
            if assignment:
                target, expression = assignment.groups()
                ids = set(_IDENT.findall(expression))
                if _SOURCE.search(expression) or ids & tainted:
                    tainted.add(target)
                # Monotonic union approximates merging both sides of branches.
            for call in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]*)\)", clean):
                name, raw_args = call.groups()
                candidates = by_name.get(name, [])
                if len(candidates) != 1:
                    continue
                callee = candidates[0]
                args = [part.strip() for part in raw_args.split(",")]
                arg_ids = [set(_IDENT.findall(arg)) for arg in args]
                for category, indexes in callee["sink_params"].items():
                    if any(i < len(args) and (arg_ids[i] & tainted or _SOURCE.search(args[i])) for i in indexes):
                        key = (str(callee["path"]), callee["start"], _SINKS[category][1])
                        if key not in seen:
                            seen.add(key)
                            findings.append(_finding(callee["path"], callee["start"], category,
                                                     f"{caller['name']} -> {callee['name']}"))
                if callee["return_params"] and assignment:
                    if any(i < len(args) and (arg_ids[i] & tainted or _SOURCE.search(args[i]))
                           for i in callee["return_params"]):
                        tainted.add(assignment.group(1))
    return findings
