"""Bounded cross-function and branch-aware source review for non-Python projects.

This is deliberately a conservative lexical analysis, not a compiler frontend.
It never executes source or sends network traffic. Results are review leads.
"""
from __future__ import annotations

from pathlib import Path
import re

from .checks import Finding
from .source_audit import MAX_FILE_BYTES, SKIP_DIRS

_LANGUAGES = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".java", ".go",
}
_IDENT = re.compile(r"[$A-Za-z_][\w$]*")
_SOURCE = re.compile(
    r"(?:req(?:uest)?\.(?:query|body|params|headers|cookies)|ctx\.(?:query|request\.body)|"
    r"location\.(?:search|hash)|URLSearchParams|event\.data|\$_(?:GET|POST|REQUEST|COOKIE|FILES)|"
    r"getParameter\s*\(|getHeader\s*\(|getQueryString\s*\(|getPart\s*\(|"
    r"\.FormValue\s*\(|\.PostForm\.Get\s*\(|\.URL\.Query\(\)\.Get\s*\()", re.I
)
_SINKS = {
    "sql": (re.compile(r"(?:\.executeQuery|\.executeUpdate|\.execute|\.query|\.exec|\.raw|\.QueryContext|\.ExecContext)\s*\(", re.I), "CWE-89", "Request-derived data may reach a database query through a helper", "Use parameterized queries and bind untrusted values separately from query text."),
    "ssrf": (re.compile(r"(?:fetch|axios\.(?:get|post|request)|https?\.request|http\.request|\.Do\s*\(|http\.(?:Get|Post)|curl_exec)\s*\(", re.I), "CWE-918", "Request-derived data may reach an outbound request through a helper", "Allowlist destination hosts and schemes; validate resolved addresses and redirects."),
    "file": (re.compile(r"(?:\bopen\s*\(|readFile(?:Sync)?\s*\(|file_get_contents\s*\(|writeFile(?:Sync)?\s*\(|new\s+File\s*\(|Paths\.get\s*\(|os\.Open\s*\()", re.I), "CWE-22", "Request-derived data may reach a filesystem operation through a helper", "Canonicalize paths and verify containment within an allowed base directory."),
    "command": (re.compile(r"(?:exec(?:Sync)?|spawn|system|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(", re.I), "CWE-78", "Request-derived data may reach a process operation through a helper", "Avoid shell interpretation; use fixed executables and structured arguments."),
    "template": (re.compile(r"(?:render_template_string|new\s+Template|Template\s*\(|createTemplate|Mustache\.render|\.ExecuteTemplate\s*\()", re.I), "CWE-94", "Request-derived data may reach a dynamic template operation through a helper", "Keep template source trusted and pass untrusted values only as escaped data."),
    "deserialize": (re.compile(r"(?:unserialize|ObjectInputStream|readObject|yaml\.load|gob\.NewDecoder)\s*\(", re.I), "CWE-502", "Request-derived data may reach an unsafe deserializer through a helper", "Use schema-validated data formats and avoid native object deserialization of untrusted input."),
}

# Function declarations used for bounded lexical summaries. Braces delimit
# bodies in these languages; unsupported syntax is skipped rather than guessed.
_DECLARATIONS = {
    "js": re.compile(r"\bfunction\s*([\w$]+)?\s*\(([^)]*)\)\s*\{|\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{"),
    "php": re.compile(r"\bfunction\s+&?([\w$]+)\s*\(([^)]*)\)\s*\{", re.I),
    "java": re.compile(r"\b(?:public|protected|private|static|final|synchronized|\s)+[\w<>?,.\[\]]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+)?\{"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:\([^)]*\)|[\w*\[\].]+)?\s*\{"),
}

def _strip_comments(line: str, language: str) -> str:
    # Keep this intentionally simple: remove obvious full-line comments only.
    stripped = line.lstrip()
    if stripped.startswith(("//", "/*", "*")):
        return ""
    if language == "php" and stripped.startswith("#"):
        return ""
    return line

def _params(raw: str) -> list[str]:
    result = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        # Last identifier handles common typed Java/Go/PHP and defaulted JS params.
        names = _IDENT.findall(part.split("=")[0])
        if names:
            result.append(names[-1])
    return result

def _functions(lines: list[str], language: str) -> list[dict]:
    pattern = _DECLARATIONS[language]
    found = []
    i = 0
    while i < len(lines):
        match = pattern.search(lines[i])
        if not match:
            i += 1
            continue
        groups = match.groups()
        if language == "js":
            name = groups[0] or groups[2] or "<anonymous>"
            raw_params = groups[1] if groups[1] is not None else (groups[3] or "")
        else:
            name, raw_params = groups[0], groups[1]
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        body = [lines[i]]
        i += 1
        while i < len(lines) and depth > 0 and len(body) < 3000:
            body.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        if depth <= 0:
            found.append({"name": name, "params": _params(raw_params), "start": start + 1, "body": body})
        # Avoid interpreting nested declarations twice; outer body is analyzed as one unit.
    return found

def _body_summary(function: dict, language: str) -> tuple[set[int], set[int]]:
    params = function["params"]
    sink_params: set[int] = set()
    return_params: set[int] = set()
    tainted = set(params)
    for line in function["body"]:
        clean = _strip_comments(line, language)
        if not clean:
            continue
        assignment = re.search(r"(?:\b(?:const|let|var|final|String|int|long|var)\s+)?([$A-Za-z_]\w*)\s*(?::=|=)\s*(.+)", clean)
        if assignment:
            target, expression = assignment.groups()
            ids = set(_IDENT.findall(expression))
            if _SOURCE.search(expression) or ids & tainted:
                tainted.add(target)
            else:
                tainted.discard(target)
        ids = set(_IDENT.findall(clean))
        if "return" in ids and ids & tainted:
            return_params.update(i for i, param in enumerate(params) if param in ids)
        for category, (pattern, *_rest) in _SINKS.items():
            if pattern.search(clean) and ids & tainted:
                sink_params.update(i for i, param in enumerate(params) if param in ids)
    return sink_params, return_params

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
        remediation_steps=[remediation, "Review the full call path, language scopes, branch conditions, and framework protections."],
        confidence_score=45,
    )

def scan_project_cross_function(root: str | Path, max_files: int = 1000) -> list[Finding]:
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        paths = [root_path]
        root_path = root_path.parent
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
            fn["sink_params"], fn["return_params"] = _body_summary(fn, language)
            functions.append(fn)

    by_name: dict[str, list[dict]] = {}
    for fn in functions:
        by_name.setdefault(fn["name"], []).append(fn)

    findings = []
    seen = set()
    for caller in functions:
        caller_taint: set[str] = set()
        for line_no, line in enumerate(caller["body"], caller["start"]):
            clean = _strip_comments(line, caller["language"])
            if not clean:
                continue
            assignment = re.search(r"(?:\b(?:const|let|var|final|String|int|long|var)\s+)?([$A-Za-z_]\w*)\s*(?::=|=)\s*(.+)", clean)
            if assignment:
                target, expression = assignment.groups()
                identifiers = set(_IDENT.findall(expression))
                if _SOURCE.search(expression) or identifiers & caller_taint:
                    caller_taint.add(target)
                else:
                    caller_taint.discard(target)
            for call in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(([^()]*)\)", clean):
                name, args = call.groups()
                candidates = by_name.get(name, [])
                # Only resolve unique names, preventing ambiguous cross-package guesses.
                if len(candidates) != 1:
                    continue
                callee = candidates[0]
                arg_values = [part.strip() for part in args.split(",")]
                identifiers = [set(_IDENT.findall(arg)) for arg in arg_values]
                for index in callee["sink_params"]:
                    if index < len(identifiers) and (identifiers[index] & caller_taint or _SOURCE.search(arg_values[index])):
                        category = next((key for key, (_, cwe, *_rest) in _SINKS.items()
                                         if any(cwe == item for item in [ _SINKS[key][1] ])), None)
                        # The callee summary records parameter indexes per sink category below.
                        for category, (pattern, cwe, *_rest) in _SINKS.items():
                            if pattern.search("\n".join(callee["body"])):
                                key = (str(callee["path"]), callee["start"], cwe)
                                if key not in seen:
                                    seen.add(key)
                                    findings.append(_finding(callee["path"], callee["start"], category,
                                                             f"{caller['name']} -> {callee['name']}"))
                # A returned parameter carries taint into the caller's assignment target.
                if callee["return_params"] and assignment:
                    if any(i < len(identifiers) and (identifiers[i] & caller_taint or _SOURCE.search(arg_values[i]))
                           for i in callee["return_params"]):
                        caller_taint.add(assignment.group(1))
    return findings
