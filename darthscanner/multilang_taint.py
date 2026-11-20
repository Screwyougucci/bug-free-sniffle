"""Bounded, line-oriented taint review for JavaScript/TypeScript, PHP, Java, and Go.

This is a conservative source-to-sink heuristic, not a language parser.
It does not execute code or send requests. Findings are review candidates only.
"""
from __future__ import annotations
from pathlib import Path
import re
from .checks import Finding
from .source_audit import MAX_FILE_BYTES

_LANGUAGES={".js":"js",".jsx":"js",".mjs":"js",".cjs":"js",".ts":"js",".tsx":"js",".php":"php",".java":"java",".go":"go"}
_ASSIGN=re.compile(r"(?:(?:const|let|var|final|String|var)\s+)?([$A-Za-z_][\w$]*)\s*[:=]\s*(.+)")
_IDENT=re.compile(r"[$A-Za-z_][\w$]*")
_SOURCES={
 "js":re.compile(r"(?:req(?:uest)?\.(?:query|body|params|headers|cookies)|ctx\.(?:query|request\.body)|location\.(?:search|hash)|URLSearchParams|\.searchParams\.get\s*\(|event\.data)",re.I),
 "php":re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",re.I),
 "java":re.compile(r"(?:getParameter|getHeader|getQueryString|getPart)\s*\(",re.I),
 "go":re.compile(r"(?:\.FormValue|\.PostForm\.Get|\.URL\.Query\(\)\.Get|\.Header\.Get)\s*\(",re.I),
}
_SINKS={
 "sql":(re.compile(r"(?:\.executeQuery|\.executeUpdate|\.execute|\.query|\.exec|\.raw|\.QueryContext|\.ExecContext)\s*\(",re.I),"CWE-89","Request-derived data reaches a database query operation","Use parameterized queries and bind untrusted values separately from fixed query text."),
 "ssrf":(re.compile(r"(?:fetch|axios\.(?:get|post|request)|https?\.request|http\.request|URL\(|new\s+URL\(|\.Do\s*\(|http\.Get|http\.Post)\s*\(",re.I),"CWE-918","Request-derived data reaches an outbound URL/request operation","Allowlist destination hosts and schemes; reject private, loopback, link-local, and reserved IP ranges after DNS resolution and on redirects."),
 "file":(re.compile(r"(?:\bopen\s*\(|readFile(?:Sync)?\s*\(|file_get_contents\s*\(|writeFile(?:Sync)?\s*\(|new\s+File\s*\(|Paths\.get\s*\(|os\.Open\s*\()",re.I),"CWE-22","Request-derived data reaches a filesystem operation","Resolve paths against a fixed base directory, verify canonical containment, and use an allowlist."),
 "command":(re.compile(r"(?:exec|execSync|spawn|system|shell_exec|passthru|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(",re.I),"CWE-78","Request-derived data reaches a process or shell operation","Avoid shell interpretation; use a fixed executable and structured argument arrays with strict allowlists."),
 "template":(re.compile(r"(?:render_template_string|Template\s*\(|createTemplate|Mustache\.render|\.ExecuteTemplate\s*\()",re.I),"CWE-94","Request-derived data reaches a dynamic template operation","Keep template source trusted and static; pass untrusted values only as escaped template data."),
 "deserialize":(re.compile(r"(?:unserialize|ObjectInputStream|readObject|pickle\.loads|yaml\.load|gob\.NewDecoder)\s*\(",re.I),"CWE-502","Request-derived data reaches a deserialization operation","Avoid native object deserialization for untrusted data; use a safe, schema-validated format."),
}

def _finding(path:Path,line:int,cwe:str,title:str,remediation:str)->Finding:
    number=cwe.split("-")[1]
    return Finding(category="source-analysis",title=title,severity="medium",confidence="low",
        url=path.resolve().as_uri(),kind="source-to-sink-candidate",
        description="A recognizable request-input pattern appears to flow through simple local assignments into a sensitive operation.",
        impact="This heuristic does not model full syntax, scopes, branches, function calls, sanitization, validation, or runtime reachability; exploitability is not established.",
        evidence=f"{path}:{line}: request-derived identifier appears near a {cwe} sink; source values and full lines are omitted.",
        remediation=remediation,cwe_ids=[cwe],references=[f"https://cwe.mitre.org/data/definitions/{number}.html"],
        affected_component=f"{path.name}:{line}",
        remediation_steps=[remediation,"Inspect the complete call path and framework-specific protections before confirming a vulnerability."],
        confidence_score=42)

def scan_multilang_taint(path:str|Path)->list[Finding]:
    file_path=Path(path); language=_LANGUAGES.get(file_path.suffix.lower())
    if language is None: return []
    try:
        if file_path.stat().st_size>MAX_FILE_BYTES: return []
        lines=file_path.read_text(encoding="utf-8",errors="replace").splitlines()
    except OSError: return []
    tainted=set(); findings=[]; seen=set(); source_pattern=_SOURCES[language]
    for number,line in enumerate(lines,1):
        stripped=line.lstrip()
        if not stripped or stripped.startswith(("//","#","*","/*")): continue
        assignment=_ASSIGN.search(line)
        if assignment:
            variable,expression=assignment.group(1),assignment.group(2)
            identifiers=set(_IDENT.findall(expression))
            if source_pattern.search(expression) or identifiers&tainted: tainted.add(variable)
            else: tainted.discard(variable)
        identifiers=set(_IDENT.findall(line))
        if not identifiers&tainted: continue
        for _,(pattern,cwe,title,remediation) in _SINKS.items():
            if pattern.search(line):
                key=(number,cwe)
                if key not in seen:
                    seen.add(key); findings.append(_finding(file_path,number,cwe,title,remediation))
    return findings
