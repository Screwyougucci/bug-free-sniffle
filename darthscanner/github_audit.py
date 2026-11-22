"""Read-only GitHub repository discovery and static source review."""
from __future__ import annotations
import base64, json, os, re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from .checks import Finding

API = "https://api.github.com"
MAX_TREE_BYTES = 12_000_000
MAX_FILE_BYTES = 512_000
MAX_TOTAL_BYTES = 10_000_000
PUBLIC_FILE_LIMIT = 40
AUTH_FILE_LIMIT = 180
SKIP_PARTS = {".git", ".github", ".venv", "venv", "node_modules", "vendor", "dist", "build", "coverage", "__pycache__", "target", "Pods"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rs", ".php", ".rb", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala", ".vue", ".svelte", ".html", ".yml", ".yaml", ".toml", ".json", ".xml", ".properties", ".sh", ".ps1", ".sql", ".tf"}
MANIFEST_NAMES = {"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle", "go.mod", "Cargo.toml", "Gemfile.lock", "composer.lock", "packages.config"}
SKIP_NAMES = {"min.js", "min.css", "bundle.js", "vendor.js"}
REPO_RE = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)
RULES = [
("Possible hard-coded secret","high","CWE-798",65,re.compile(r'''(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b\s*[:=]\s*["'][^"']{8,}["']'''),"Move the credential to a secret manager or environment variable, remove it from repository history, and rotate it."),
("AWS access key identifier","high","CWE-798",75,re.compile(r"\bAKIA[0-9A-Z]{16}\b"),"Treat this as exposed until verified otherwise; rotate the key and inspect repository history."),
("GitHub personal access token pattern","critical","CWE-798",85,re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),"Revoke and rotate the token immediately if genuine; remove it from repository history."),
("Dynamic code execution","high","CWE-95",60,re.compile(r"\b(?:eval|exec)\s*\("),"Avoid evaluating untrusted data as code; use parsing and explicit dispatch."),
("Unsafe deserialization","high","CWE-502",60,re.compile(r"\b(?:pickle\.loads?|yaml\.unsafe_load|marshal\.loads?)\s*\("),"Do not deserialize attacker-controlled data; use a safe, schema-validated format."),
("Shell command execution requires input-flow review","high","CWE-78",55,re.compile(r"\b(?:os\.system|child_process\.exec|Runtime\.getRuntime\(\)\.exec|shell=True)\b"),"Prefer argument-array process APIs with shell interpretation disabled; validate every argument."),
("Potential SQL string construction","medium","CWE-89",40,re.compile(r"(?i)(?:execute|query)\s*\(\s*(?:f['\"]|['\"][^'\"]{0,160}\s*\+\s*)"),"Use parameterized queries and pass values separately from SQL text."),
("TLS certificate verification disabled","high","CWE-295",85,re.compile(r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"),"Enable certificate and hostname verification; configure a trusted CA bundle if needed."),
("Potential DOM injection sink","medium","CWE-79",40,re.compile(r"\b(?:innerHTML|outerHTML)\s*="),"Use textContent or safe DOM construction; sanitize and context-encode untrusted HTML."),
("Potential unsafe HTML rendering","medium","CWE-79",35,re.compile(r"\bdangerouslySetInnerHTML\b"),"Sanitize untrusted HTML with a maintained sanitizer and review the data source."),
("Potential permissive CORS policy","medium","CWE-942",35,re.compile(r"(?i)(?:Access-Control-Allow-Origin|allow_origins)\s*[:=]\s*['\"]?\*"),"Restrict allowed origins to an explicit allowlist; do not combine wildcard origins with credentials."),
("Potential path traversal sink","medium","CWE-22",30,re.compile(r"(?i)(?:send_file|sendFile|readFile|open)\s*\([^)]*(?:request\.|req\.|params\[|query\[)"),"Resolve paths against a fixed base directory and reject traversal after canonicalization."),
]
SECRET_LINE = re.compile(r'''(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|private[_-]?key)\b\s*[:=]\s*)(["'])[^"']{8,}(["'])''')

def parse_repository_url(value: str) -> tuple[str,str]:
    raw=value.strip()
    if not raw: raise ValueError("Enter a GitHub repository URL.")
    if "://" not in raw: raw="https://"+raw
    parts=urlsplit(raw)
    if parts.scheme!="https" or (parts.hostname or "").lower() not in {"github.com","www.github.com"}:
        raise ValueError("Only https://github.com/owner/repository URLs are supported.")
    seg=[x for x in parts.path.split("/") if x]
    if len(seg)<2: raise ValueError("The URL must identify a repository.")
    owner,repo=seg[0],seg[1]
    if repo.endswith(".git"): repo=repo[:-4]
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",repo):
        raise ValueError("The GitHub owner or repository name is invalid.")
    return owner,repo

def discover_github_repositories(text: str, limit: int=10) -> list[str]:
    found=[]; seen=set()
    for m in REPO_RE.finditer(text[:2_000_000]):
        owner,repo=m.group(1),m.group(2)
        if repo.lower() in {"issues","pull","pulls","discussions","settings","actions","wiki","tree","blob"}: continue
        value=f"https://github.com/{owner}/{repo}"
        if value.lower() not in seen: seen.add(value.lower()); found.append(value)
        if len(found)>=limit: break
    return found

def _request(url: str, token: str|None, limit: int) -> bytes:
    headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"DarthScanner-ReadOnly-Audit"}
    if token: headers["Authorization"]="Bearer "+token
    try:
        with urlopen(Request(url,headers=headers,method="GET"),timeout=15) as response: data=response.read(limit+1)
    except HTTPError as exc:
        if exc.code==404: raise ValueError("GitHub repository or source file was not found, or it is private and no valid GITHUB_TOKEN is configured.") from exc
        if exc.code==403: raise ValueError("GitHub rate limit or access restriction. Configure a read-only GITHUB_TOKEN or retry later.") from exc
        raise ValueError(f"GitHub returned HTTP {exc.code}.") from exc
    except (URLError,TimeoutError,OSError) as exc: raise ValueError(f"Could not reach GitHub: {exc}") from exc
    if len(data)>limit: raise ValueError("GitHub response exceeded the configured size limit.")
    return data

def _safe_excerpt(line: str) -> str:
    value=SECRET_LINE.sub(r"\1\2[REDACTED]\3",line.strip())
    value=re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}",r"\1[REDACTED]",value)
    return value[:360]

def audit_github_repository(repository_url: str, max_files: int|None=None) -> tuple[list[Finding],dict]:
    owner,repo=parse_repository_url(repository_url)
    token=os.environ.get("GITHUB_TOKEN","").strip() or None
    ceiling=AUTH_FILE_LIMIT if token else PUBLIC_FILE_LIMIT
    file_limit=max_files if max_files is not None else ceiling
    if not 1<=file_limit<=ceiling: raise ValueError(f"max_files must be between 1 and {ceiling} for this GitHub access mode.")
    base=f"{API}/repos/{quote(owner)}/{quote(repo)}"
    metadata=json.loads(_request(base,token,1_000_000))
    branch=metadata.get("default_branch") or "main"
    tree=json.loads(_request(base+"/git/trees/"+quote(branch,safe="")+"?recursive=1",token,MAX_TREE_BYTES))
    candidates=[]
    for entry in tree.get("tree") or []:
        if entry.get("type")!="blob": continue
        path=str(entry.get("path") or ""); parts=path.split("/")
        if {p.lower() for p in parts}&SKIP_PARTS: continue
        name=parts[-1].lower() if parts else ""
        suffix="."+name.rsplit(".",1)[-1] if "." in name else ""
        if suffix in SOURCE_SUFFIXES or name in MANIFEST_NAMES or name=="dockerfile": candidates.append(entry)
    candidates.sort(key=lambda x:(0 if str(x.get("path","")).split("/")[-1].lower() in MANIFEST_NAMES else 1,str(x.get("path",""))))
    findings=[]; reviewed=skipped=total=0; manifests=[]
    for entry in candidates:
        if reviewed>=file_limit: skipped+=1; continue
        size=int(entry.get("size") or 0)
        if size>MAX_FILE_BYTES or total+size>MAX_TOTAL_BYTES: skipped+=1; continue
        path=str(entry.get("path") or ""); sha=str(entry.get("sha") or "")
        if not sha: skipped+=1; continue
        blob=json.loads(_request(base+"/git/blobs/"+quote(sha),token,MAX_FILE_BYTES*2))
        if blob.get("encoding")!="base64": skipped+=1; continue
        try: raw=base64.b64decode(blob.get("content",""),validate=False); source=raw.decode("utf-8")
        except (ValueError,UnicodeDecodeError): skipped+=1; continue
        if len(raw)>MAX_FILE_BYTES: skipped+=1; continue
        total+=len(raw); reviewed+=1
        name=path.rsplit("/",1)[-1].lower()
        if name in MANIFEST_NAMES: manifests.append({"path":path,"bytes":len(raw),"note":"Dependency manifest detected; this pass does not infer complete CVE coverage."})
        source_url=f"https://github.com/{owner}/{repo}/blob/{quote(branch,safe='')}/{quote(path,safe='/')}"
        for line_no,line in enumerate(source.splitlines(),1):
            for title,severity,cwe,score,pattern,fix in RULES:
                if not pattern.search(line): continue
                excerpt=_safe_excerpt(line)
                findings.append(Finding(category="github-source-review",title=title,severity=severity,
                    confidence="medium" if score>=55 else "low",url=source_url,evidence=f"{path}:{line_no}: {excerpt}",
                    remediation=fix,kind="github-static-analysis-lead",
                    description="A static source pattern matched. Data flow, framework behavior, reachability, and runtime configuration require human review.",
                    impact="Potential impact depends on whether untrusted input reaches this code path and whether compensating controls exist.",
                    cwe_ids=[cwe],references=[f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"],
                    affected_component=f"{owner}/{repo}:{path}:{line_no}",
                    remediation_steps=[fix,"Review callers, input sources, and runtime configuration before classifying this as exploitable."],
                    confidence_score=score,source_excerpt=excerpt,source_line=line_no,source_url=source_url,
                    source_kind="github-repository-source",
                    evidence_details={"repository":f"{owner}/{repo}","branch":branch,"file_path":path,"line":line_no,"source_url":source_url,"response_body_saved":False}))
    summary={"repository":f"{owner}/{repo}","repository_url":f"https://github.com/{owner}/{repo}","default_branch":branch,
        "visibility":metadata.get("visibility","unknown"),"files_reviewed":reviewed,"files_skipped":skipped+max(0,len(candidates)-file_limit),
        "bytes_reviewed":total,"tree_truncated":bool(tree.get("truncated")),"dependency_manifests":manifests,
        "access_mode":"authenticated read-only" if token else "public unauthenticated read-only",
        "limitations":["Static pattern matches are leads, not proof of exploitability.","No repository code was executed and no files were modified.","Dependency manifests are inventoried; this pass does not claim complete CVE coverage.","Private repositories require a user-supplied read-only GITHUB_TOKEN in the local environment."]}
    return findings,summary
