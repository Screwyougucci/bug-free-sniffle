"""Bounded Java and Go interprocedural graph enrichment."""
from __future__ import annotations
import re
from pathlib import Path
from .analysis_graph import AnalysisGraph
from .source_audit import MAX_FILE_BYTES

_JAVA = re.compile(r"(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(?:<[^>{}]+>\s*)?[\w$<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*(?:throws\s+[\w$.,\s]+)?\{", re.M)
_GO = re.compile(r"func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^()]*)\)\s*(?:\([^{}]*\)|[\w.*\[\]<>]+)?\s*\{", re.M)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_SINKS = {"query":"CWE-89","executeQuery":"CWE-89","executeUpdate":"CWE-89","exec":"CWE-78","start":"CWE-78","ProcessBuilder":"CWE-78","Get":"CWE-918","Post":"CWE-918","Do":"CWE-918","ReadFile":"CWE-22","WriteFile":"CWE-22","Open":"CWE-22","get":"CWE-22","NewDecoder":"CWE-502","readObject":"CWE-502"}

def _end(source, opening):
    depth=0; quote=""; escaped=False; line_comment=False; block_comment=False; i=opening
    while i<len(source):
        ch=source[i]; nxt=source[i+1] if i+1<len(source) else ""
        if line_comment:
            if ch=="\n": line_comment=False
        elif block_comment:
            if ch=="*" and nxt=="/": block_comment=False; i+=1
        elif quote:
            if escaped: escaped=False
            elif ch=="\\": escaped=True
            elif ch==quote: quote=""
        elif ch=="/" and nxt=="/": line_comment=True; i+=1
        elif ch=="/" and nxt=="*": block_comment=True; i+=1
        elif ch in {"'",'"'}: quote=ch
        elif ch=="{": depth+=1
        elif ch=="}":
            depth-=1
            if depth==0:return i
        i+=1
    return len(source)

def _params(raw, language):
    result=[]
    for item in raw.split(","):
        item=item.strip()
        if not item: continue
        match=(re.search(r"([A-Za-z_$]\w*)\s*(?:\[\])?\s*$",item) if language=="java"
               else re.match(r"(?:\.\.\.)?([A-Za-z_]\w*)\s+",item) or re.match(r"([A-Za-z_]\w*)$",item))
        if match: result.append(match.group(1))
    return result

def enrich_java_go_dataflow(path, graph, *, display_path=None):
    file_path=Path(path); suffix=file_path.suffix.lower()
    language="java" if suffix==".java" else "go" if suffix==".go" else ""
    if not language:return 0
    try:
        if file_path.stat().st_size>MAX_FILE_BYTES:return 0
        source=file_path.read_text(encoding="utf-8",errors="replace")
    except OSError:return 0
    relative=display_path or file_path.as_posix(); pattern=_JAVA if language=="java" else _GO
    functions={}
    for match in pattern.finditer(source):
        opening=source.find("{",match.start(),match.end())
        if opening<0:continue
        functions[match.group(1)]={"params":_params(match.group(2),language),"line":source.count("\n",0,match.start())+1,"start":opening+1,"end":_end(source,opening)}
    indexed={}; added=0
    for name,info in sorted(functions.items()):
        pids={}
        for param in info["params"]:
            pids[param]=graph.add_node("transform",name+"::"+param,path=relative,line=info["line"],language=language,confidence=0.56,metadata={"analysis":"interprocedural","role":"parameter","parser":"bounded-java-go-source-adapter"})
        rid=graph.add_node("transform",name+"::return",path=relative,line=info["line"],language=language,confidence=0.52,metadata={"analysis":"interprocedural","role":"return","parser":"bounded-java-go-source-adapter"})
        indexed[name]=(rid,pids)
    for name,info in sorted(functions.items()):
        rid,pids=indexed[name]; body=source[info["start"]:info["end"]]; base=source.count("\n",0,info["start"])+1
        for offset,line in enumerate(body.splitlines()):
            line_no=base+offset; identifiers=set(_IDENT.findall(line))
            for sink,cwe in _SINKS.items():
                if not re.search(r"\b"+re.escape(sink)+r"\s*\(",line):continue
                sid=graph.add_node("sink",sink,path=relative,line=line_no,language=language,cwe=cwe,confidence=0.48,metadata={"analysis":"interprocedural","parser":"bounded-java-go-source-adapter"})
                for param,pid in pids.items():
                    if param in identifiers and graph.add_edge(pid,sid,"parameter-to-sink",0.5):added+=1
            if re.search(r"\breturn\b",line):
                for param,pid in pids.items():
                    if param in identifiers and graph.add_edge(pid,rid,"function-return",0.48):added+=1
    for caller,info in sorted(functions.items()):
        body=source[info["start"]:info["end"]]; base=source.count("\n",0,info["start"])+1
        for match in re.finditer(r"\b([A-Za-z_$]\w*)\s*\(([^()]*)\)",body):
            callee=match.group(1)
            if callee not in indexed or callee==caller:continue
            _,target_params=indexed[callee]; caller_params=indexed[caller][1]
            args=[x.strip() for x in match.group(2).split(",")]
            for arg,param in zip(args,list(target_params)):
                for ident in _IDENT.findall(arg):
                    source_id=caller_params.get(ident,"")
                    if not source_id:
                        line_no=base+body.count("\n",0,match.start())
                        candidates=[n for n in graph.nodes.values() if n.path==relative and n.label==ident and n.line<=line_no and n.kind in {"source","transform","sanitizer"}]
                        if candidates:source_id=max(candidates,key=lambda n:n.line).id
                    if source_id and graph.add_edge(source_id,target_params[param],"call-argument",0.48):added+=1
    return added
