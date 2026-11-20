"""Conservative PHP interprocedural dataflow enrichment."""
from __future__ import annotations
import re
from pathlib import Path
from .analysis_graph import AnalysisGraph
from .source_audit import MAX_FILE_BYTES
_FUNCTION = re.compile(r"(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", re.I)
_IDENT = re.compile(r"\$?[A-Za-z_][A-Za-z0-9_]*")
_SINKS = {"query":"CWE-89","exec":"CWE-89","prepare":"CWE-89","mysqli_query":"CWE-89","pg_query":"CWE-89","shell_exec":"CWE-78","system":"CWE-78","passthru":"CWE-78","proc_open":"CWE-78","file_get_contents":"CWE-22","fopen":"CWE-22","readfile":"CWE-22","file_put_contents":"CWE-22","include":"CWE-98","require":"CWE-98","curl_init":"CWE-918"}
def _body_bounds(source: str, after: int) -> tuple[int,int] | None:
    opening=source.find("{",after)
    if opening<0:return None
    depth=0; quote=""; escaped=False
    for pos in range(opening,len(source)):
        char=source[pos]
        if quote:
            if escaped: escaped=False
            elif char=="\\": escaped=True
            elif char==quote: quote=""
            continue
        if char in {"'",'"'}: quote=char
        elif char=="{": depth+=1
        elif char=="}":
            depth-=1
            if depth==0:return opening+1,pos
    return opening+1,len(source)
def _graph_value(graph: AnalysisGraph,path: str,label: str,before: int)->str:
    normalized=label.lstrip("$")
    candidates=[n for n in graph.nodes.values() if n.path==path and n.label.lstrip("$")==normalized and n.line<=before and n.kind in {"source","transform","sanitizer"}]
    return max(candidates,key=lambda n:(n.line,n.column)).id if candidates else ""
def enrich_php_dataflow(path: str|Path,graph: AnalysisGraph,*,display_path: str|None=None)->int:
    file_path=Path(path)
    if file_path.suffix.lower()!=".php":return 0
    try:
        if file_path.stat().st_size>MAX_FILE_BYTES:return 0
        source=file_path.read_text(encoding="utf-8",errors="replace")
    except OSError:return 0
    relative=display_path or file_path.as_posix(); functions={}
    for match in _FUNCTION.finditer(source):
        params=[]
        for raw in match.group(2).split(","):
            found=re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)",raw)
            if found:params.append(found.group(1))
        bounds=_body_bounds(source,match.end())
        if bounds:functions[match.group(1)]={"params":params,"line":source.count("\n",0,match.start())+1,"start":bounds[0],"end":bounds[1]}
    function_nodes={}; added=0
    for name,info in sorted(functions.items()):
        params={}
        for param in info["params"]:
            params[param]=graph.add_node("transform",name+"::$"+param,path=relative,line=info["line"],language="php",confidence=0.58,metadata={"analysis":"interprocedural","role":"parameter","parser":"bounded-php-source-adapter"})
        return_id=graph.add_node("transform",name+"::return",path=relative,line=info["line"],language="php",confidence=0.54,metadata={"analysis":"interprocedural","role":"return","parser":"bounded-php-source-adapter"})
        function_nodes[name]=(return_id,params)
    for name,info in sorted(functions.items()):
        return_id,params=function_nodes[name]; body=source[info["start"]:info["end"]]; base_line=source.count("\n",0,info["start"])+1
        for offset,line in enumerate(body.splitlines()):
            line_no=base_line+offset; identifiers={item.lstrip("$") for item in _IDENT.findall(line)}
            for sink_name,cwe in _SINKS.items():
                if not re.search(rf"\b{re.escape(sink_name)}\s*\(",line,re.I):continue
                sink_id=graph.add_node("sink",sink_name,path=relative,line=line_no,language="php",cwe=cwe,confidence=0.52,metadata={"analysis":"interprocedural","parser":"bounded-php-source-adapter"})
                for param,param_id in params.items():
                    if param in identifiers and graph.add_edge(param_id,sink_id,"parameter-to-sink",0.55):added+=1
            if re.search(r"\breturn\b",line):
                for param,param_id in params.items():
                    if param in identifiers and graph.add_edge(param_id,return_id,"function-return",0.5):added+=1
    for caller,info in sorted(functions.items()):
        body=source[info["start"]:info["end"]]; base_line=source.count("\n",0,info["start"])+1
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)",body):
            callee=match.group(1)
            if callee not in function_nodes or callee==caller:continue
            _,callee_params=function_nodes[callee]; args=[item.strip() for item in match.group(2).split(",")]
            call_line=base_line+body.count("\n",0,match.start())
            for argument,param in zip(args,list(callee_params)):
                for identifier in _IDENT.findall(argument):
                    source_id=_graph_value(graph,relative,identifier,call_line)
                    if source_id and graph.add_edge(source_id,callee_params[param],"call-argument",0.5):added+=1
    return added
