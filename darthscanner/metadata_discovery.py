"""Passive API and well-known resource inventory with strict same-origin limits."""
from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit
from .scope import Scope
from .api_schema_audit import inspect_openapi_schema

_CANDIDATES=("/robots.txt","/sitemap.xml","/.well-known/security.txt","/security.txt","/openapi.json","/swagger.json","/api-docs")

def _origin(url):
    p=urlsplit(url)
    return p.scheme.lower(),(p.hostname or "").lower(),p.port or (443 if p.scheme=="https" else 80)

def _same_origin(url,origin,scope):
    try:
        scope.validate_url(url)
        return _origin(url)==origin
    except ValueError:
        return False

def discover_api_resources(base_url,scope,client,*,max_resources=7):
    scope.validate_url(base_url)
    if not 1<=max_resources<=len(_CANDIDATES):
        raise ValueError("max_resources must be between 1 and 7.")
    origin=_origin(base_url)
    root=f"{origin[0]}://{origin[1]}"+(f":{origin[2]}" if origin[2] not in (80,443) else "")+"/"
    resources=[]; endpoints={}; sitemap_urls=set(); robots_sitemaps=set(); schema_findings=[]
    for path in _CANDIDATES[:max_resources]:
        if client.requests_made>=client.max_requests: break
        url=urljoin(root,path); response=client.get(url)
        ctype=response.headers.get("content-type","").lower()
        record={"url":response.url,"status":response.status,"response_bytes":len(response.body),"resource_type":"metadata"}
        resources.append(record)
        if response.status is None or not 200<=response.status<300 or not response.body: continue
        text=response.text[:1_000_000]; resource_path=urlsplit(url).path.lower()
        if resource_path.endswith("robots.txt"):
            for line in text.splitlines():
                m=re.match(r"\s*sitemap\s*:\s*(\S+)",line,re.I)
                if m:
                    candidate=urljoin(url,m.group(1))
                    if _same_origin(candidate,origin,scope): robots_sitemaps.add(candidate)
        elif resource_path.endswith("sitemap.xml"):
            try:
                xml_root=ET.fromstring(text)
                for node in xml_root.iter():
                    if node.tag.rsplit("}",1)[-1].lower()=="loc" and node.text:
                        candidate=urljoin(url,node.text.strip())
                        if _same_origin(candidate,origin,scope): sitemap_urls.add(candidate)
            except ET.ParseError: record["parse_note"]="Invalid sitemap XML; no URLs extracted."
        elif resource_path.endswith(("openapi.json","swagger.json","/api-docs")) or "json" in ctype:
            try: spec=json.loads(text)
            except json.JSONDecodeError: continue
            if not isinstance(spec,dict): continue
            schema_findings.extend(item.to_dict() for item in inspect_openapi_schema(spec,response.url))
            paths=spec.get("paths",{})
            if isinstance(paths,dict):
                for api_path,ops in paths.items():
                    if not isinstance(api_path,str) or not api_path.startswith("/"): continue
                    methods=sorted(k.upper() for k,v in ops.items() if k.lower() in {"get","post","put","patch","delete","options","head"} and isinstance(v,dict)) if isinstance(ops,dict) else []
                    endpoints[api_path]={"path":api_path,"methods_documented":methods}
                info=spec.get("info") if isinstance(spec.get("info"),dict) else {}
                record["api_title"]=info.get("title"); record["api_version"]=info.get("version")
                record["api_paths_found"]=len(paths) if isinstance(paths,dict) else 0
        elif resource_path.endswith("security.txt"):
            fields={}
            for line in text.splitlines():
                if ":" not in line or line.lstrip().startswith("#"): continue
                key,value=line.split(":",1); key=key.lower().strip()
                if key in {"contact","expires","policy","preferred-languages","canonical"}: fields.setdefault(key,[]).append(value.strip()[:300])
            record["security_txt_fields"]=sorted(fields); record["security_txt_present"]=True
    return {"resources":resources,"api_endpoints":sorted(endpoints.values(),key=lambda x:x["path"]),
            "sitemap_urls_discovered":sorted(sitemap_urls),"robots_sitemaps_discovered":sorted(robots_sitemaps),"schema_findings":schema_findings,
            "note":"Discovered URLs and API methods are inventory only; no API operations were invoked."}
