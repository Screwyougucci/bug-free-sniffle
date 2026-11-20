"""JSON, HTML dashboard, and CSV report generation."""
from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
import json
from pathlib import Path

from . import __version__


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


def build_report(*, target: str, requests_made: int, pages: list[dict],
                 findings: list, fuzz_observations: list[dict] | None = None,
                 software_components: list[dict] | None = None,
                 exposure_paths_checked: int = 0,
                 tls_probes: int = 0,
                 source_files_reviewed: int = 0,
                 source_files_skipped: int = 0,
                 api_inventory: dict | None = None) -> dict:
    """Normalize, deduplicate, sort, and summarize scan results."""
    unique = {}
    for item in findings:
        existing = unique.get(item.finding_id)
        if existing is None or item.confidence_score > existing.confidence_score:
            unique[item.finding_id] = item
    normalized = sorted(
        unique.values(),
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 6),
            -(item.cvss_score or 0.0),
            -item.confidence_score,
            item.category,
            item.url,
            item.title,
        ),
    )
    severity_counts = Counter(item.severity for item in normalized)
    category_counts = Counter(item.category for item in normalized)
    kind_counts = Counter(item.kind for item in normalized)
    page_statuses = Counter(
        "error" if page.get("status") is None else
        "2xx" if 200 <= page["status"] < 300 else
        "3xx" if 300 <= page["status"] < 400 else
        "4xx" if 400 <= page["status"] < 500 else
        "5xx" if page["status"] >= 500 else "other"
        for page in pages
    )
    cve_findings = [item for item in normalized if item.category == "cve"]
    return {
        "tool": "Darth Scanner",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "coverage": {
            "requests_made": requests_made,
            "pages_reviewed": len(pages),
            "page_statuses": dict(page_statuses),
            "software_components_identified": len(software_components or []),
            "api_endpoints_discovered": len((api_inventory or {}).get("api_endpoints", [])),
            "metadata_resources_checked": len((api_inventory or {}).get("resources", [])),
            "exposure_paths_checked": exposure_paths_checked,
            "tls_probes": tls_probes,
            "source_files_reviewed": source_files_reviewed,
            "source_files_skipped": source_files_skipped,
            "findings_total": len(normalized),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "kind_counts": dict(kind_counts),
            "cve_matches": len(cve_findings),
            "fuzz_anomalies": sum("no notable" not in item.get("note", "") for item in (fuzz_observations or [])),
        },
        "software_components": software_components or [],
        "api_inventory": api_inventory or {"resources": [], "api_endpoints": [], "sitemap_urls_discovered": [], "robots_sitemaps_discovered": []},
        "pages": pages,
        "findings": [item.to_dict() for item in normalized],
        "fuzz_observations": fuzz_observations or [],
        "disclaimer": (
            "CVE matches are candidates based on available CPE/version data and must be "
            "validated against vendor advisories, platform conditions, and backported fixes. "
            "HEAD exposure checks confirm only response metadata, not file contents. "
            "Fuzz anomalies are triage signals, not proof of exploitability."
        ),
    }


def write_report(path: str, *, target: str, requests_made: int,
                 pages: list[dict], findings: list,
                 fuzz_observations: list[dict] | None = None,
                 software_components: list[dict] | None = None,
                 exposure_paths_checked: int = 0,
                 tls_probes: int = 0,
                 source_files_reviewed: int = 0,
                 source_files_skipped: int = 0,
                 api_inventory: dict | None = None) -> dict:
    payload = build_report(
        target=target,
        requests_made=requests_made,
        pages=pages,
        findings=findings,
        fuzz_observations=fuzz_observations,
        software_components=software_components,
        exposure_paths_checked=exposure_paths_checked,
        tls_probes=tls_probes,
        source_files_reviewed=source_files_reviewed,
        source_files_skipped=source_files_skipped,
        api_inventory=api_inventory,
    )
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload


def write_csv_report(path: str, report: dict) -> None:
    """Export one row per finding; no response bodies or secrets are exported."""
    columns = [
        "finding_id", "severity", "cvss_score", "cvss_version", "category", "kind",
        "confidence", "confidence_score", "title", "url", "affected_component",
        "cve_ids", "cwe_ids", "description", "impact", "evidence", "remediation",
        "remediation_steps", "references",
    ]
    with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in report.get("findings", []):
            row = dict(item)
            for key in ("cve_ids", "cwe_ids", "remediation_steps", "references"):
                row[key] = "; ".join(str(value) for value in row.get(key, []))
            writer.writerow(row)


def write_html_report(path: str, report: dict) -> None:
    """Write a self-contained local dashboard with client-side filters."""
    data = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
    data = data.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Darth Scanner — Security Assessment</title>
<style>
:root{color-scheme:dark;--bg:#0b0e14;--panel:#131925;--line:#263244;--muted:#9aa8bb;--text:#edf3fc;--red:#ed5361;--orange:#f2a64a;--yellow:#e8cf61;--blue:#69a8ff;--green:#69c795}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 12% 0,#182336 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1220px;margin:auto;padding:34px 22px 70px}.top{display:flex;gap:18px;align-items:center;justify-content:space-between;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:20px}
.brand{display:flex;gap:12px;align-items:center}.mark{width:42px;height:42px;border:1px solid #7b2530;border-radius:12px;display:grid;place-items:center;color:#ff6472;font-weight:900;font-size:20px;background:#21151d}.eyebrow{color:#ff7280;text-transform:uppercase;font-size:11px;letter-spacing:.17em;font-weight:800}.muted{color:var(--muted)}h1{font-size:25px;margin:2px 0}h2{font-size:17px;margin:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:22px 0}.tile,.filters,.finding,.section{background:linear-gradient(145deg,#151e2b,#111722);border:1px solid var(--line);border-radius:14px}.tile{padding:15px}.tile small{color:var(--muted);display:block}.num{font-size:25px;font-weight:800;margin-top:4px}
.filters{padding:15px;margin:20px 0;display:grid;grid-template-columns:2fr repeat(3,minmax(130px,1fr));gap:10px;align-items:end}.control label{display:block;font-size:11px;color:var(--muted);margin:0 0 5px}.control input,.control select{width:100%;padding:10px;border-radius:8px;border:1px solid #344258;background:#0d131d;color:var(--text)}
.results-head{display:flex;justify-content:space-between;align-items:center;margin:22px 0 10px;gap:10px}.finding{padding:17px;margin:10px 0}.fhead{display:flex;gap:10px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}.ftitle{font-size:16px;font-weight:750;max-width:850px}.badges{display:flex;flex-wrap:wrap;gap:6px}.badge{font-size:11px;border:1px solid var(--line);padding:3px 8px;border-radius:999px;color:#c7d3e3;background:#101722}.critical{color:#ff7a83;border-color:#79343b}.high{color:#ffb278;border-color:#74462c}.medium{color:#f4da78;border-color:#655a2d}.low{color:#8cbcff;border-color:#34547c}.info{color:#a8c2da}.field{margin-top:13px}.field b{display:block;color:#8fa2bc;font-size:10px;letter-spacing:.11em;text-transform:uppercase;margin-bottom:3px}.field p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.refs{overflow-wrap:anywhere;color:#9ab9de}.empty{padding:30px;text-align:center;border:1px dashed #37465b;border-radius:12px;color:var(--muted)}.footer{color:var(--muted);font-size:12px;margin-top:30px;border-top:1px solid var(--line);padding-top:15px}
@media(max-width:760px){.filters{grid-template-columns:1fr 1fr}.filters .wide{grid-column:1/-1}}@media(max-width:440px){.filters{grid-template-columns:1fr}}
</style>
</head>
<body><main>
<header class="top"><div class="brand"><div class="mark">D</div><div><div class="eyebrow">Darth Scanner</div><h1>Security Assessment</h1><div class="muted" id="target"></div></div></div><div class="muted" id="generated"></div></header>
<section class="grid" id="summary"></section>
<section class="filters">
 <div class="control wide"><label for="search">Search findings</label><input id="search" type="search" placeholder="Title, path, evidence, CVE, component…"></div>
 <div class="control"><label for="severity">Severity</label><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></div>
 <div class="control"><label for="cwe">CWE contains</label><input id="cwe" placeholder="e.g. CWE-79"></div>
 <div class="control"><label for="cvss">Minimum CVSS</label><input id="cvss" type="number" min="0" max="10" step=".1" placeholder="Any"></div>
</section>
<div class="results-head"><h2>Findings</h2><span class="muted" id="result-count"></span></div>
<section id="findings"></section>
<section class="section" style="padding:16px;margin-top:22px"><h2>Fuzz observations</h2><div id="fuzz" class="muted" style="margin-top:10px"></div></section>
<section class="section" style="padding:16px;margin-top:22px"><h2>Identified software</h2><div id="software" class="muted" style="margin-top:10px"></div></section>
<div class="footer" id="disclaimer"></div>
</main>
<script type="application/json" id="report-data">""" + data + """</script>
<script>
"use strict";
const report=JSON.parse(document.getElementById("report-data").textContent);
const $=id=>document.getElementById(id);
const findings=Array.isArray(report.findings)?report.findings:[];
$("target").textContent=report.target||"";
$("generated").textContent=report.generated_at||"";
$("disclaimer").textContent=report.disclaimer||"";
const coverage=report.coverage||{};
const tiles=[
 ["Pages reviewed",coverage.pages_reviewed??0],
 ["Requests made",coverage.requests_made??0],
 ["Findings",coverage.findings_total??findings.length],
 ["CVE candidates",coverage.cve_matches??0],
 ["Exposed paths checked",coverage.exposure_paths_checked??0],
 ["Software identified",coverage.software_components_identified??0],["API paths discovered",coverage.api_endpoints_discovered??0],["Metadata resources",coverage.metadata_resources_checked??0],["Source files reviewed",coverage.source_files_reviewed??0]
];
for(const [label,value] of tiles){const card=document.createElement("div");card.className="tile";const small=document.createElement("small");small.textContent=label;const number=document.createElement("div");number.className="num";number.textContent=value;card.append(small,number);$("summary").append(card)}
function addField(parent,label,value,cls){if(value===undefined||value===null||value==="")return;const wrap=document.createElement("div");wrap.className="field";const name=document.createElement("b");name.textContent=label;const text=document.createElement("p");if(Array.isArray(value))text.textContent=value.join(", ");else text.textContent=String(value);if(cls)text.className=cls;wrap.append(name,text);parent.append(wrap)}
function render(){const severity=$("severity").value;const needle=$("search").value.trim().toLowerCase();const cwe=$("cwe").value.trim().toLowerCase();const min=$("cvss").value===""?null:Number($("cvss").value);const filtered=findings.filter(f=>{if(severity&&f.severity!==severity)return false;if(cwe&&!(f.cwe_ids||[]).some(x=>x.toLowerCase().includes(cwe)))return false;if(min!==null&&(f.cvss_score===null||f.cvss_score===undefined||Number(f.cvss_score)<min))return false;const blob=[f.title,f.url,f.evidence,f.description,f.impact,f.affected_component,(f.cve_ids||[]).join(" "),(f.cwe_ids||[]).join(" ")].join(" ").toLowerCase();return !needle||blob.includes(needle)});$("result-count").textContent=filtered.length+" of "+findings.length+" findings";const root=$("findings");root.replaceChildren();if(!filtered.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No findings match the selected filters.";root.append(empty);return}for(const f of filtered){const card=document.createElement("article");card.className="finding";const head=document.createElement("div");head.className="fhead";const title=document.createElement("div");title.className="ftitle";title.textContent=f.title||"Untitled finding";const badges=document.createElement("div");badges.className="badges";for(const label of [String(f.severity||"info").toUpperCase(),f.cvss_score!==null&&f.cvss_score!==undefined?"CVSS "+f.cvss_score:"",f.confidence_score!==undefined?"Confidence "+f.confidence_score+"%":"",f.finding_id||""]){if(!label)continue;const badge=document.createElement("span");badge.className="badge "+String(f.severity||"info");badge.textContent=label;badges.append(badge)}head.append(title,badges);card.append(head);addField(card,"Category / type",[f.category,f.kind].filter(Boolean).join(" · "));addField(card,"Affected URL",f.url);addField(card,"CVE / CWE",[...(f.cve_ids||[]),...(f.cwe_ids||[])].join(", "));addField(card,"Description",f.description);addField(card,"Impact",f.impact);addField(card,"Evidence",f.evidence);addField(card,"Remediation",f.remediation);addField(card,"References",f.references||[],"refs");root.append(card)}}
for(const id of ["search","severity","cwe","cvss"])$(id).addEventListener("input",render);
const components=report.software_components||[];$("software").textContent=components.length?components.map(x=>[x.name,x.version,"("+x.cpe+")"].join(" ")).join("\n"):"No versioned software fingerprints identified.";
render();
</script></body></html>"""
    Path(path).write_text(page, encoding="utf-8")


def write_report_bundle(json_path: str, html_path: str, csv_path: str, **kwargs) -> dict:
    """Write the JSON source report and its self-contained HTML/CSV exports."""
    report = write_report(json_path, **kwargs)
    write_html_report(html_path, report)
    write_csv_report(csv_path, report)
    return report
