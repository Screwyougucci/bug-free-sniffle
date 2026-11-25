"""OWASP ZAP integration for authorized, local web assessments.

Darth Scanner delegates crawling and vulnerability rules to the installed ZAP
engine. ZAP runs as a loopback-only daemon with a per-run API key; its API is
never exposed to the network. Passive scanning is the default. Active scanning
is a separate, explicit opt-in.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
from typing import Callable
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen
import json

from .checks import Finding, _safe_evidence_url


class ZapEngineError(RuntimeError):
    """Raised when the local ZAP engine cannot be started or controlled."""


class ZapNotInstalledError(ZapEngineError):
    """Raised when no supported local ZAP launcher can be found."""


@dataclass
class ZapRuntime:
    process: subprocess.Popen
    base_url: str
    api_key: str
    launcher: Path


def find_zap_launcher() -> Path | None:
    """Find an existing official ZAP Windows launcher without guessing downloads."""
    configured = os.environ.get("DARTH_ZAP_PATH", "").strip()
    candidates: list[Path] = []
    if configured:
        path = Path(configured).expanduser()
        if path.is_dir():
            candidates.extend((path / "zap.bat", path / "zap.exe", path / "ZAP.exe"))
        else:
            candidates.append(path)
    for name in ("zap.bat", "zap.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    roots = [
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LOCALAPPDATA"),
    ]
    for root in filter(None, roots):
        base = Path(root)
        candidates.extend((
            base / "ZAP" / "Zed Attack Proxy" / "zap.bat",
            base / "OWASP" / "Zed Attack Proxy" / "zap.bat",
            base / "Programs" / "ZAP" / "Zed Attack Proxy" / "zap.bat",
            base / "Programs" / "OWASP" / "Zed Attack Proxy" / "zap.bat",
        ))
    for candidate in candidates:
        if candidate.is_file() and candidate.name.lower() in {"zap.bat", "zap.exe"}:
            return candidate.resolve()
    return None


def scope_regex_for_target(target: str) -> str:
    """Return a strict same-host URL regex for a ZAP context."""
    parts = urlsplit(target)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Target must be a valid HTTP or HTTPS URL.")
    host = re.escape(parts.hostname.encode("idna").decode("ascii"))
    port = f":{parts.port}" if parts.port else ""
    return f"^{re.escape(parts.scheme)}://{host}{re.escape(port)}/.*$"


def build_launch_command(launcher: Path, port: int, api_key: str) -> list[str]:
    """Build a Windows-safe command for the official batch or executable launcher."""
    arguments = [
        "-daemon", "-host", "127.0.0.1", "-port", str(port),
        "-config", f"api.key={api_key}",
        "-config", "api.addrs.addr.name=127.0.0.1",
        "-config", "api.addrs.addr.regex=false",
    ]
    if os.name == "nt" and launcher.suffix.lower() == ".bat":
        return ["cmd.exe", "/c", str(launcher), *arguments]
    return [str(launcher), *arguments]


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _redact(value: object, limit: int = 1800) -> str:
    text = str(value or "")
    text = re.sub(
        r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie)([\s:=]+)([^\s,;<>\"']+)",
        r"\1\2[REDACTED]", text,
    )
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", text)
    return text[:limit]


def alerts_to_findings(alerts: list[dict]) -> list[Finding]:
    """Normalize ZAP alerts into Darth's persistent finding format."""
    findings: list[Finding] = []
    risk_map = {
        "high": "high", "medium": "medium", "low": "low",
        "informational": "info", "info": "info",
    }
    confidence_map = {"high": "high", "medium": "medium", "low": "low"}
    for alert in alerts:
        title = str(alert.get("name") or alert.get("alert") or "OWASP ZAP alert").strip()
        url = _safe_evidence_url(str(alert.get("url") or ""))
        if not url:
            continue
        risk_text = str(alert.get("risk") or alert.get("riskdesc") or "Informational").split()[0].lower()
        severity = risk_map.get(risk_text, "info")
        confidence_text = str(alert.get("confidence") or "Low").split()[0].lower()
        confidence = confidence_map.get(confidence_text, "low")
        evidence_parts = []
        for label, key in (("Parameter", "param"), ("Attack", "attack"), ("Evidence", "evidence")):
            if alert.get(key):
                evidence_parts.append(f"{label}: {_redact(alert[key], 700)}")
        evidence = "\n".join(evidence_parts) or "ZAP rule matched; inspect the alert details and request/response in the local ZAP session."
        cwe = str(alert.get("cweid") or "").strip()
        cwe_ids = [f"CWE-{cwe}"] if cwe.isdigit() and int(cwe) > 0 else []
        refs = str(alert.get("reference") or "")
        references = [item.strip() for item in re.findall(r"https?://[^\s<>\"']+", refs)][:20]
        cve_ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", refs + " " + str(alert.get("other") or ""), re.I)))
        remediation = _redact(alert.get("solution") or "Review the rule guidance and verify the behavior in the affected application.", 1800)
        plugin_id = str(alert.get("pluginId") or "")
        method = str(alert.get("method") or "Not supplied")
        param = str(alert.get("param") or "")
        findings.append(Finding(
            category="owasp-zap",
            title=title,
            severity=severity,
            confidence=confidence,
            url=url,
            evidence=evidence,
            remediation=remediation,
            kind="candidate",
            description=_redact(alert.get("description") or "", 2500),
            impact=_redact(alert.get("riskdesc") or "", 500),
            cwe_ids=cwe_ids,
            cve_ids=cve_ids,
            references=references,
            affected_component=param or None,
            remediation_steps=[remediation] if remediation else [],
            evidence_details={
                "engine": "OWASP ZAP",
                "plugin_id": plugin_id,
                "method": method,
                "parameter": _redact(param, 200),
                "confidence": confidence_text,
                "alert_reference": _redact(alert.get("reference") or "", 1800),
                "response_body_saved": False,
                "raw_attack_value_saved": False,
            },
            reproduction_steps=[
                "Open the corresponding alert in the local OWASP ZAP session.",
                f"Review the affected URL: {url}",
                "Verify the reported behavior manually in the authorized test environment; a scanner alert is not by itself proof of impact.",
            ],
        ))
    return findings


class ZapEngine:
    """Own a loopback-only ZAP daemon and orchestrate a bounded scan."""

    def __init__(
        self,
        launcher: Path | None = None,
        *,
        port: int | None = None,
        api_timeout: float = 10.0,
        popen_factory: Callable = subprocess.Popen,
        api_call: Callable | None = None,
    ):
        self.launcher = launcher or find_zap_launcher()
        self.port = port or _free_loopback_port()
        self.api_timeout = api_timeout
        self._popen = popen_factory
        self._api_override = api_call
        self.runtime: ZapRuntime | None = None
        self._owned_process = False

    def _api(self, component: str, kind: str, operation: str, **params) -> dict:
        if self._api_override is not None:
            return self._api_override(component, kind, operation, params)
        if self.runtime is None:
            raise ZapEngineError("ZAP is not running.")
        query = dict(params)
        query["apikey"] = self.runtime.api_key
        url = f"{self.runtime.base_url}/JSON/{component}/{kind}/{operation}/?{urlencode(query)}"
        try:
            with urlopen(url, timeout=self.api_timeout) as response:
                payload = json.loads(response.read(4_000_000).decode("utf-8", "replace"))
        except (OSError, URLError, ValueError) as exc:
            raise ZapEngineError(f"ZAP API {component}/{kind}/{operation} failed: {exc}") from exc
        if isinstance(payload, dict) and payload.get("code") and payload.get("message"):
            raise ZapEngineError(f"ZAP API error: {payload.get('message')}")
        return payload if isinstance(payload, dict) else {}

    def start(self, *, startup_timeout: float = 90.0) -> str:
        if self.runtime is not None:
            return str(self._api("core", "view", "version").get("version", "unknown"))
        if self.launcher is None or not self.launcher.is_file():
            raise ZapNotInstalledError(
                "OWASP ZAP is not installed. Install the official ZAP Windows release, "
                "then restart Darth Scanner. You can set DARTH_ZAP_PATH to the folder containing zap.bat."
            )
        api_key = secrets.token_urlsafe(32)
        base_url = f"http://127.0.0.1:{self.port}"
        command = build_launch_command(self.launcher, self.port, api_key)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            process = self._popen(
                command, cwd=str(self.launcher.parent),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=creationflags,
            )
        except OSError as exc:
            raise ZapEngineError(f"Could not start OWASP ZAP: {exc}") from exc
        self.runtime = ZapRuntime(process, base_url, api_key, self.launcher)
        self._owned_process = True
        deadline = time.monotonic() + startup_timeout
        last_error = "waiting for ZAP API"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.close()
                raise ZapEngineError("OWASP ZAP exited during startup. Check its Java 17+ installation.")
            try:
                version = self._api("core", "view", "version").get("version")
                if version:
                    return str(version)
            except ZapEngineError as exc:
                last_error = str(exc)
            time.sleep(0.5)
        self.close()
        raise ZapEngineError(f"OWASP ZAP did not become ready within {startup_timeout:.0f}s ({last_error}).")

    def _wait(self, component: str, operation: str, scan_id: str, *,
              stop_event=None, timeout: float, progress=None) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                try:
                    self._api(component, "action", "stop", scanId=scan_id)
                except ZapEngineError:
                    pass
                raise ZapEngineError("Scan stopped by user.")
            payload = self._api(component, "view", operation, scanId=scan_id)
            raw = payload.get("status", "0")
            if component == "clientSpider":
                done = str(raw).lower() not in {"running", "starting", "pending"}
                percent = 100 if done else 0
            else:
                try:
                    percent = int(raw)
                except (TypeError, ValueError):
                    percent = 0
                done = percent >= 100
            if progress:
                progress(f"{component}: {percent}%")
            if done:
                return
            time.sleep(1.0)
        try:
            self._api(component, "action", "stop", scanId=scan_id)
        except ZapEngineError:
            pass
        raise ZapEngineError(f"{component} scan exceeded its {timeout:.0f}s time limit.")

    def scan(self, target: str, *, active_scan: bool = False, stop_event=None,
             progress=None, spider_timeout: float = 900.0,
             active_timeout: float = 600.0) -> dict:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("Target must be a valid HTTP or HTTPS URL.")
        version = self.start()
        context_name = "Darth-" + secrets.token_hex(6)
        self._api("core", "action", "newSession", name="darth-" + secrets.token_hex(6), overwrite="true")
        context = self._api("context", "action", "newContext", contextName=context_name)
        context_id = str(context.get("contextId") or "")
        exact_origin = scope_regex_for_target(target)
        self._api("context", "action", "includeInContext", contextName=context_name, regex=exact_origin)
        self._api("context", "action", "setContextInScope", contextName=context_name, booleanInScope="true")

        if progress:
            progress("OWASP ZAP traditional spider starting")
        spider = self._api(
            "spider", "action", "scan", url=target,
            contextName=context_name, recurse="true", subtreeOnly="true",
            maxChildren="1000",
        )
        spider_id = str(spider.get("scan") or "0")
        self._wait("spider", "status", spider_id, stop_event=stop_event,
                   timeout=spider_timeout, progress=progress)

        client_spider_status = "not-run"
        try:
            if progress:
                progress("OWASP ZAP browser-based Client Spider starting")
            client = self._api(
                "clientSpider", "action", "scan", url=target,
                contextName=context_name, subtreeOnly="true",
                maxCrawlDepth="8", pageLoadTime="2",
            )
            client_id = str(client.get("scan") or "0")
            self._wait("clientSpider", "status", client_id, stop_event=stop_event,
                       timeout=min(spider_timeout, 600.0), progress=progress)
            client_spider_status = "completed"
        except ZapEngineError as exc:
            if "stopped by user" in str(exc).lower():
                raise
            client_spider_status = "unavailable: " + str(exc)[:300]
            if progress:
                progress("Client Spider unavailable; continuing with traditional Spider: " + str(exc))

        if progress:
            progress("Waiting for ZAP passive analysis queue")
        passive_deadline = time.monotonic() + 180.0
        while time.monotonic() < passive_deadline:
            if stop_event is not None and stop_event.is_set():
                raise ZapEngineError("Scan stopped by user.")
            pending = self._api("pscan", "view", "recordsToScan")
            try:
                remaining = int(pending.get("recordsToScan", 0))
            except (TypeError, ValueError):
                remaining = 0
            if remaining <= 0:
                break
            if progress:
                progress(f"Passive analysis queue: {remaining} records")
            time.sleep(1.0)

        active_status = "not-requested"
        if active_scan:
            if progress:
                progress("OWASP ZAP active scanner starting (authorized opt-in)")
            active = self._api(
                "ascan", "action", "scan", url=target,
                recurse="true", inScopeOnly="true",
                contextId=context_id, scanPolicyName="Default Policy",
            )
            active_id = str(active.get("scan") or "0")
            self._wait("ascan", "status", active_id, stop_event=stop_event,
                       timeout=active_timeout, progress=progress)
            active_status = "completed"

        if progress:
            progress("Collecting ZAP alerts")
        alert_payload = self._api("core", "view", "alerts", baseurl=target, start="0", count="10000")
        alerts = alert_payload.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []
        url_payload = self._api("core", "view", "urls")
        urls = url_payload.get("urls", [])
        if not isinstance(urls, list):
            urls = []
        findings = alerts_to_findings(alerts)
        return {
            "engine": "OWASP ZAP",
            "engine_version": version,
            "target": _safe_evidence_url(target),
            "traditional_spider": "completed",
            "client_spider": client_spider_status,
            "active_scan": active_status,
            "discovered_url_count": len(urls),
            "discovered_urls": [_safe_evidence_url(item) for item in urls[:5000]],
            "alert_count": len(alerts),
            "findings": [item.to_dict() for item in findings],
            "limitations": [
                "ZAP alerts are scanner findings and require human validation.",
                "No HTTP request or response bodies are copied into the Darth report.",
                "Active scanning is only run when separately enabled and authorized.",
            ],
        }

    def close(self) -> None:
        runtime = self.runtime
        self.runtime = None
        if runtime is None or not self._owned_process:
            return
        try:
            self._api_override = None
            query = urlencode({"apikey": runtime.api_key})
            with urlopen(f"{runtime.base_url}/JSON/core/action/shutdown/?{query}", timeout=2):
                pass
        except Exception:
            pass
        try:
            runtime.process.wait(timeout=8)
        except Exception:
            try:
                runtime.process.terminate()
                runtime.process.wait(timeout=5)
            except Exception:
                try:
                    runtime.process.kill()
                except Exception:
                    pass
        self._owned_process = False


def run_zap_scan(target: str, *, active_scan: bool = False, stop_event=None,
                 progress=None, launcher: Path | None = None) -> dict:
    """Convenience wrapper that always closes the daemon started by this run."""
    engine = ZapEngine(launcher=launcher)
    try:
        return engine.scan(target, active_scan=active_scan,
                           stop_event=stop_event, progress=progress)
    finally:
        engine.close()
