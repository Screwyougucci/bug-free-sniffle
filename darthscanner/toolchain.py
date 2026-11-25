"""Managed third-party security toolchain for authorized web assessments.

Downloads official Windows x64 release archives over HTTPS, verifies publisher
SHA-256 checksum manifests, and extracts only the expected executable. Runtime
commands are argument arrays (never a shell), exact-scope filtered, rate limited,
and checkpointed between long-running assessment cycles.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
from urllib.error import URLError
from urllib.request import Request, urlopen
import zipfile
from io import BytesIO
from urllib.parse import urlsplit


TOOL_SPECS = {
    "ffuf": ("ffuf/ffuf", "ffuf", "ffuf"),
    "subfinder": ("projectdiscovery/subfinder", "subfinder", "subfinder"),
    "httpx": ("projectdiscovery/httpx", "httpx", "httpx"),
    "katana": ("projectdiscovery/katana", "katana", "katana"),
    "nuclei": ("projectdiscovery/nuclei", "nuclei", "nuclei"),
}
SAFE_PATH_WORDLIST = """admin
api
api/v1
api/v2
assets
backup
 backups
config
dashboard
docs
download
downloads
health
healthz
images
img
js
login
logout
manifest.json
metrics
old
portal
robots.txt
sitemap.xml
static
status
swagger
swagger-ui
swagger.json
test
uploads
user
users
version
web
well-known
.well-known/security.txt
.well-known/change-password
.git/HEAD
.env.example
"""
MAX_ARCHIVE_BYTES = 160 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 100 * 1024 * 1024


class ToolchainError(RuntimeError):
    """Raised for installation, scope, or orchestration errors."""


def tool_root() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local" / "share"))
    path = base / "DarthScanner" / "tools"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _read_url(url: str, limit: int) -> bytes:
    request = Request(url, headers={"User-Agent": "DarthScanner-ToolManager/0.26.0", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ToolchainError(f"Download exceeds the {limit} byte safety limit: {url}")
    return data


def _latest_release(repo: str) -> dict:
    try:
        raw = _read_url(f"https://api.github.com/repos/{repo}/releases/latest", 2_000_000)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, URLError, ValueError) as exc:
        raise ToolchainError(f"Could not read official release metadata for {repo}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ToolchainError(f"GitHub did not return a usable release for {repo}.")
    return data


def _checksum_for(manifest: bytes, filename: str) -> str:
    text = manifest.decode("utf-8", "replace")
    for line in text.splitlines():
        match = re.search(r"(?i)\b([a-f0-9]{64})\s+\*?(.+?)\s*$", line)
        if match and Path(match.group(2).strip()).name == filename:
            return match.group(1).lower()
    raise ToolchainError(f"The official checksum manifest did not contain {filename}.")


def _install_release_binary(name: str, repo: str, executable: str, prefix: str,
                            destination: Path, progress) -> dict:
    release = _latest_release(repo)
    assets = release["assets"]
    candidates = [
        item for item in assets
        if item.get("name", "").lower().startswith(prefix.lower() + "_")
        and item.get("name", "").lower().endswith("_windows_amd64.zip")
        and item.get("browser_download_url")
    ]
    if not candidates:
        raise ToolchainError(f"No official Windows x64 ZIP was published for {name} in {repo}.")
    asset = candidates[0]
    manifests = [item for item in assets if "checksum" in item.get("name", "").lower() and item.get("browser_download_url")]
    if not manifests:
        raise ToolchainError(f"{repo} did not publish a checksum manifest; refusing an unverifiable binary.")
    progress(f"{name}: downloading official release {release.get('tag_name', 'latest')}…")
    archive = _read_url(asset["browser_download_url"], MAX_ARCHIVE_BYTES)
    manifest = _read_url(manifests[0]["browser_download_url"], 2_000_000)
    expected = _checksum_for(manifest, asset["name"])
    actual = sha256(archive).hexdigest()
    if actual != expected:
        raise ToolchainError(f"{name}: SHA-256 mismatch; downloaded archive was rejected.")
    try:
        with zipfile.ZipFile(BytesIO(archive)) as bundle:
            matches = [info for info in bundle.infolist()
                       if Path(info.filename.replace("\\", "/")).name.lower() == executable.lower()
                       and not info.is_dir()]
            if not matches:
                raise ToolchainError(f"{name}: expected {executable} was not in the verified archive.")
            info = matches[0]
            if info.file_size <= 0 or info.file_size > MAX_EXECUTABLE_BYTES:
                raise ToolchainError(f"{name}: executable size is outside the allowed limit.")
            binary = bundle.read(info)
    except zipfile.BadZipFile as exc:
        raise ToolchainError(f"{name}: release archive is not a valid ZIP.") from exc
    if len(binary) != info.file_size:
        raise ToolchainError(f"{name}: extracted executable size mismatch.")
    destination.mkdir(parents=True, exist_ok=True)
    final_path = destination / executable
    temporary = final_path.with_suffix(final_path.suffix + ".download")
    temporary.write_bytes(binary)
    temporary.replace(final_path)
    return {
        "name": name, "version": release.get("tag_name", "unknown"),
        "repository": repo, "asset": asset["name"],
        "archive_sha256": actual, "executable": str(final_path),
        "installed_at": datetime.now(timezone.utc).isoformat(),
    }



def _winget_install(package_id: str, progress) -> bool:
    winget = shutil.which("winget")
    if not winget:
        progress(f"WinGet is unavailable; skipped prerequisite {package_id}.")
        return False
    command = [winget, "install", "--id", package_id, "--exact", "--silent",
               "--accept-package-agreements", "--accept-source-agreements"]
    progress(f"WinGet: installing {package_id} (Windows may request approval)…")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace", timeout=1200, creationflags=flags)
    except (OSError, subprocess.TimeoutExpired) as exc:
        progress(f"WinGet could not install {package_id}: {exc}")
        return False
    for line in (result.stdout or "").splitlines()[-12:]:
        progress(line[:500])
    if result.returncode != 0:
        progress(f"WinGet installation failed for {package_id} (exit {result.returncode}).")
        return False
    progress(f"WinGet installed or updated {package_id}.")
    return True


def _java_17_available() -> bool:
    java = shutil.which("java")
    if not java:
        return False
    try:
        result = subprocess.run([java, "-version"], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=8)
        match = re.search(r'version "?(?:1\\.)?(\\d+)', result.stdout or "", re.IGNORECASE)
        return bool(match and int(match.group(1)) >= 17)
    except (OSError, subprocess.TimeoutExpired):
        return False


def install_toolchain(progress=lambda message: None, stop_event=None) -> dict:
    """Install/update ffuf and ProjectDiscovery binaries into app-local storage."""
    if os.name != "nt" or os.environ.get("PROCESSOR_ARCHITECTURE", "").lower() not in {"amd64", "x86_64"}:
        raise ToolchainError("The bundled tool installer currently supports Windows x64 only.")
    binary_dir = tool_root() / "bin"
    installed = {}
    for name, (repo, executable, prefix) in TOOL_SPECS.items():
        if stop_event is not None and stop_event.is_set():
            raise ToolchainError("Tool installation was cancelled.")
        installed[name] = _install_release_binary(
            name, repo, executable + ".exe", prefix, binary_dir, progress
        )
    if not _java_17_available():
        _winget_install("EclipseAdoptium.Temurin.17.JRE", progress)
    from .zap_engine import find_zap_launcher
    if find_zap_launcher() is None:
        _winget_install("ZAP.ZAP", progress)
    manifest_path = tool_root() / "installed-tools.json"
    manifest_path.write_text(json.dumps({
        "schema_version": 1, "updated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "windows-x64", "tools": installed,
    }, indent=2), encoding="utf-8")
    progress(f"Installed/updated {len(installed)} tools. Manifest: {manifest_path}")
    return installed


def tool_status() -> dict:
    binary_dir = tool_root() / "bin"
    status = {}
    for name in TOOL_SPECS:
        path = binary_dir / f"{name}.exe"
        status[name] = {"installed": path.is_file(), "path": str(path) if path.is_file() else None}
    try:
        from .zap_engine import find_zap_launcher
        launcher = find_zap_launcher()
    except Exception:
        launcher = None
    status["zap"] = {"installed": launcher is not None, "path": str(launcher) if launcher else None}
    return status


def _is_in_scope(root_url: str, candidate: str, include_subdomains: bool) -> bool:
    try:
        root = urlsplit(root_url)
        item = urlsplit(candidate)
        root_host = (root.hostname or "").encode("idna").decode("ascii").lower()
        host = (item.hostname or "").encode("idna").decode("ascii").lower()
        if item.scheme not in {"http", "https"} or item.username or item.password:
            return False
        if include_subdomains:
            host_ok = host == root_host or host.endswith("." + root_host)
        else:
            host_ok = host == root_host
        return host_ok and item.port in (None, root.port) and item.scheme == root.scheme
    except (UnicodeError, ValueError):
        return False


def _run_command(command: list[str], *, stop_event, progress, timeout: int,
                 cwd: Path | None = None) -> tuple[int, list[str]]:
    """Run one tool without a shell and stream output while remaining cancellable."""
    if stop_event is not None and stop_event.is_set():
        return -1, []
    progress("RUN: " + " ".join(command[:4]) + (" …" if len(command) > 4 else ""))
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    process = subprocess.Popen(
        command, cwd=str(cwd) if cwd else None, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True,
        encoding="utf-8", errors="replace", creationflags=flags,
    )
    lines: list[str] = []
    output_queue: queue.Queue = queue.Queue()
    def reader():
        try:
            for line in process.stdout:
                output_queue.put(line.rstrip())
        finally:
            output_queue.put(None)
    threading.Thread(target=reader, daemon=True).start()
    started = time.monotonic()
    finished_reading = False
    while process.poll() is None or not finished_reading:
        if stop_event is not None and stop_event.is_set():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            progress("STOP: current tool process was terminated.")
            break
        if time.monotonic() - started > timeout:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            progress("TIME LIMIT: tool process was stopped.")
            break
        try:
            item = output_queue.get(timeout=0.2)
            if item is None:
                finished_reading = True
            elif item:
                lines.append(item)
                progress(item[:700])
        except queue.Empty:
            pass
    return process.poll() if process.poll() is not None else -1, lines


def _read_jsonl(path: Path, limit: int = 10000) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if len(rows) >= limit:
                break
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except ValueError:
                continue
    return rows


def run_toolchain_watch(target: str, output_dir: Path, *, duration_hours: int = 1,
                        include_subdomains: bool = False, run_nuclei: bool = False,
                        run_zap: bool = False, stop_event=None,
                        progress=lambda message: None,
                        cycle_interval_seconds: int = 1800) -> dict:
    """Run checkpointed, rate-limited assessment cycles until duration or Stop.

    Subdomain enumeration is passive. Active requests to discovered subdomains are
    only made when include_subdomains is explicitly enabled by the UI confirmation.
    """
    if not 1 <= int(duration_hours) <= 24:
        raise ToolchainError("Duration must be between 1 and 24 hours.")
    if not _is_in_scope(target, target, False):
        raise ToolchainError("Target must be a valid HTTP(S) URL.")
    binary_dir = tool_root() / "bin"
    missing = [name for name in TOOL_SPECS if not (binary_dir / f"{name}.exe").is_file()]
    if missing:
        raise ToolchainError("Missing tools: " + ", ".join(missing) + ". Click INSTALL / UPDATE TOOLS first.")
    output_dir.mkdir(parents=True, exist_ok=True)
    state_path = output_dir / "scan-state.json"
    now = time.time()
    state = {}
    if state_path.is_file():
        try:
            previous = json.loads(state_path.read_text(encoding="utf-8"))
            if previous.get("target") == target and previous.get("status") in {"paused", "running"} and previous.get("deadline", 0) > now:
                state = previous
                progress(f"Resuming saved assessment at cycle {int(state.get('last_completed_cycle', 0)) + 1}.")
        except (OSError, ValueError):
            state = {}
    if not state:
        state = {
            "target": target, "started_at": datetime.now(timezone.utc).isoformat(),
            "deadline": now + int(duration_hours) * 3600,
            "duration_hours": int(duration_hours), "last_completed_cycle": 0,
        }
    state["status"] = "running"
    state["include_subdomains"] = bool(include_subdomains)
    state["nuclei_enabled"] = bool(run_nuclei)
    root = urlsplit(target)
    root_host = root.hostname or ""
    wordlist = output_dir / "safe-web-paths.txt"
    wordlist.write_text(SAFE_PATH_WORDLIST.replace(" backups\n", "backups\n"), encoding="utf-8")
    cycle = int(state.get("last_completed_cycle", 0)) + 1
    while time.time() < float(state["deadline"]):
        if stop_event is not None and stop_event.is_set():
            break
        cycle_dir = output_dir / f"cycle-{cycle:04d}"
        cycle_dir.mkdir(parents=True, exist_ok=True)
        progress(f"=== TOOLCHAIN CYCLE {cycle} ===")
        host_file = cycle_dir / "hosts.txt"
        hosts = [root_host]
        if include_subdomains:
            subfinder = binary_dir / "subfinder.exe"
            sub_path = cycle_dir / "subdomains.txt"
            _run_command([str(subfinder), "-d", root_host, "-silent", "-o", str(sub_path), "-max-time", "5"],
                         stop_event=stop_event, progress=progress, timeout=420)
            if sub_path.is_file():
                discovered = [line.strip().lower() for line in sub_path.read_text(encoding="utf-8", errors="replace").splitlines()]
                hosts.extend(item for item in discovered if item and (item == root_host or item.endswith("." + root_host)))
            hosts = list(dict.fromkeys(hosts))[:25]
        host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        httpx_out = cycle_dir / "live-hosts.jsonl"
        _run_command([str(binary_dir / "httpx.exe"), "-l", str(host_file), "-silent", "-json",
                      "-rate-limit", "2", "-threads", "2", "-timeout", "10", "-retries", "0",
                      "-o", str(httpx_out)], stop_event=stop_event, progress=progress, timeout=600)
        live = []
        for item in _read_jsonl(httpx_out, 100):
            candidate = str(item.get("url") or item.get("input") or "")
            if candidate and _is_in_scope(target, candidate, include_subdomains):
                live.append(candidate.rstrip("/"))
        if not live:
            live = [f"{root.scheme}://{root.netloc}"]
        live = list(dict.fromkeys(live))[:10]
        for index, base_url in enumerate(live, 1):
            if stop_event is not None and stop_event.is_set():
                break
            if not _is_in_scope(target, base_url, include_subdomains):
                continue
            safe_name = re.sub(r"[^a-zA-Z0-9.-]", "_", urlsplit(base_url).netloc)
            katana_out = cycle_dir / f"katana-{safe_name}.jsonl"
            _run_command([str(binary_dir / "katana.exe"), "-u", base_url, "-d", "3",
                          "-c", "2", "-rl", "2", "-timeout", "10", "-jc",
                          "-jsonl", "-silent", "-o", str(katana_out)],
                         stop_event=stop_event, progress=progress, timeout=600)
            ffuf_out = cycle_dir / f"ffuf-{safe_name}.json"
            _run_command([str(binary_dir / "ffuf.exe"), "-u", base_url.rstrip("/") + "/FUZZ",
                          "-w", str(wordlist), "-rate", "2", "-t", "2",
                          "-maxtime", "180", "-noninteractive", "-of", "json", "-o", str(ffuf_out)],
                         stop_event=stop_event, progress=progress, timeout=210)
            if run_nuclei and (stop_event is None or not stop_event.is_set()):
                nuclei_out = cycle_dir / f"nuclei-{safe_name}.jsonl"
                _run_command([str(binary_dir / "nuclei.exe"), "-u", base_url,
                              "-tags", "misconfig,exposure,ssl",
                              "-exclude-tags", "dos,intrusive,fuzz,bruteforce,default-login",
                              "-severity", "info,low,medium", "-rate-limit", "2",
                              "-c", "2", "-timeout", "10", "-retries", "0",
                              "-jsonl", "-o", str(nuclei_out)],
                             stop_event=stop_event, progress=progress, timeout=900)
        if run_zap and (stop_event is None or not stop_event.is_set()):
            try:
                from .zap_engine import find_zap_launcher, run_zap_scan
                if find_zap_launcher() is None:
                    progress("OWASP ZAP is not installed; passive ZAP step skipped.")
                else:
                    progress("Running OWASP ZAP passive spider (active scan disabled).")
                    zap_payload = run_zap_scan(target, active_scan=False, stop_event=stop_event, progress=progress)
                    (cycle_dir / "zap-passive.json").write_text(
                        json.dumps(zap_payload, indent=2, ensure_ascii=False), encoding="utf-8"
                    )
            except Exception as exc:
                progress(f"OWASP ZAP step failed; other tools continue: {exc}")
        state["last_completed_cycle"] = cycle
        state["last_cycle_at"] = datetime.now(timezone.utc).isoformat()
        state["status"] = "paused" if stop_event is not None and stop_event.is_set() else "running"
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        progress(f"Cycle {cycle} checkpoint saved. Results: {cycle_dir}")
        if stop_event is not None and stop_event.is_set():
            break
        cycle += 1
        sleep_until = min(time.time() + cycle_interval_seconds, float(state["deadline"]))
        while time.time() < sleep_until:
            if stop_event is not None and stop_event.wait(min(1.0, sleep_until - time.time())):
                break
            if stop_event is None:
                time.sleep(min(1.0, sleep_until - time.time()))
    completed = time.time() >= float(state["deadline"])
    state["status"] = "completed" if completed else "paused"
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    progress(f"Assessment {state['status']}; {state['last_completed_cycle']} cycle(s) checkpointed.")
    return state
