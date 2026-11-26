"""Reliable, per-tool Windows installer for Darth Scanner's official engines.

Uses GitHub's release asset SHA-256 digest when available, otherwise parses
publisher checksum files. A failure for one tool never prevents attempts for
the remaining tools. Archives are inspected in memory; only the expected EXE
is written into Darth Scanner's private tools directory.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import zipfile

from .toolchain import TOOL_SPECS, ToolchainError, tool_root

MAX_ARCHIVE_BYTES = 160 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 100 * 1024 * 1024
USER_AGENT = "DarthScanner-ToolManager/0.27.0"


def _read_url(url: str, limit: int) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "api.github.com"}:
        raise ToolchainError("Refusing a non-GitHub or non-HTTPS release URL.")
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    try:
        with urlopen(request, timeout=45) as response:
            data = response.read(limit + 1)
    except (OSError, URLError) as exc:
        raise ToolchainError(f"Download failed: {exc}") from exc
    if len(data) > limit:
        raise ToolchainError(f"Download exceeds the {limit} byte safety limit.")
    return data


def _latest_release(repo: str) -> dict:
    raw = _read_url(f"https://api.github.com/repos/{repo}/releases/latest", 2_000_000)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ToolchainError(f"GitHub returned invalid release metadata for {repo}.") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise ToolchainError(f"GitHub returned no usable release for {repo}.")
    return payload


def _filename(value: str) -> str:
    return str(value).replace("\\", "/").rsplit("/", 1)[-1].strip()


def _checksum_for(manifest: bytes, filename: str) -> str:
    """Accept common SHA256SUMS, sha256sum, and OpenSSL checksum formats."""
    wanted = _filename(filename)
    text = manifest.decode("utf-8-sig", "replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns = (
            r"(?i)^([a-f0-9]{64})\s+\*?(.+?)\s*$",
            r"(?i)^SHA256\s*\((.+?)\)\s*=\s*([a-f0-9]{64})\s*$",
            r"(?i)^([a-f0-9]{64})\s+\*?(.+?)\s*$",
        )
        for index, pattern in enumerate(patterns):
            match = re.match(pattern, line)
            if not match:
                continue
            digest, listed = (match.group(2), match.group(1)) if index == 1 else (match.group(1), match.group(2))
            if _filename(listed) == wanted:
                return digest.lower()
    raise ToolchainError(f"No SHA-256 entry for {wanted} was found in the publisher's checksum file.")


def _asset_sha256(asset: dict, assets: list[dict]) -> tuple[str, str]:
    """Return expected digest and its provenance; never accept an unverified archive."""
    digest = str(asset.get("digest") or "").strip().lower()
    match = re.fullmatch(r"sha256:([a-f0-9]{64})", digest)
    if match:
        return match.group(1), "GitHub release asset digest"

    checksum_assets = [
        item for item in assets
        if item.get("browser_download_url")
        and re.search(r"(checksum|sha256|sha-256)", str(item.get("name", "")), re.I)
        and item.get("name") != asset.get("name")
    ]
    for checksum_asset in checksum_assets:
        try:
            manifest = _read_url(checksum_asset["browser_download_url"], 2_000_000)
            return _checksum_for(manifest, asset["name"]), f"publisher file {checksum_asset['name']}"
        except ToolchainError:
            continue
    raise ToolchainError(
        f"No usable GitHub SHA-256 digest or publisher checksum entry was available for {asset.get('name')}; "
        "the archive was not installed."
    )


def _select_windows_asset(assets: list[dict], prefix: str) -> dict:
    matches = [
        item for item in assets
        if str(item.get("name", "")).lower().startswith(prefix.lower() + "_")
        and str(item.get("name", "")).lower().endswith("_windows_amd64.zip")
        and item.get("browser_download_url")
    ]
    if not matches:
        raise ToolchainError(f"No official Windows x64 ZIP matching {prefix}_*_windows_amd64.zip was published.")
    # Prefer a non-debug, non-symbol archive if a release publishes several.
    matches.sort(key=lambda item: ("debug" in item["name"].lower(), "symbols" in item["name"].lower(), item["name"]))
    return matches[0]


def _install_one(name: str, repo: str, executable: str, prefix: str, destination: Path, progress) -> dict:
    release = _latest_release(repo)
    asset = _select_windows_asset(release["assets"], prefix)
    expected, verification = _asset_sha256(asset, release["assets"])
    progress(f"{name}: downloading {release.get('tag_name', 'latest')} from {repo}…")
    archive = _read_url(asset["browser_download_url"], MAX_ARCHIVE_BYTES)
    actual = sha256(archive).hexdigest()
    if actual != expected:
        raise ToolchainError(f"{name}: SHA-256 mismatch ({verification}); archive rejected.")

    try:
        with zipfile.ZipFile(BytesIO(archive)) as bundle:
            matches = [
                item for item in bundle.infolist()
                if _filename(item.filename).lower() == executable.lower() and not item.is_dir()
            ]
            if not matches:
                raise ToolchainError(f"{name}: verified archive did not contain {executable}.")
            info = matches[0]
            if info.file_size <= 0 or info.file_size > MAX_EXECUTABLE_BYTES:
                raise ToolchainError(f"{name}: executable size is outside the allowed safety limit.")
            binary = bundle.read(info)
    except zipfile.BadZipFile as exc:
        raise ToolchainError(f"{name}: publisher archive was not a valid ZIP.") from exc

    if len(binary) != info.file_size or not binary.startswith(b"MZ"):
        raise ToolchainError(f"{name}: extracted file failed Windows executable validation.")
    destination.mkdir(parents=True, exist_ok=True)
    final_path = destination / executable
    temporary = final_path.with_suffix(final_path.suffix + ".download")
    temporary.write_bytes(binary)
    temporary.replace(final_path)
    progress(f"{name}: installed and verified ({verification}).")
    return {
        "installed": True,
        "version": release.get("tag_name", "unknown"),
        "asset": asset["name"],
        "verification": verification,
        "sha256": actual,
        "path": str(final_path),
    }


def _java_17_available() -> bool:
    local_java = tool_root() / "runtime" / "java17" / "bin" / "java.exe"
    java = str(local_java) if local_java.is_file() else shutil.which("java")
    if not java:
        return False
    try:
        result = subprocess.run(
            [java, "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", timeout=10,
        )
        match = re.search(r'version\s+"?(?:1\.)?(\d+)', result.stdout or "", re.I)
        return bool(match and int(match.group(1)) >= 17)
    except (OSError, subprocess.SubprocessError):
        return False


def _zap_launcher():
    try:
        from .zap_engine import find_zap_launcher
        return find_zap_launcher()
    except Exception:
        return None


def _winget_install(package_id: str, progress) -> bool:
    winget = shutil.which("winget")
    if not winget:
        progress(f"PREREQUISITE NOT INSTALLED: WinGet was not found; cannot install {package_id} automatically.")
        return False
    command = [
        winget, "install", "--id", package_id, "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements",
    ]
    progress(f"Installing prerequisite {package_id} through WinGet…")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            timeout=1200, creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        progress(f"PREREQUISITE FAILED: {package_id}: {exc}")
        return False
    for line in (result.stdout or "").splitlines()[-10:]:
        progress(line[:500])
    if result.returncode:
        progress(f"PREREQUISITE FAILED: {package_id} (WinGet exit {result.returncode}).")
        return False
    progress(f"PREREQUISITE READY: {package_id}.")
    return True



def _safe_extract_zip(archive: bytes, destination: Path, max_expanded: int = 900 * 1024 * 1024) -> list[Path]:
    """Extract a GitHub ZIP with traversal and expansion limits."""
    written = []
    root = destination.resolve()
    total = 0
    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
                raise ToolchainError("Archive contains an absolute path.")
            parts = [part for part in name.split("/") if part not in {"", "."}]
            if any(part == ".." for part in parts):
                raise ToolchainError("Archive contains path traversal.")
            total += info.file_size
            if total > max_expanded:
                raise ToolchainError("Archive exceeds expanded-size limit.")
            target = root.joinpath(*parts).resolve()
            if root != target and root not in target.parents:
                raise ToolchainError("Archive entry escapes install folder.")
            target.parent.mkdir(parents=True, exist_ok=True)
            data = bundle.read(info)
            if len(data) != info.file_size:
                raise ToolchainError("Archive entry size mismatch.")
            target.write_bytes(data)
            written.append(target)
    return written


def _install_java17_github(progress) -> dict:
    if _java_17_available():
        return {"installed": True, "source": "existing Java 17+ on PATH"}
    release = _latest_release("adoptium/temurin17-binaries")
    assets = [a for a in release["assets"] if re.match(
        r"(?i)^OpenJDK17U-jre_x64_windows_hotspot_.*\.zip$", str(a.get("name", "")))]
    if not assets:
        raise ToolchainError("Temurin release has no Windows x64 JRE ZIP.")
    asset = assets[0]
    digest, provenance = _asset_sha256(asset, release["assets"])
    progress(f"Java 17: downloading Temurin {release.get('tag_name')} from GitHub…")
    archive = _read_url(asset["browser_download_url"], 300 * 1024 * 1024)
    actual = sha256(archive).hexdigest()
    if actual != digest:
        raise ToolchainError("Temurin JRE SHA-256 mismatch; archive rejected.")
    base = tool_root() / "runtime"
    staging = base / "java17-staging"
    final = base / "java17"
    shutil.rmtree(staging, ignore_errors=True)
    files = _safe_extract_zip(archive, staging)
    java_files = [p for p in files if p.name.lower() == "java.exe" and p.parent.name.lower() == "bin"]
    if not java_files:
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolchainError("Verified JRE archive did not contain bin/java.exe.")
    home = java_files[0].parent.parent
    shutil.rmtree(final, ignore_errors=True)
    final.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(home), str(final))
    shutil.rmtree(staging, ignore_errors=True)
    progress(f"Java 17 installed from GitHub: {final}")
    return {"installed": True, "version": release.get("tag_name"), "path": str(final / "bin" / "java.exe"), "sha256": actual, "verification": provenance}


def _install_zap_github(progress) -> dict:
    existing = _zap_launcher()
    if existing:
        return {"installed": True, "source": "existing ZAP", "path": str(existing)}
    release = _latest_release("zaproxy/zaproxy")
    assets = [a for a in release["assets"] if str(a.get("name", "")).endswith("_Crossplatform.zip")]
    if not assets:
        raise ToolchainError("ZAP release has no Crossplatform ZIP.")
    asset = assets[0]
    digest, provenance = _asset_sha256(asset, release["assets"])
    progress(f"OWASP ZAP: downloading {release.get('tag_name')} from GitHub…")
    archive = _read_url(asset["browser_download_url"], 450 * 1024 * 1024)
    actual = sha256(archive).hexdigest()
    if actual != digest:
        raise ToolchainError("OWASP ZAP SHA-256 mismatch; archive rejected.")
    staging = tool_root() / "zap-staging"
    final = tool_root() / "zap"
    shutil.rmtree(staging, ignore_errors=True)
    files = _safe_extract_zip(archive, staging)
    launchers = [p for p in files if p.name.lower() == "zap.bat"]
    if not launchers:
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolchainError("Verified ZAP archive did not contain zap.bat.")
    shutil.rmtree(final, ignore_errors=True)
    shutil.move(str(launchers[0].parent), str(final))
    shutil.rmtree(staging, ignore_errors=True)
    progress(f"OWASP ZAP installed from GitHub: {final}")
    return {"installed": True, "version": release.get("tag_name"), "path": str(final / "zap.bat"), "sha256": actual, "verification": provenance}


def _install_sqlmap_github(progress) -> dict:
    release = _latest_release("sqlmapproject/sqlmap")
    tag = str(release.get("tag_name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,80}", tag):
        raise ToolchainError("sqlmap release tag is missing or invalid.")
    progress(f"sqlmap: downloading official GitHub source tag {tag}…")
    archive = _read_url(f"https://api.github.com/repos/sqlmapproject/sqlmap/zipball/{tag}", 80 * 1024 * 1024)
    staging = tool_root() / "sqlmap-staging"
    final = tool_root() / "sqlmap"
    shutil.rmtree(staging, ignore_errors=True)
    files = _safe_extract_zip(archive, staging, max_expanded=250 * 1024 * 1024)
    entrypoints = [p for p in files if p.name == "sqlmap.py"]
    if not entrypoints:
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolchainError("sqlmap source archive did not contain sqlmap.py.")
    shutil.rmtree(final, ignore_errors=True)
    shutil.move(str(entrypoints[0].parent), str(final))
    shutil.rmtree(staging, ignore_errors=True)
    progress(f"sqlmap source installed from GitHub tag {tag}.")
    return {"installed": True, "version": tag, "path": str(final / "sqlmap.py"), "source": "GitHub release tag over HTTPS", "note": "sqlmap publishes source, not a Windows executable."}


def install_toolchain(progress=lambda message: None, stop_event=None) -> dict:
    """Install each security engine independently from official GitHub sources."""
    if os.name != "nt":
        raise ToolchainError("The managed installer currently supports Windows x64 only.")
    architecture = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "")
    if architecture.lower() not in {"amd64", "x86_64"}:
        raise ToolchainError(f"Windows x64 is required; detected architecture: {architecture or 'unknown'}.")
    binary_dir = tool_root() / "bin"
    report = {"installed": {}, "failed": {}, "prerequisites": {}}
    for name, (repo, executable, prefix) in TOOL_SPECS.items():
        if stop_event is not None and stop_event.is_set():
            report["failed"][name] = "Cancelled by user."
            continue
        try:
            report["installed"][name] = _install_one(name, repo, executable + ".exe", prefix, binary_dir, progress)
        except Exception as exc:
            report["failed"][name] = str(exc) or exc.__class__.__name__
            progress(f"{name}: INSTALL FAILED — {report['failed'][name]}")
    for name, installer in (("java17", _install_java17_github), ("zap", _install_zap_github), ("sqlmap", _install_sqlmap_github)):
        try:
            result = installer(progress)
            if name == "sqlmap":
                report["installed"][name] = result
            else:
                report["prerequisites"][name] = result
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            if name == "sqlmap":
                report["failed"][name] = message
            else:
                report["prerequisites"][name] = {"installed": False, "detail": message}
            progress(f"{name}: GitHub installation failed — {message}")
    manifest_path = tool_root() / "installed-tools.json"
    manifest_path.write_text(json.dumps({
        "schema_version": 3, "updated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "windows-x64", **report,
    }, indent=2), encoding="utf-8")
    progress(f"INSTALL SUMMARY: {len(report['installed'])}/6 tools installed; {len(report['failed'])}/6 failed.")
    progress(f"Java 17+: {'READY' if report['prerequisites'].get('java17', {}).get('installed') else 'MISSING'}")
    progress(f"OWASP ZAP: {'READY' if report['prerequisites'].get('zap', {}).get('installed') else 'MISSING'}")
    progress(f"Detailed installation report: {manifest_path}")
    return report
