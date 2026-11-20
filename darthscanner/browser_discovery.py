"""Optional, scope-enforced Playwright discovery for rendered web applications.

The browser adapter observes metadata only: it never submits forms, clicks controls,
replays requests, stores request/response bodies, or exports cookies/authorization.
Cross-origin requests are blocked before they leave the browser context.
"""
from __future__ import annotations

from collections import deque
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .scope import Scope


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are supported.")
    return parts.scheme.lower(), parts.hostname.lower().rstrip("."), parts.port or (443 if parts.scheme == "https" else 80)


def _safe_url(url: str) -> str:
    parts = urlsplit(url)
    # Query values and fragments may contain credentials or personal data.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", "", ""))


def _query_names(url: str) -> list[str]:
    names = []
    for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if name and name.lower() not in {"token", "access_token", "refresh_token", "authorization", "password", "passwd", "secret", "session", "sessionid", "cookie", "api_key", "apikey", "signature", "sig", "code"} and name not in names:
            names.append(name[:100])
    return names[:40]


def _same_origin(base: str, candidate: str) -> bool:
    try:
        return _origin(base) == _origin(candidate)
    except ValueError:
        return False


def _control_inventory(page) -> dict:
    """Read rendered DOM metadata only; never read values, placeholders, or text."""
    return page.evaluate("""() => {
      const forms = Array.from(document.forms).slice(0, 100).map(form => ({
        action: (() => { try { const u = new URL(form.getAttribute('action') || location.href, location.href); return u.origin === location.origin ? u.pathname : null; } catch (_) { return null; } })(),
        method: (form.method || 'get').toUpperCase(),
        controls: Array.from(form.elements).slice(0, 100).map(el => ({
          tag: el.tagName.toLowerCase(),
          type: String(el.type || el.tagName).toLowerCase().slice(0, 40),
          name: String(el.name || '').slice(0, 120),
          id: String(el.id || '').slice(0, 120),
          required: Boolean(el.required),
          disabled: Boolean(el.disabled),
          autocomplete: String(el.autocomplete || '').slice(0, 80),
          maxlength: Number.isInteger(el.maxLength) && el.maxLength >= 0 ? Math.min(el.maxLength, 1000000) : null
        }))
      }));
      const outside = Array.from(document.querySelectorAll('input,textarea,select,button')).filter(el => !el.form).length;
      const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500).map(a => {
        try { const u = new URL(a.href, location.href); return u.origin === location.origin ? u.href : null; } catch (_) { return null; }
      }).filter(Boolean);
      return {forms, controls_outside_forms: outside, links};
    }""") 


def browser_discover(target: str, scope: Scope, *, max_pages: int = 12,
                     timeout_ms: int = 15000) -> dict:
    """Render and inventory a bounded same-origin SPA surface using Playwright."""
    if not 1 <= max_pages <= 40:
        raise ValueError("max_pages must be between 1 and 40.")
    if not 1000 <= timeout_ms <= 60000:
        raise ValueError("timeout_ms must be between 1000 and 60000.")
    scope.validate_url(target)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Browser discovery requires the optional dependency. Install with: pip install 'darth-scanner[browser]'") from exc

    origin = _origin(target)
    queue = deque([target])
    queued = {target}
    visited: set[str] = set()
    pages: list[dict] = []
    requests: dict[tuple[str, str, str], dict] = {}
    request_index: dict[int, dict] = {}
    link_edges: dict[tuple[str, str], dict] = {}
    blocked_cross_origin = 0
    requests_made = 0
    request_budget_exhausted = False
    errors: list[dict] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        def guard(route):
            nonlocal blocked_cross_origin, requests_made, request_budget_exhausted
            request_url = route.request.url
            try:
                scope.validate_url(request_url)
                allowed = _origin(request_url) == origin
            except ValueError:
                allowed = False
            if not allowed:
                blocked_cross_origin += 1
                route.abort()
            elif requests_made >= scope.max_requests:
                request_budget_exhausted = True
                route.abort()
            else:
                requests_made += 1
                route.continue_()

        page.route("**/*", guard)

        def observe(request):
            url = request.url
            if not _same_origin(target, url):
                return
            try:
                scope.validate_url(url)
            except ValueError:
                return
            safe = _safe_url(url)
            method = request.method.upper()
            resource_type = request.resource_type
            try:
                initiator = _safe_url(request.frame.url)
            except Exception:
                initiator = None
            key = (method, safe, resource_type)
            if key not in requests and len(requests) < 2000:
                requests[key] = {
                    "method": method,
                    "url": safe,
                    "query_parameter_names": _query_names(url),
                    "resource_type": resource_type,
                    "observed_from_pages": [],
                    "response_statuses": [],
                }
            item = requests.get(key)
            if item is not None and initiator and initiator not in item["observed_from_pages"]:
                item["observed_from_pages"].append(initiator)
            request_index[id(request)] = item if item is not None else {}

        def observe_response(response):
            item = request_index.get(id(response.request))
            if not item:
                return
            status = response.status
            if status not in item["response_statuses"]:
                item["response_statuses"].append(status)
            try:
                content_type = response.headers.get("content-type", "").split(";", 1)[0][:120]
            except Exception:
                content_type = ""
            if content_type and content_type not in item.setdefault("response_content_types", []):
                item["response_content_types"].append(content_type)

        page.on("request", observe)
        page.on("response", observe_response)
        try:
            while queue and len(visited) < max_pages and not request_budget_exhausted:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                try:
                    response = page.goto(current, wait_until="domcontentloaded", timeout=timeout_ms)
                    try:
                        page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 4000))
                    except Exception:
                        pass
                    status = response.status if response else None
                    inventory = _control_inventory(page)
                    final_url = page.url
                    if not _same_origin(target, final_url):
                        errors.append({"url": _safe_url(current), "error": "navigation left the authorized origin and was not inventoried"})
                        continue
                    safe_final = _safe_url(final_url)
                    pages.append({
                        "url": safe_final,
                        "status": status,
                        "title": str(page.title())[:200],
                        "forms": inventory["forms"],
                        "form_count": len(inventory["forms"]),
                        "controls_outside_forms": inventory["controls_outside_forms"],
                        "rendered_links_discovered": len(inventory["links"]),
                    })
                    for link in inventory["links"]:
                        destination = _safe_url(link)
                        edge_key = (safe_final, destination)
                        link_edges.setdefault(edge_key, {"source_page": safe_final, "destination": destination, "relationship": "rendered-anchor-link"})
                        if len(queued) >= max_pages * 20:
                            break
                        if _same_origin(target, link):
                            try:
                                scope.validate_url(link)
                            except ValueError:
                                continue
                            normalized = _safe_url(link)
                            if normalized not in queued and len(queued) < max_pages * 20:
                                queue.append(link)
                                queued.add(normalized)
                except Exception as exc:
                    errors.append({"url": _safe_url(current), "error": type(exc).__name__})
        finally:
            context.close()
            browser.close()

    return {
        "browser_engine": "Playwright Chromium",
        "pages": pages,
        "page_count": len(pages),
        "network_requests": list(requests.values()),
        "network_request_count": len(requests),
        "api_relationships": [item for item in requests.values() if item.get("resource_type") in {"xhr", "fetch", "websocket"}],
        "page_link_relationships": list(link_edges.values()),
        "relationship_counts": {"api_requests": sum(1 for item in requests.values() if item.get("resource_type") in {"xhr", "fetch", "websocket"}), "page_links": len(link_edges)},
        "requests_made": requests_made,
        "request_budget_exhausted": request_budget_exhausted,
        "blocked_cross_origin_requests": blocked_cross_origin,
        "navigation_errors": errors,
        "limits": {"max_pages": max_pages, "timeout_ms": timeout_ms},
        "security_notes": [
            "Rendered DOM inventory only; no forms or controls were submitted or clicked.",
            "Request metadata only; query values, headers, cookies, authorization data, and bodies are not stored.",
            "Cross-origin requests are blocked; only exact authorized host and same-origin requests are observed.",
            "Discovered network routes are inventory only and are never replayed.",
        ],
    }
