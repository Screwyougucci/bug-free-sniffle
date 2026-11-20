"""Passive inventory of HTML forms, controls, and client framework hints.

This module parses already-fetched HTML only. It never submits forms, executes
scripts, retains control values, or requests discovered form actions.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


_MAX_HTML_CHARS = 2_000_000
_MAX_FORMS = 100
_MAX_CONTROLS_PER_FORM = 100

_FRAMEWORKS = (
    ("Next.js", re.compile(r"__NEXT_DATA__|/_next/|next/router", re.I)),
    ("Nuxt", re.compile(r"__NUXT__|/_nuxt/", re.I)),
    ("React", re.compile(r"data-reactroot|react-dom|__REACT", re.I)),
    ("Vue", re.compile(r"data-v-[a-f0-9]+|__VUE__|vue(?:\.runtime)?\.js", re.I)),
    ("Angular", re.compile(r"ng-version=|ng-app=|angular(?:\.min)?\.js", re.I)),
    ("Svelte", re.compile(r"svelte-[a-z0-9]+|svelte/internal", re.I)),
    ("Astro", re.compile(r"astro-island|astro:page-load", re.I)),
    ("Blazor", re.compile(r"_framework/blazor|blazor\.webassembly", re.I)),
)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only absolute HTTP(S) page URLs can be inventoried.")
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    return parts.scheme.lower(), parts.hostname.lower().rstrip("."), port


def _safe_action(page_url: str, action: str) -> tuple[str, bool] | None:
    candidate = urljoin(page_url, action.strip() or page_url)
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        return None
    if parts.username or parts.password:
        return None
    try:
        same_origin = _origin(candidate) == _origin(page_url)
    except ValueError:
        return None
    clean = urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", "", ""))
    return clean, same_origin


class _SurfaceParser(HTMLParser):
    def __init__(self, page_url: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[dict[str, object]] = []
        self.current: dict[str, object] | None = None
        self.controls_without_form = 0

    def handle_starttag(self, tag: str, attrs):
        values = {key.lower(): value for key, value in attrs if key}
        tag = tag.lower()

        if tag == "form":
            if len(self.forms) >= _MAX_FORMS:
                self.current = None
                return
            resolved = _safe_action(self.page_url, values.get("action") or "")
            if resolved is None:
                action, same_origin = None, None
            else:
                action, same_origin = resolved
            method = (values.get("method") or "get").strip().upper()
            if method not in {"GET", "POST", "DIALOG"}:
                method = "OTHER"
            self.current = {
                "page_url": self.page_url,
                "action": action,
                "same_origin_action": same_origin,
                "method": method,
                "enctype": (values.get("enctype") or "application/x-www-form-urlencoded").lower()[:100],
                "controls": [],
            }
            self.forms.append(self.current)
            return

        if tag in {"input", "textarea", "select", "button"}:
            control = {
                "tag": tag,
                "type": (values.get("type") or ("text" if tag == "input" else tag)).lower()[:40],
                "name": (values.get("name") or "")[:120],
                "id": (values.get("id") or "")[:120],
                "required": "required" in values,
                "disabled": "disabled" in values,
                "autocomplete": (values.get("autocomplete") or "")[:80],
            }
            if values.get("maxlength", "").isdigit():
                control["maxlength"] = min(int(values["maxlength"]), 1_000_000)
            if self.current is not None:
                controls = self.current["controls"]
                if len(controls) < _MAX_CONTROLS_PER_FORM:
                    controls.append(control)
            else:
                self.controls_without_form += 1

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self.current = None


def inspect_app_surface(page_url: str, html: str) -> dict[str, object]:
    """Return redacted form/control inventory and framework indicators."""
    _origin(page_url)
    source = html[:_MAX_HTML_CHARS]
    parser = _SurfaceParser(page_url)
    try:
        parser.feed(source)
    except Exception:
        # HTMLParser is intentionally tolerant; retain only what it safely parsed.
        pass

    frameworks = [
        name for name, pattern in _FRAMEWORKS
        if pattern.search(source)
    ]
    return {
        "page_url": page_url,
        "forms": parser.forms,
        "form_count": len(parser.forms),
        "controls_outside_forms": parser.controls_without_form,
        "framework_hints": frameworks,
        "framework_detection_note": (
            "Framework names are heuristic hints from delivered HTML, not verified dependencies."
        ),
        "inventory_note": (
            "Passive HTML inventory only. Form/control values are never retained; "
            "forms are never submitted and actions are never requested."
        ),
    }
