"""Scope-enforced HTTP client with request budgets and no redirect following."""
from __future__ import annotations

from dataclasses import dataclass
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .scope import Scope


@dataclass
class HttpResponse:
    url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    elapsed_seconds: float
    error: str | None = None

    @property
    def text(self) -> str:
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"
        for part in content_type.split(";")[1:]:
            if "charset=" in part.lower():
                charset = part.split("=", 1)[1].strip().strip('"') or "utf-8"
        return self.body.decode(charset, errors="replace")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SafeHttpClient:
    """Single-threaded HTTP client. HEAD/OPTIONS responses never read response bodies."""

    def __init__(self, scope: Scope, max_requests: int | None = None):
        self.scope = scope
        requested_limit = scope.max_requests if max_requests is None else max_requests
        self.max_requests = min(requested_limit, scope.max_requests)
        self.requests_made = 0
        self._last_request_at = 0.0
        self._opener = build_opener(_NoRedirect())

    def request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None) -> HttpResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("Only GET, HEAD, and OPTIONS are supported by the scanner.")
        self.scope.validate_url(url)
        if self.requests_made >= self.max_requests:
            raise RuntimeError(f"Request budget exhausted ({self.max_requests}).")

        wait_for = self.scope.request_delay_seconds - (time.monotonic() - self._last_request_at)
        if self._last_request_at and wait_for > 0:
            time.sleep(wait_for)

        request = Request(
            url,
            headers={
                "User-Agent": "BugFreeSniffle/0.3 (+authorized-security-assessment)",
                "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.5",
                **{str(k): str(v) for k, v in (headers or {}).items()},
            },
            method=method,
        )
        self.requests_made += 1
        started = time.monotonic()
        self._last_request_at = started
        try:
            with self._opener.open(request, timeout=self.scope.timeout_seconds) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                body = b""
                if method == "GET":
                    data = response.read(1_000_001)
                    body = data[:1_000_000]
                    error = "response body truncated" if len(data) > 1_000_000 else None
                else:
                    error = None
                return HttpResponse(url, response.status, headers, body,
                                    time.monotonic() - started, error)
        except HTTPError as exc:
            headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            body = b""
            if method == "GET":
                data = exc.read(1_000_001)
                body = data[:1_000_000]
            return HttpResponse(url, exc.code, headers, body,
                                time.monotonic() - started,
                                "redirect not followed" if 300 <= exc.code < 400 else None)
        except (URLError, TimeoutError, OSError) as exc:
            return HttpResponse(url, None, {}, b"", time.monotonic() - started, str(exc))

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        return self.request(url, "GET", headers=headers)

    def head(self, url: str) -> HttpResponse:
        return self.request(url, "HEAD")

    def options(self, url: str) -> HttpResponse:
        return self.request(url, "OPTIONS")
