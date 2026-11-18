"""Passive server/software fingerprinting from public response metadata."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re

from .http_client import HttpResponse


@dataclass(frozen=True)
class SoftwareComponent:
    name: str
    version: str
    cpe: str
    source: str
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return asdict(self)


# Keep patterns conservative: emit a CPE only where product identity is clear.
# A response header is not proof of the actual installed build.
_PATTERNS = [
    (re.compile(r"\bnginx[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "nginx", "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bApache[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Apache HTTP Server", "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bPHP[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "PHP", "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bMicrosoft-IIS[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)*)", re.I),
     "Microsoft IIS", "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bOpenSSL[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "OpenSSL", "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bOpenResty[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "OpenResty", "cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bCaddy[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Caddy", "cpe:2.3:a:caddyserver:caddy:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\blighttpd[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "lighttpd", "cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bHAProxy[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "HAProxy", "cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\benvoy[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Envoy Proxy", "cpe:2.3:a:envoyproxy:envoy:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bTraefik[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Traefik", "cpe:2.3:a:traefik:traefik:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bJetty\(?[/ ]?([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Eclipse Jetty", "cpe:2.3:a:eclipse:jetty:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bApache Tomcat[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Apache Tomcat", "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bgunicorn[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Gunicorn", "cpe:2.3:a:gunicorn:gunicorn:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\buvicorn[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Uvicorn", "cpe:2.3:a:encode:uvicorn:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bVarnish[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Varnish Cache", "cpe:2.3:a:varnish-software:varnish_cache:{version}:*:*:*:*:*:*:*"),
    (re.compile(r"\bNode\.js[/ ]([0-9]+(?:\.[0-9A-Za-z_-]+)+)", re.I),
     "Node.js", "cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*"),
]


def fingerprint_response(response: HttpResponse) -> list[SoftwareComponent]:
    """Return versioned software candidates; untrusted headers may be spoofed."""
    if response.status is None:
        return []
    sources = [
        ("Server", response.headers.get("server", "")),
        ("X-Powered-By", response.headers.get("x-powered-by", "")),
        ("Via", response.headers.get("via", "")),
        ("X-AspNet-Version", response.headers.get("x-aspnet-version", "")),
        ("X-AspNetMvc-Version", response.headers.get("x-aspnetmvc-version", "")),
        ("X-Runtime", response.headers.get("x-runtime", "")),
    ]
    found: dict[str, SoftwareComponent] = {}
    for source, value in sources:
        for pattern, name, cpe_template in _PATTERNS:
            match = pattern.search(value)
            if not match:
                continue
            version = match.group(1)
            component = SoftwareComponent(
                name=name,
                version=version,
                cpe=cpe_template.format(version=version),
                source=f"{source}: {value[:180]}",
                confidence="medium",
            )
            found[component.cpe] = component
    return list(found.values())
