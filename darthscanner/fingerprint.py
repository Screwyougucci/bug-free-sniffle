"""Passive software fingerprinting from public response metadata."""
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
]


def fingerprint_response(response: HttpResponse) -> list[SoftwareComponent]:
    """Return conservative version fingerprints; headers can be spoofed."""
    if response.status is None:
        return []
    sources = [
        ("Server", response.headers.get("server", "")),
        ("X-Powered-By", response.headers.get("x-powered-by", "")),
        ("Via", response.headers.get("via", "")),
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
