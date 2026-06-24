from __future__ import annotations

import re
import socket

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.removeprefix("https://").removeprefix("http://")
    value = value.split("/", 1)[0].split(":", 1)[0]
    if not DOMAIN_RE.match(value):
        raise ValueError(f"Invalid domain: {value!r}")
    return value


def resolve_domain(domain: str) -> dict:
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {"resolved": False, "addresses": [], "error": str(exc)}

    addresses = sorted({item[4][0] for item in infos})
    return {"resolved": bool(addresses), "addresses": addresses}
