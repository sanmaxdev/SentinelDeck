"""In-process DNS resolution.

Email-security accuracy hinges on reliable DNS. The original implementation
shelled out to ``dig``/``host``, which silently returns nothing when those
binaries are absent (containers, serverless, many CI images) — making the
scanner report SPF/DMARC/MX as *missing* when they are actually fine.

This module resolves records in-process with ``dnspython`` when available and
only falls back to the subprocess approach when it is not. ``query_records``
returns a list of clean record strings; the resolver status is exposed
separately so callers can tell "no such record" apart from "could not resolve".
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

try:  # pragma: no cover - import guard
    import dns.exception
    import dns.resolver

    _HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - exercised only without dnspython
    _HAS_DNSPYTHON = False

# Resolver status values returned by :func:`resolve`.
OK = "ok"  # the query executed (zero or more records)
NXDOMAIN = "nxdomain"  # the name authoritatively does not exist
ERROR = "error"  # the resolver could not be reached / timed out

USER_AGENT = "SentinelDeck/0.1"
# Google's JSON DNS-over-HTTPS endpoint, used only as a fallback over port 443.
DOH_ENDPOINT = "https://dns.google/resolve"
# Numeric RR type codes, used to keep only answers of the requested type (DoH
# responses can include CNAME hops and other records in the Answer section).
DOH_TYPE_CODES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
    "TXT": 16, "AAAA": 28, "DNSKEY": 48, "CAA": 257,
}

# A DoH fetcher takes (name, record_type, timeout) and returns the parsed JSON
# response, or None when the request fails. Injectable for offline testing.
DohFetcher = Callable[[str, str, float], "dict[str, Any] | None"]


def resolve(
    name: str,
    record_type: str,
    timeout: float = 5.0,
    *,
    doh_fetcher: DohFetcher | None = None,
    enable_doh: bool = True,
) -> tuple[list[str], str]:
    """Resolve ``name``/``record_type`` and return ``(records, status)``.

    Direct port-53 DNS is blocked on some networks (corporate egress filters,
    captive portals, locked-down hotspots). When the direct query cannot reach a
    resolver at all, we fall back to DNS-over-HTTPS on port 443 so that MX, SPF,
    DMARC, CAA, and DNSKEY checks still resolve instead of degrading to
    *unverified*. The fallback never overrides an authoritative answer: it runs
    only when the direct path returns ``ERROR``.
    """
    records, status = _resolve_direct(name, record_type, timeout)
    if status == ERROR and enable_doh:
        return _resolve_doh(name, record_type, timeout, doh_fetcher or _doh_fetch)
    return records, status


def _resolve_direct(name: str, record_type: str, timeout: float) -> tuple[list[str], str]:
    if _HAS_DNSPYTHON:
        return _resolve_dnspython(name, record_type, timeout)
    return _resolve_subprocess(name, record_type, timeout)


def query_records(name: str, record_type: str, timeout: float = 5.0) -> list[str]:
    """Convenience wrapper returning only the records (best effort)."""
    return resolve(name, record_type, timeout)[0]


class Resolver:
    """A per-scan resolver that fails over to DNS-over-HTTPS quickly.

    The plain :func:`resolve` pays the full DNS timeout on *every* lookup before
    falling back to DoH. On a port-53-blocked network where every query times
    out, a single scan makes ~17 lookups and waits the timeout each time. This
    wrapper remembers the first hard failure and then routes subsequent lookups
    straight to DoH, so a blocked scan pays the direct timeout once instead of
    once per record. It is safe to share across the threads of one scan.

    Correctness is preserved: DoH returns authoritative answers, the breaker
    trips only on a hard ``ERROR`` (never on an authoritative reply), and if DoH
    later fails the lookup retries the direct path.
    """

    def __init__(
        self,
        timeout: float = 5.0,
        *,
        doh_fetcher: DohFetcher | None = None,
        enable_doh: bool = True,
    ) -> None:
        self.timeout = timeout
        self._doh_fetcher = doh_fetcher or _doh_fetch
        self._enable_doh = enable_doh
        self._direct_blocked = False
        self._lock = threading.Lock()

    def __call__(self, name: str, record_type: str) -> tuple[list[str], str]:
        if self._enable_doh and self._tripped():
            records, status = _resolve_doh(name, record_type, self.timeout, self._doh_fetcher)
            if status != ERROR:
                return records, status
            # DoH itself failed; fall through and retry the direct path.
        records, status = _resolve_direct(name, record_type, self.timeout)
        if status == ERROR and self._enable_doh:
            self._trip()
            return _resolve_doh(name, record_type, self.timeout, self._doh_fetcher)
        return records, status

    def _tripped(self) -> bool:
        with self._lock:
            return self._direct_blocked

    def _trip(self) -> None:
        with self._lock:
            self._direct_blocked = True


def _resolve_dnspython(name: str, record_type: str, timeout: float) -> tuple[list[str], str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    # Long TXT records (SPF/DKIM) often exceed the UDP path; on timeout we retry
    # once over TCP before treating the lookup as a genuine failure.
    for use_tcp in (False, True):
        try:
            answers = resolver.resolve(name, record_type, raise_on_no_answer=True, tcp=use_tcp)
        except dns.resolver.NXDOMAIN:
            return [], NXDOMAIN
        except dns.resolver.NoAnswer:
            return [], OK
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            continue
        except dns.exception.DNSException:
            return [], ERROR
        return _format_answers(answers, record_type), OK
    return [], ERROR


def _format_answers(answers: Any, record_type: str) -> list[str]:
    records: list[str] = []
    for rdata in answers:
        if record_type == "TXT":
            records.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        elif record_type == "MX":
            records.append(f"{rdata.preference} {rdata.exchange.to_text()}")
        else:
            records.append(rdata.to_text())
    return records


def _doh_fetch(name: str, record_type: str, timeout: float) -> dict[str, Any] | None:
    url = f"{DOH_ENDPOINT}?name={urllib.parse.quote(name)}&type={urllib.parse.quote(record_type)}"
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - any failure simply means no DoH answer
        return None


def _resolve_doh(
    name: str, record_type: str, timeout: float, fetcher: DohFetcher
) -> tuple[list[str], str]:
    data = fetcher(name, record_type, timeout)
    if not data:
        return [], ERROR
    status_code = data.get("Status")
    if status_code == 3:  # NXDOMAIN
        return [], NXDOMAIN
    if status_code != 0:  # any non-NOERROR rcode: treat as unresolved
        return [], ERROR
    wanted = DOH_TYPE_CODES.get(record_type)
    records = [
        _format_doh_record(record_type, answer.get("data", ""))
        for answer in data.get("Answer", [])
        if wanted is None or answer.get("type") == wanted
    ]
    return [record for record in records if record], OK


def _format_doh_record(record_type: str, data: str) -> str:
    data = data.strip()
    if record_type == "TXT":
        # DoH returns TXT data quoted, and long records as adjacent quoted
        # chunks; strip the quotes and concatenate to match the dnspython output.
        parts = re.findall(r'"([^"]*)"', data)
        return "".join(parts) if parts else data.strip('"')
    return data


def _resolve_subprocess(name: str, record_type: str, timeout: float) -> tuple[list[str], str]:
    commands = [
        ["dig", "+short", record_type, name],
        ["host", "-t", record_type, name],
    ]
    ran = False
    for command in commands:
        try:
            completed = subprocess.run(
                command, check=False, capture_output=True, text=True, timeout=timeout
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        ran = True
        if completed.returncode == 0 and completed.stdout.strip():
            if record_type == "TXT":
                return parse_txt_records(completed.stdout), OK
            if record_type == "MX":
                return parse_mx_records(completed.stdout), OK
            return [line.strip() for line in completed.stdout.splitlines() if line.strip()], OK
    # No binary available at all -> we genuinely could not resolve.
    return [], OK if ran else ERROR


def parse_txt_records(output: str) -> list[str]:
    records: list[str] = []
    for line in output.splitlines():
        parts = re.findall(r'"([^"]*)"', line)
        if parts:
            records.append("".join(parts).strip())
        elif line.strip():
            records.append(line.strip())
    return records


def parse_mx_records(output: str) -> list[str]:
    records: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if " mail is handled by " in line:
            records.append(line.split(" mail is handled by ", 1)[1])
        else:
            records.append(line)
    return records
