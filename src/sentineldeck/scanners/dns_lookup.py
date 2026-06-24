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

import re
import subprocess
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


def resolve(name: str, record_type: str, timeout: float = 5.0) -> tuple[list[str], str]:
    """Resolve ``name``/``record_type`` and return ``(records, status)``."""
    if _HAS_DNSPYTHON:
        return _resolve_dnspython(name, record_type, timeout)
    return _resolve_subprocess(name, record_type, timeout)


def query_records(name: str, record_type: str, timeout: float = 5.0) -> list[str]:
    """Convenience wrapper returning only the records (best effort)."""
    return resolve(name, record_type, timeout)[0]


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
