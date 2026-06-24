from __future__ import annotations

import re
import subprocess
from collections.abc import Callable

DnsQuery = Callable[[str, str], str]


def query_dns(name: str, record_type: str) -> str:
    """Query DNS using common system tools without adding runtime dependencies."""
    commands = [
        ["dig", "+short", record_type, name],
        ["host", "-t", record_type, name],
    ]
    for command in commands:
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and completed.stdout.strip():
            return completed.stdout
    return ""


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


def extract_spf_policy(record: str | None) -> str | None:
    if not record:
        return None
    mechanisms = record.lower().split()
    for mechanism in ("-all", "~all", "?all", "+all"):
        if mechanism in mechanisms:
            return mechanism
    return None


def extract_dmarc_policy(record: str | None) -> str | None:
    if not record:
        return None
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.lower() == "p":
            return value.strip().lower() or None
    return None


def analyze_email_security(domain: str, query: DnsQuery = query_dns) -> dict:
    mx_records = parse_mx_records(query(domain, "MX"))
    txt_records = parse_txt_records(query(domain, "TXT"))
    dmarc_records = parse_txt_records(query(f"_dmarc.{domain}", "TXT"))

    spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
    dmarc_policy_records = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    spf_record = spf_records[0] if spf_records else None
    dmarc_record = dmarc_policy_records[0] if dmarc_policy_records else None

    return {
        "mx": {"present": bool(mx_records), "records": mx_records},
        "spf": {
            "present": bool(spf_records),
            "records": spf_records,
            "policy": extract_spf_policy(spf_record),
        },
        "dmarc": {
            "present": bool(dmarc_policy_records),
            "records": dmarc_policy_records,
            "policy": extract_dmarc_policy(dmarc_record),
        },
    }
