"""Typosquatting / lookalike-domain detection.

Generates plausible misspellings and homoglyph variants of a domain, then checks
which ones actually resolve. A registered, resolving lookalike is the
infrastructure phishing and brand-impersonation campaigns run on, so surfacing
them turns a single-domain scan into brand-protection. Permutation generation is
pure (tested offline); resolution uses the shared DoH-aware resolver.
"""
from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from sentineldeck.scanners.dns_lookup import resolve

Resolver = Callable[[str, str], "tuple[list[str], str]"]

_HOMOGLYPHS = {
    "o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5",
    "b": "6", "g": "9", "t": "7", "z": "2",
}
_SWAP_TLDS = ("com", "net", "org", "co", "io", "info", "biz", "online", "app", "xyz", "us", "site")
MAX_CANDIDATES = 40


def generate_permutations(domain: str) -> list[str]:
    """Return de-duplicated lookalike variants of ``domain``."""
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    sld, tld = parts[0], ".".join(parts[1:])
    out: set[str] = set()

    for i in range(len(sld)):  # omission
        out.add(sld[:i] + sld[i + 1:] + "." + tld)
    for i in range(len(sld)):  # repetition
        out.add(sld[:i] + sld[i] + sld[i:] + "." + tld)
    for i in range(len(sld) - 1):  # transposition
        out.add(sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:] + "." + tld)
    for i, ch in enumerate(sld):  # homoglyph
        if ch in _HOMOGLYPHS:
            out.add(sld[:i] + _HOMOGLYPHS[ch] + sld[i + 1:] + "." + tld)
    for i in range(1, len(sld)):  # hyphenation
        out.add(sld[:i] + "-" + sld[i:] + "." + tld)
    for swap in _SWAP_TLDS:  # TLD swap
        if swap != tld:
            out.add(sld + "." + swap)

    out.discard(domain)
    return sorted(x for x in out if all(part for part in x.split(".")))


def detect_typosquats(
    domain: str, resolver: Resolver = resolve, limit: int = MAX_CANDIDATES
) -> dict:
    """Resolve up to ``limit`` lookalike variants and return those that exist."""
    candidates = generate_permutations(domain)[:limit]
    if not candidates:
        return {"status": "ok", "checked": 0, "registered": [], "truncated": False}

    def _probe(candidate: str) -> dict | None:
        records, _ = resolver(candidate, "A")
        return {"domain": candidate, "resolves": True} if records else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [r for r in pool.map(_probe, candidates) if r]

    return {
        "status": "ok",
        "checked": len(candidates),
        "registered": sorted(results, key=lambda r: r["domain"]),
        "truncated": len(generate_permutations(domain)) > limit,
    }
