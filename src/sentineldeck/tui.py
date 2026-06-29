"""Terminal styling for the SentinelDeck CLI.

The SentinelDeck red/black identity, a branded home screen, and colored scan
summaries, rendered with plain ANSI truecolor and no third-party dependency.
Colour is enabled only when stdout is an interactive terminal and ``NO_COLOR``
is unset, so piped or redirected output (JSON, files) stays clean. On Windows
the virtual-terminal mode is enabled so the colours show in the standard
console.
"""
from __future__ import annotations

import os
import sys

from sentineldeck import __version__

# Truecolor palette, matching the HTML report and SVG theme.
RED = (220, 38, 38)        # accent / brand
BRIGHT = (239, 68, 68)
SOFT = (248, 113, 113)
WHITE = (245, 245, 247)
MUTED = (155, 155, 168)
DIM = (110, 110, 122)

GRADE_RGB = {
    "A": (34, 197, 94), "B": (132, 204, 22), "C": (245, 158, 11),
    "D": (249, 115, 22), "F": (239, 68, 68),
}
SEVERITY_RGB = {
    "critical": (220, 38, 38), "high": (244, 63, 94), "medium": (251, 146, 60),
    "low": (250, 204, 21), "info": (167, 139, 250),
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

RESET = "\033[0m"
_LINK = "github.com/sanmaxdev/SentinelDeck"

_color_cache: bool | None = None


def init_stream() -> None:
    """Make stdout/stderr UTF-8 so box-drawing renders and never crashes on a
    legacy console codepage. Safe to call once at startup; a no-op if it fails."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 - never fatal
            pass


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = getattr(ctypes, "windll").kernel32  # windll is Windows-only
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 - colour is a nicety, never fatal
        pass


def color_enabled() -> bool:
    global _color_cache
    if _color_cache is None:
        enabled = (
            os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
            and bool(getattr(sys.stdout, "isatty", lambda: False)())
        )
        if enabled:
            _enable_windows_vt()
        _color_cache = enabled
    return _color_cache


def fg(text: str, rgb: tuple[int, int, int], *, bold: bool = False, dim: bool = False) -> str:
    if not color_enabled():
        return text
    codes = []
    if bold:
        codes.append("1")
    if dim:
        codes.append("2")
    r, g, b = rgb
    codes.append(f"38;2;{r};{g};{b}")
    return f"\033[{';'.join(codes)}m{text}{RESET}"


def _rule(width: int = 58) -> str:
    return fg("─" * width, RED, dim=True)


def _heading(text: str) -> str:
    return fg(text, BRIGHT, bold=True)


# A compact 5-row block font for the letters in SENTINELDECK.
_BANNER_FONT = {
    "S": ("█████", "█    ", "█████", "    █", "█████"),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "T": ("█████", "  █  ", "  █  ", "  █  ", "  █  "),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
    "C": ("█████", "█    ", "█    ", "█    ", "█████"),
    "K": ("█   █", "█  █ ", "███  ", "█  █ ", "█   █"),
    " ": ("     ", "     ", "     ", "     ", "     "),
}


def ascii_banner(text: str = "SENTINELDECK", *, indent: str = "  ") -> str:
    """Render ``text`` as a red ASCII-art banner using the block font."""
    rows = ["", "", "", "", ""]
    for char in text.upper():
        glyph = _BANNER_FONT.get(char, _BANNER_FONT[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    return "\n".join(indent + fg(row.rstrip(), RED, bold=True) for row in rows)


def _logo() -> list[str]:
    name = fg("SentinelDeck", WHITE, bold=True) + "  " + fg(f"v{__version__}", DIM)
    tag = fg("Passive attack-surface radar", MUTED)
    return [
        ascii_banner(),
        "",
        "  " + name + fg("   ·   ", DIM) + tag,
    ]


def home_screen() -> str:
    cmds = [
        ("scan", "Run a safe passive scan against a domain"),
        ("dashboard", "Open the interactive web dashboard in your browser"),
        ("report", "Render a saved report as HTML, a score card, or a badge"),
        ("diff", "Compare two scans and show what changed"),
        ("monitor", "Scan on a schedule and alert on regressions"),
        ("checks", "List every check SentinelDeck performs"),
        ("explain", "Show the copy-paste fix for a finding id"),
        ("version", "Print the installed version"),
    ]
    examples = [
        "sentineldeck dashboard",
        "sentineldeck scan example.com --html report.html",
        "sentineldeck explain dmarc-missing",
    ]
    out: list[str] = ["", *_logo(), "", _rule(72), ""]

    out.append("  " + _heading("COMMANDS"))
    for name, desc in cmds:
        out.append("    " + fg(f"{name:<9}", SOFT, bold=True) + fg(desc, MUTED))
    out.append("")

    out.append("  " + _heading("QUICK START"))
    for ex in examples:
        out.append("    " + fg("$ ", DIM) + fg(ex, WHITE))
    out.append("")

    out.append("  " + _heading("TIP"))
    out.append("    " + fg("Every finding ships a copy-paste fix. Open the HTML report to", MUTED))
    out.append("    " + fg("use the interactive remediation simulator with a client.", MUTED))
    out.append("")

    out.append(_rule(72))
    out.append(
        "  " + fg("docs ", DIM) + fg(_LINK, SOFT)
        + fg("   ·   ", DIM) + fg("pip install -U sentineldeck", MUTED)
    )
    out.append("")
    return "\n".join(out)


def _severity_counts(report) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        if getattr(f, "suppressed", False):
            continue
        sev = f.severity.lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def render_scan_summary(report) -> str:
    grade = report.grade.upper()
    grade_rgb = GRADE_RGB.get(grade, MUTED)
    counts = _severity_counts(report)
    scored = [
        f for f in report.findings
        if not getattr(f, "suppressed", False) and f.severity.lower() != "info"
    ]

    out: list[str] = ["", "  " + fg(report.target, WHITE, bold=True), ""]
    out.append(
        "  " + fg(f" {grade} ", grade_rgb, bold=True)
        + fg(f"  grade {grade}", grade_rgb, bold=True)
        + fg("   ·   ", DIM)
        + fg(f"risk {report.risk_score}/100", WHITE)
        + fg("   ·   ", DIM)
        + fg(f"{sum(counts.values())} findings", MUTED)
    )
    out.append("")

    chips = [
        fg("•", SEVERITY_RGB[s]) + fg(f" {counts[s]} {s}", MUTED)
        for s in SEVERITY_ORDER if counts[s]
    ]
    if chips:
        out.append("  " + fg("FINDINGS  ", BRIGHT, bold=True) + "  ".join(chips))
        out.append("")

    tech = (getattr(report, "checks", {}) or {}).get("technologies", {}).get("detected", [])
    if tech:
        names = " · ".join(
            t["name"] + (f" {t['version']}" if t.get("version") else "") for t in tech[:6]
        )
        out.append("  " + fg("STACK     ", BRIGHT, bold=True) + fg(names, MUTED))
        out.append("")

    top = sorted(scored, key=lambda f: SEVERITY_ORDER.index(f.severity.lower()))[:5]
    for f in top:
        sev = f.severity.lower()
        out.append(
            "    " + fg(f"{f.severity.upper():<8}", SEVERITY_RGB.get(sev, MUTED), bold=True)
            + fg(f.title, WHITE)
        )
    if len(scored) > len(top):
        out.append("    " + fg(f"... and {len(scored) - len(top)} more", DIM))
    if not scored:
        out.append("    " + fg("No scored issues. Clean posture.", GRADE_RGB.get("A", MUTED)))
    out.append("")

    out.append(
        "  " + fg("Next  ", DIM)
        + fg("add --html report.html", SOFT)
        + fg("  to save the report with copy-paste fixes + the simulator", MUTED)
    )
    out.append("")
    return "\n".join(out)


def _stream_color(stream) -> bool:
    return (
        os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") != "dumb"
        and bool(getattr(stream, "isatty", lambda: False)())
    )


class ScanProgress:
    """Stream live, per-surface scan progress to a stream (stderr by default),
    so stdout stays clean for the report or JSON."""

    def __init__(self, target: str, stream=None) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.color = _stream_color(self.stream)
        if self.color:
            _enable_windows_vt()
        self._emit(
            "\n  " + self._paint("Scanning ", MUTED)
            + self._paint(target, WHITE, bold=True) + self._paint(" …", MUTED) + "\n"
        )

    def _paint(self, text: str, rgb: tuple[int, int, int], *, bold: bool = False) -> str:
        if not self.color:
            return text
        codes = ["1"] if bold else []
        r, g, b = rgb
        codes.append(f"38;2;{r};{g};{b}")
        return f"\033[{';'.join(codes)}m{text}{RESET}"

    def step(self, label: str) -> None:
        self._emit(
            "    " + self._paint("✓", (34, 197, 94), bold=True)
            + " " + self._paint(label, MUTED) + "\n"
        )

    def finish(self) -> None:
        self._emit("\n")

    def _emit(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except Exception:  # noqa: BLE001 - progress is cosmetic, never fatal
            pass


_CHECK_SURFACES = [
    ("DNS", ["Resolution", "CAA issuance control", "DNSSEC", "Nameserver redundancy",
             "IPv6 (AAAA) readiness", "DANE / TLSA"]),
    ("Email", ["MX", "SPF policy, lookups, multiples", "DMARC policy + coverage",
               "DKIM presence + key strength", "MTA-STS record + policy", "TLS-RPT", "BIMI"]),
    ("HTTP", ["HTTPS reachability", "HTTP to HTTPS redirect", "Security headers + value quality",
              "CORS policy", "Clickjacking / framing", "Cookie flags + SameSite", "security.txt"]),
    ("TLS", ["Trust + failure reason", "Expiry", "Protocol version", "Key strength",
             "Hostname match", "Protocol enumeration + Mozilla config grade", "Open ports (--active)"]),
    ("Attack surface", ["Certificate-transparency + passive-DNS subdomains",
                        "Sensitive subdomain labels", "Subdomain takeover"]),
    ("Recon", ["Technology fingerprint (CMS, framework, server, CDN)",
               "Vulnerable JavaScript libraries", "Cloud-storage (S3/GCS/Azure) exposure"]),
    ("Infrastructure", ["IP geolocation, ASN, hosting provider", "Full redirect chain",
                        "WAF / CDN detection", "robots.txt, sitemap, link & social-tag analysis"]),
    ("Threat intel", ["Typosquatting / lookalike domains", "Malware / phishing reputation",
                      "Wayback archive history"]),
    ("Domain", ["RDAP registration", "Newly-registered domain age"]),
]


def checks_screen() -> str:
    out: list[str] = [
        "", "  " + fg("SentinelDeck checks", WHITE, bold=True)
        + fg("   every scan, all passive", DIM), "", _rule(72), "",
    ]
    for surface, items in _CHECK_SURFACES:
        out.append("  " + _heading(surface.upper()))
        for item in items:
            out.append("    " + fg("•", RED) + " " + fg(item, MUTED))
        out.append("")
    out.append(_rule(72))
    out.append("  " + fg("explain any finding:  ", DIM)
               + fg("sentineldeck explain <finding-id>", SOFT))
    out.append("")
    return "\n".join(out)


def render_fix(finding_id: str, fix: dict) -> str:
    """Render a single remediation fix (used by the ``explain`` command)."""
    kind = fix.get("kind", "")
    out: list[str] = [
        "", "  " + fg(finding_id, BRIGHT, bold=True)
        + (fg(f"   [{kind}]", DIM) if kind else ""), "",
    ]
    if fix.get("title"):
        out.append("  " + fg(fix["title"], WHITE))
        out.append("")
    for line in fix.get("snippet", "").splitlines():
        out.append("    " + fg(line, MUTED))
    references = fix.get("references") or []
    if references:
        out.append("")
        out.append("  " + fg("ref  ", DIM) + fg(", ".join(references), SOFT))
    out.append("")
    return "\n".join(out)
