"""A zero-dependency local web dashboard for SentinelDeck.

``sentineldeck dashboard`` starts a small HTTP server bound to localhost, opens
the browser, and serves a single-page app. Entering a domain runs the same
passive ``scan_domain`` used by the CLI; progress is streamed live to the page
over Server-Sent Events and the finished report renders as a grid of cards.

Only the Python standard library is used, so ``pip install sentineldeck`` stays
self-contained: no Node build, no extra dependencies. The server binds to
127.0.0.1 by default and is never exposed to the network.
"""
from __future__ import annotations

import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from sentineldeck import __version__
from sentineldeck.scanner import scan_target
from sentineldeck.scanners.target import classify_target

WEBUI_DIR = Path(__file__).parent / "webui"
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _make_handler(timeout: int):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = f"SentinelDeck/{__version__}"

        def log_message(self, *args):  # noqa: D401 - keep the console quiet
            return

        def do_GET(self):  # noqa: N802 - http.server API
            path = urlparse(self.path).path
            if path == "/api/scan":
                self._scan()
            elif path in ("/", "/index.html"):
                self._serve_asset("index.html")
            elif path.lstrip("/") in {"app.js", "style.css"}:
                self._serve_asset(path.lstrip("/"))
            else:
                self.send_error(404)

        def _serve_asset(self, name: str) -> None:
            asset = WEBUI_DIR / name
            if not asset.is_file():
                self.send_error(404)
                return
            body = asset.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", _CONTENT_TYPES.get(asset.suffix, "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _sse_open(self) -> None:
            # Close the connection when the scan ends so the client (and urllib in
            # tests) sees the stream finish; the page closes its EventSource on the
            # done/failed event, so the browser never reconnects.
            self.close_connection = True
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()

        def _emit(self, event: str, data: dict) -> None:
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
            self.wfile.write(payload)
            self.wfile.flush()

        def _scan(self) -> None:
            params = parse_qs(urlparse(self.path).query)
            target = (params.get("domain") or [""])[0].strip()
            active = (params.get("active") or ["0"])[0] == "1"
            self._sse_open()
            try:
                classify_target(target)
            except ValueError as exc:
                self._emit("failed", {"message": str(exc)})
                return
            try:
                report = scan_target(
                    target, timeout=timeout, active=active,
                    progress=lambda label: self._emit("progress", {"label": label}),
                )
                self._emit("done", report.to_dict())
            except Exception as exc:  # noqa: BLE001 - report the failure to the page
                self._emit("failed", {"message": str(exc)})

    return DashboardHandler


def _bind(host: str, port: int, timeout: int) -> ThreadingHTTPServer | None:
    """Try to bind the dashboard server to ``port``; return None if unavailable."""
    try:
        return ThreadingHTTPServer((host, port), _make_handler(timeout))
    except OSError:
        # Port in use by another app, or blocked/reserved by the OS (e.g. Windows
        # WinError 10013 / Hyper-V reserved ranges). Caller falls back.
        return None


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True, timeout: int = 10) -> int:
    """Run the dashboard server until interrupted. Returns a process exit code."""
    # The requested port may be taken or blocked, so fall back to other ports and
    # finally an OS-assigned one (0) instead of crashing with a stack trace.
    candidates: list[int] = []
    for candidate in (port, 8765, 8780, 8800, 8888, 9000, 0):
        if candidate not in candidates:
            candidates.append(candidate)

    httpd = next((s for s in (_bind(host, c, timeout) for c in candidates) if s is not None), None)
    if httpd is None:
        print(
            f"Could not start the dashboard: no free port was available "
            f"(tried {', '.join(str(c) for c in candidates if c)}). "
            f"Free a port or pass --port.",
            file=sys.stderr,
        )
        return 1

    actual = httpd.server_address[1]
    if actual != port:
        print(f"Port {port} was unavailable, so the dashboard is using port {actual} instead.")
    url = f"http://{host}:{actual}"
    print(f"SentinelDeck dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - headless environments have no browser
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        httpd.server_close()
    return 0
