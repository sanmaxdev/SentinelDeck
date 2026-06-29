import threading
import urllib.request
from http.server import ThreadingHTTPServer

from sentineldeck import dashboard
from sentineldeck.models import ScanReport


def _start_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard._make_handler(timeout=5))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def _get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
        return response.status, response.read().decode("utf-8")


def test_bind_returns_none_when_port_is_forbidden(monkeypatch):
    real = dashboard.ThreadingHTTPServer

    def fake(addr, handler):
        if addr[1] == 8765:
            raise PermissionError("WinError 10013")  # simulate a blocked port
        return real(addr, handler)

    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", fake)

    assert dashboard._bind("127.0.0.1", 8765, 5) is None
    httpd = dashboard._bind("127.0.0.1", 0, 5)
    assert httpd is not None
    httpd.server_close()


def test_serve_falls_back_to_a_free_port(monkeypatch):
    real = dashboard.ThreadingHTTPServer
    bound = {}

    def stop(self):  # so serve() returns instead of blocking on serve_forever
        raise KeyboardInterrupt

    monkeypatch.setattr(real, "serve_forever", stop)

    def fake(addr, handler):
        if addr[1] == 8765:
            raise PermissionError("WinError 10013")  # default port blocked
        server = real(addr, handler)
        bound["port"] = server.server_address[1]
        return server

    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", fake)

    rc = dashboard.serve(port=8765, open_browser=False)
    assert rc == 0
    assert bound["port"] != 8765  # fell back to a working port


def test_dashboard_serves_static_assets():
    httpd, port = _start_server()
    try:
        for path, needle in [("/", "SENTINEL"), ("/app.js", "EventSource"), ("/style.css", "--red")]:
            status, body = _get(port, path)
            assert status == 200
            assert needle in body
    finally:
        httpd.shutdown()


def test_dashboard_scan_streams_progress_and_report(monkeypatch):
    def fake_scan(domain, timeout=10, progress=None, active=False):
        if progress:
            progress("DNS resolution")
        return ScanReport(target=domain, generated_at="t", risk_score=10, grade="B", checks={}, findings=[])

    monkeypatch.setattr(dashboard, "scan_target", fake_scan)
    httpd, port = _start_server()
    try:
        _, body = _get(port, "/api/scan?domain=example.com")
    finally:
        httpd.shutdown()

    assert "event: progress" in body and "DNS resolution" in body
    assert "event: done" in body
    assert '"grade": "B"' in body


def test_dashboard_scan_rejects_invalid_domain():
    httpd, port = _start_server()
    try:
        _, body = _get(port, "/api/scan?domain=not%20a%20domain")
    finally:
        httpd.shutdown()

    assert "event: failed" in body
