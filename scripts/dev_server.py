#!/usr/bin/env python3
"""Dev server for the html-inspector app.

Serves the repo root as static files AND exposes a same-origin fetch
proxy at /fetch?url=... — the "campus-apphost option-1" lookup path in
local form. The SPA's proxy chain (js/mdn.js) prefers /fetch when
served over http(s), so page loads and the MDN fallback work without
the public CORS proxies.

Usage:  python scripts/dev_server.py [port]      (default port 8123)
Open:   http://127.0.0.1:<port>/

Stdlib only. Dev tool — NOT hardened for production deployment:
- redirects are followed without re-checking the SSRF blocklist
- no rate limiting; the 2 MB cap and the private-address block are on
"""
import ipaddress
import mimetypes
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 2_000_000
FETCH_TIMEOUT = 20
USER_AGENT = "Mozilla/5.0 (compatible; html-inspector-dev-proxy)"


def _blocked_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def proxy_fetch(url: str):
    """Server-side fetch with SSRF guards. Returns (status, body, ctype)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return 400, b"only http/https URLs are fetched", "text/plain"
    host = parsed.hostname or ""
    if not host:
        return 400, b"no host in URL", "text/plain"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        return 502, f"DNS lookup failed for {host}: {exc}".encode(), "text/plain"
    for info in infos:
        ip = info[4][0]
        if _blocked_ip(ip):
            return 403, f"blocked host {host} ({ip})".encode(), "text/plain"
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read(MAX_BYTES + 1)
            ctype = resp.headers.get("Content-Type") or "text/html; charset=utf-8"
            status = resp.status
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc).encode(), "text/plain"
    except Exception as exc:  # timeouts, refused, TLS…
        return 502, f"upstream fetch failed: {exc}".encode(), "text/plain"
    if len(data) > MAX_BYTES:
        return 502, b"upstream response exceeded the 2 MB cap", "text/plain"
    return status, data, ctype


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/fetch":
            qs = urllib.parse.parse_qs(parsed.query)
            url = (qs.get("url") or [""])[0]
            if not url:
                self._send(400, b"missing ?url=", "text/plain")
                return
            status, body, ctype = proxy_fetch(url)
            self._send(status, body, ctype)
            return
        self._serve_static(parsed.path)

    def _serve_static(self, path):
        rel = path.lstrip("/") or "index.html"
        target = (ROOT / rel).resolve()
        if ROOT not in target.parents and target != ROOT:
            self._send(403, b"forbidden", "text/plain")
            return
        if not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), ctype)

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"html-inspector dev server on http://127.0.0.1:{port}/ "
          f"(static: {ROOT}, proxy: /fetch?url=...)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
