#!/usr/bin/env python3
"""serve.py - a small web server for the built site (site/public). Standard library only, made for a Raspberry Pi.

    python3 site/serve.py                          # http://0.0.0.0:8080, serves site/public
    python3 site/serve.py --port 80 --dir /home/pi/bb/site/public

What it adds to a plain file server (the reason this file exists):
    * CORS header (Access-Control-Allow-Origin: *), so scripts and other web pages can call the API
    * correct types: .txt as text/plain (so `curl .../subdomains.txt | httpx` and a browser both work), .json as application/json
    * gzip on the fly (cached in memory), because scope/subdomains.json is a few MB and the lists compress ~5x
    * ETag / 304 answers, so a phone does not download the same file twice; /healthz for monitoring
    * /api and /api/v1/ answer with the endpoint list (index.json)
It only reads files below --dir (no directory listing, no path tricks). For a public internet site put nginx or Caddy in front.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import mimetypes
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".json": "application/json; charset=utf-8", ".txt": "text/plain; charset=utf-8", ".svg": "image/svg+xml",
         ".tsv": "text/tab-separated-values; charset=utf-8", ".webmanifest": "application/manifest+json", ".ico": "image/x-icon"}
COMPRESSIBLE = (".html", ".js", ".css", ".json", ".txt", ".svg", ".tsv", ".webmanifest")
_cache: dict = {}                 # (path, mtime, size) -> (etag, raw bytes, gzip bytes); small files and big ones alike
_lock = threading.Lock()
CACHE_LIMIT = 200 * 1024 * 1024   # bytes of cached answers (raw + gzip)
_cached_bytes = 0


class Handler(BaseHTTPRequestHandler):
    root: Path = HERE / "public"
    server_version = "bbsite/1"

    def log_message(self, fmt, *args):                 # one short line per request
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _resolve(self) -> Path | None:
        path = unquote(urlsplit(self.path).path)
        if path in ("/api", "/api/", "/api/v1", "/api/v1/"):
            path = "/api/v1/index.json"
        if path.endswith("/"):
            path += "index.html"
        target = (self.root / path.lstrip("/")).resolve()
        try:
            target.relative_to(self.root.resolve())
        except ValueError:
            return None
        return target if target.is_file() else None

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain; charset=utf-8", extra: dict | None = None, head: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head and body:
            self.wfile.write(body)

    def _serve(self, head: bool):
        global _cached_bytes
        if urlsplit(self.path).path == "/healthz":
            return self._send(200, b"ok\n", head=head)
        f = self._resolve()
        if f is None:
            return self._send(404, b"not found\n", head=head)
        st = f.stat()
        key = (str(f), st.st_mtime_ns, st.st_size)
        with _lock:
            hit = _cache.get(key)
        if hit is None:
            raw = f.read_bytes()
            gz = gzip.compress(raw, 6) if f.suffix in COMPRESSIBLE and len(raw) > 1024 else b""
            hit = (hashlib.md5(raw).hexdigest()[:16], raw, gz)
            with _lock:
                if _cached_bytes + len(raw) + len(gz) < CACHE_LIMIT:
                    _cache[key] = hit
                    _cached_bytes += len(raw) + len(gz)
        etag, raw, gz = hit
        ctype = TYPES.get(f.suffix) or mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        # the UI files change when you update the project: always revalidate (cheap, 304). Data files: reuse for a minute.
        cache = "no-cache" if f.suffix in (".html", ".js", ".css") else "public, max-age=60"
        extra = {"ETag": f'"{etag}"', "Cache-Control": cache, "Vary": "Accept-Encoding"}
        if f.suffix == ".html":
            # The data contains text written by strangers (program scope pages). The page escapes it, and this header is the
            # second lock: only scripts from this site may run, nothing is loaded from other sites, nothing can frame it.
            extra["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                                "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            extra["Referrer-Policy"] = "no-referrer"
        if self.headers.get("If-None-Match") == f'"{etag}"':
            return self._send(304, b"", ctype, extra, head=True)
        if gz and "gzip" in (self.headers.get("Accept-Encoding") or ""):
            extra["Content-Encoding"] = "gzip"
            return self._send(200, gz, ctype, extra, head)
        return self._send(200, raw, ctype, extra, head)

    def do_GET(self):
        self._serve(False)

    def do_HEAD(self):
        self._serve(True)

    def do_OPTIONS(self):
        self._send(204, b"", extra={"Access-Control-Allow-Methods": "GET, HEAD, OPTIONS", "Access-Control-Allow-Headers": "*"})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Serve the built site and its static API")
    ap.add_argument("--dir", type=Path, default=HERE / "public")
    ap.add_argument("--host", default=os.environ.get("BB_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("BB_PORT", "8080")))
    a = ap.parse_args(argv)
    if not (a.dir / "index.html").is_file():
        print(f"error: {a.dir}/index.html not found. Run: python3 site/build_site.py", file=sys.stderr)
        return 2
    Handler.root = a.dir
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    print(f"serving {a.dir} on http://{a.host}:{a.port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
