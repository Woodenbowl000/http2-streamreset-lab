#!/usr/bin/env python3
"""
dashboard — tiny stdlib web server for the stream-reset DoS lab.

Serves the single-page UI and proxies a handful of calls through to the
detector, so the browser only ever talks to one origin. No framework, no build
step: open http://localhost:8088 after `docker compose up`.
"""
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DETECTOR = os.environ.get("DETECTOR_URL", "http://detector:9130")
PORT = int(os.environ.get("DASHBOARD_PORT", "8088"))
HERE = os.path.dirname(os.path.abspath(__file__))


def proxy(method, path, body=None):
    url = DETECTOR + path
    data = body if body else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.read()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            try:
                self._send(200, proxy("GET", "/state"))
            except Exception as e:
                self._send(502, json.dumps({"error": str(e)}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        route = {
            "/api/mitigate": ("/mitigate", body),
            "/api/unmitigate": ("/unmitigate", body),
            "/api/mode": ("/mode", body),
            "/api/reset": ("/reset", body),
        }.get(self.path)
        if not route:
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            self._send(200, proxy("POST", route[0], route[1]))
        except Exception as e:
            self._send(502, json.dumps({"error": str(e)}))


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"dashboard on :{PORT} (proxying {DETECTOR})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
