#!/usr/bin/env python3
"""
dashboard — tiny stdlib web server for the stream-reset DoS lab.

Serves the single-page UI and proxies a handful of calls through to the
detector, so the browser only ever talks to one origin. No framework, no build
step: open http://localhost:8088 after `docker compose up`.
"""
import json
import os
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DETECTOR = os.environ.get("DETECTOR_URL", "http://detector:9130")
PORT = int(os.environ.get("DASHBOARD_PORT", "8088"))
HERE = os.path.dirname(os.path.abspath(__file__))

ATTACKER_IMAGE = os.environ.get("ATTACKER_IMAGE", "http2-streamreset-lab-attacker:latest")
ATTACKER_NETWORK = os.environ.get("ATTACKER_NETWORK", "h2lab-net")

# Fixed, known-safe scenario presets -- the dashboard only ever launches the
# attacker against the lab's own guard:8080 with parameters we've already
# exercised via scripts/scenario.sh. No user-supplied host/port/args reach
# `docker run`, so this can't be turned into an arbitrary command launcher.
RUN_PRESETS = {
    "rapid-reset": ["rapid-reset", "--host", "guard", "--port", "8080",
                    "--path", "/?ms=0", "--duration", "30", "--connections", "6"],
    "madeyoureset": ["madeyoureset", "--host", "guard", "--port", "8080",
                     "--path", "/?ms=500", "--duration", "20", "--connections", "3",
                     "--primitive", "zero-increment"],
    "legit": ["legit", "--host", "guard", "--port", "8080",
              "--path", "/?ms=200", "--duration", "20", "--connections", "6"],
}

_runs_lock = threading.Lock()
_runs = []  # most recent first: {"mode", "started_at", "proc", "status"}


def launch_attack(mode):
    args = RUN_PRESETS.get(mode)
    if not args:
        raise ValueError(f"unknown mode: {mode}")
    cmd = ["docker", "run", "--rm", "--network", ATTACKER_NETWORK, ATTACKER_IMAGE, *args]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with _runs_lock:
        _runs.insert(0, {"mode": mode, "started_at": time.time(), "proc": proc})
        del _runs[20:]
    return proc


def runs_status():
    with _runs_lock:
        out = []
        for r in _runs:
            rc = r["proc"].poll()
            out.append({
                "mode": r["mode"],
                "started_at": r["started_at"],
                "running": rc is None,
            })
        return out


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
        elif self.path == "/api/run/status":
            self._send(200, json.dumps(runs_status()))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        if self.path == "/api/run":
            try:
                mode = json.loads(body or b"{}").get("mode", "")
                launch_attack(mode)
                return self._send(200, json.dumps({"ok": True, "mode": mode}))
            except Exception as e:
                return self._send(400, json.dumps({"error": str(e)}))
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
