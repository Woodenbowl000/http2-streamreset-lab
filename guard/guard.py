#!/usr/bin/env python3
"""
guard — an L4 (TCP) proxy that sits in front of the victim and is the lab's
mitigation enforcement point.

All lab traffic (legitimate load AND attack) connects to the guard, which
forwards raw bytes to the victim. Because it operates at the TCP layer it passes
HTTP/2 (h2c) through transparently without parsing frames. Its one job beyond
forwarding is a source-IP blocklist:

    * POST /block    {"ip": "..."}      add a source to the blocklist
    * POST /unblock  {"ip": "..."}      remove a source
    * POST /clear                       empty the blocklist
    * GET  /blocklist                   current blocklist (JSON)
    * GET  /metrics                     Prometheus metrics

This realises the proposal's Tier-1 mitigation: once the detection service
decides a source is flooding resets, it calls /block and the guard drops all
current and future connections from that source for a cooldown window — the
"terminate the connection and blocklist the source" action, demonstrable live
from the dashboard's Mitigate button.
"""
import asyncio
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VICTIM_HOST = os.environ.get("VICTIM_HOST", "victim")
VICTIM_PORT = int(os.environ.get("VICTIM_PORT", "8080"))
LISTEN_PORT = int(os.environ.get("GUARD_LISTEN_PORT", "8080"))
CONTROL_PORT = int(os.environ.get("GUARD_CONTROL_PORT", "9120"))

_lock = threading.Lock()
_blocklist = {}            # ip -> expiry_epoch (0 = permanent until cleared)
_stats = {
    "connections_total": 0,
    "blocked_connections_total": 0,
    "active_connections": 0,
    "bytes_c2s": 0,
    "bytes_s2c": 0,
}
_per_source = {}           # ip -> connection count
_active = {}               # ip -> set of (client_writer, victim_writer)
_loop = None               # asyncio loop ref, set when the proxy starts


def _register(ip, pair):
    with _lock:
        _active.setdefault(ip, set()).add(pair)


def _unregister(ip, pair):
    with _lock:
        s = _active.get(ip)
        if s:
            s.discard(pair)
            if not s:
                _active.pop(ip, None)


def force_close_ip(ip):
    """Close all live proxied connections from ip (called from the control thread)."""
    if _loop is None:
        return
    with _lock:
        pairs = list(_active.get(ip, set()))

    def _close():
        for cw, vw in pairs:
            for w in (cw, vw):
                try:
                    w.close()
                except Exception:
                    pass

    try:
        _loop.call_soon_threadsafe(_close)
    except Exception:
        pass


def _is_blocked(ip: str) -> bool:
    with _lock:
        exp = _blocklist.get(ip)
        if exp is None:
            return False
        if exp != 0 and exp < time.time():
            del _blocklist[ip]
            return False
        return True


async def _pump(reader, writer, counter_key):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            with _lock:
                _stats[counter_key] += len(data)
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(client_reader, client_writer):
    peer = client_writer.get_extra_info("peername")
    ip = peer[0] if peer else "?"
    with _lock:
        _stats["connections_total"] += 1
        _per_source[ip] = _per_source.get(ip, 0) + 1
    if _is_blocked(ip):
        with _lock:
            _stats["blocked_connections_total"] += 1
        try:
            client_writer.close()
        except Exception:
            pass
        return
    try:
        victim_reader, victim_writer = await asyncio.open_connection(VICTIM_HOST, VICTIM_PORT)
    except Exception:
        try:
            client_writer.close()
        except Exception:
            pass
        return
    pair = (client_writer, victim_writer)
    _register(ip, pair)
    with _lock:
        _stats["active_connections"] += 1
    try:
        await asyncio.gather(
            _pump(client_reader, victim_writer, "bytes_c2s"),
            _pump(victim_reader, client_writer, "bytes_s2c"),
        )
    finally:
        _unregister(ip, pair)
        with _lock:
            _stats["active_connections"] = max(0, _stats["active_connections"] - 1)


async def proxy_main():
    global _loop
    _loop = asyncio.get_running_loop()
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    print(f"guard L4 proxy :{LISTEN_PORT} -> {VICTIM_HOST}:{VICTIM_PORT}", flush=True)
    async with server:
        await server.serve_forever()


# --- control / metrics HTTP server (stdlib, runs in a thread) ----------------
class Control(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def do_GET(self):
        if self.path == "/blocklist":
            with _lock:
                self._json(200, {"blocklist": dict(_blocklist), "per_source": dict(_per_source)})
        elif self.path == "/metrics":
            with _lock:
                s = dict(_stats)
                bl = len(_blocklist)
            lines = [
                "# HELP guard_connections_total TCP connections accepted",
                "# TYPE guard_connections_total counter",
                f"guard_connections_total {s['connections_total']}",
                "# HELP guard_blocked_connections_total connections dropped by blocklist",
                "# TYPE guard_blocked_connections_total counter",
                f"guard_blocked_connections_total {s['blocked_connections_total']}",
                "# HELP guard_active_connections currently proxied connections",
                "# TYPE guard_active_connections gauge",
                f"guard_active_connections {s['active_connections']}",
                "# HELP guard_blocklist_size blocked sources",
                "# TYPE guard_blocklist_size gauge",
                f"guard_blocklist_size {bl}",
                "# HELP guard_bytes_c2s_total client->server bytes",
                "# TYPE guard_bytes_c2s_total counter",
                f"guard_bytes_c2s_total {s['bytes_c2s']}",
                "# HELP guard_bytes_s2c_total server->client bytes",
                "# TYPE guard_bytes_s2c_total counter",
                f"guard_bytes_s2c_total {s['bytes_s2c']}",
            ]
            body = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/block":
            data = self._read_json()
            ip = data.get("ip")
            cooldown = float(data.get("cooldown", 0))
            if not ip:
                return self._json(400, {"error": "ip required"})
            exp = 0 if cooldown <= 0 else time.time() + cooldown
            with _lock:
                _blocklist[ip] = exp
            # Tier-1: terminate the source's live connections immediately, not
            # just future ones, so the flood stops at once.
            force_close_ip(ip)
            return self._json(200, {"blocked": ip, "expires": exp})
        if self.path == "/unblock":
            data = self._read_json()
            ip = data.get("ip")
            with _lock:
                _blocklist.pop(ip, None)
            return self._json(200, {"unblocked": ip})
        if self.path == "/clear":
            with _lock:
                _blocklist.clear()
            return self._json(200, {"cleared": True})
        return self._json(404, {"error": "not found"})


def run_control():
    httpd = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), Control)
    print(f"guard control/metrics :{CONTROL_PORT}", flush=True)
    httpd.serve_forever()


def main():
    threading.Thread(target=run_control, daemon=True).start()
    asyncio.run(proxy_main())


if __name__ == "__main__":
    main()
