#!/usr/bin/env python3
"""
guard — an L4 (TCP) proxy that sits in front of the victim and is the lab's
mitigation enforcement point.

All lab traffic (legitimate load AND attack) connects to the guard, which
forwards raw bytes to the victim unmodified -- it never buffers, delays, or
rewrites anything (bytes are proxied as they arrive; frames are only counted
on the side, read-only). Its one job beyond forwarding is a source-IP
blocklist:

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

Per-source attack attribution: alongside relaying bytes, the guard does a
best-effort, read-only scan of each connection's HTTP/2 frames (both
directions) to count RST_STREAM frames per source IP, split by direction:
  - client -> victim RST_STREAM  = that source flooding client resets
    (the Rapid Reset / CVE-2023-44487 signal, attributed per IP)
  - victim -> client RST_STREAM  = that source triggering server-side resets
    (the MadeYouReset / CVE-2025-8671 signal, attributed per IP)
This lets the detector target mitigation at whichever source is actually
causing *each specific* attack pattern, instead of only "whoever holds the
most live connections" (which can't tell the two attacks apart). The scan is
advisory only: a parse error or non-HTTP/2 traffic just stops counting for
that connection -- it can never block, alter, or delay the proxied bytes.
"""
import asyncio
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RST_STREAM_FRAME_TYPE = 0x3
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_SCAN_BUFFER = 1_000_000  # safety cap: abandon counting for this connection
                             # rather than buffer unbounded non-HTTP/2 traffic

# --- Experimental: connection-scoped inline mitigation -----------------------
# OPT-IN (GUARD_INLINE_MITIGATION=true), default OFF so the verified source-IP
# blocklist path is byte-for-byte unchanged. When enabled, the guard enforces a
# per-connection RST_STREAM budget itself: a single connection that churns more
# than GUARD_CONN_RESET_BUDGET resets (either direction) is served a forceful
# GOAWAY(ENHANCE_YOUR_CALM) and torn down, without a detector round-trip and
# without any source-IP attribution. This is the per-connection "how useful is
# this connection" mitigation the Rapid Reset disclosures recommend, and because
# it acts at connection granularity it also covers MadeYouReset, whose
# server-side resets cannot be attributed per source behind an L4 proxy.
INLINE_MITIGATION = os.environ.get("GUARD_INLINE_MITIGATION", "false").lower() == "true"
CONN_RESET_BUDGET = int(os.environ.get("GUARD_CONN_RESET_BUDGET", "100"))
# A complete HTTP/2 GOAWAY frame (length 8, type 0x07, flags 0, stream 0),
# last-stream-id 0, error code 0x0b = ENHANCE_YOUR_CALM.
GOAWAY_ENHANCE_YOUR_CALM = (
    b"\x00\x00\x08\x07\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x0b"
)


class H2ResetScanner:
    """Incrementally scans a one-directional raw byte stream for HTTP/2
    RST_STREAM frames. Stateful across reads (frames split across TCP
    packets), best-effort, and side-effect-free: feed() only ever returns a
    count, it never raises and never touches the bytes it's given."""

    __slots__ = ("buf", "preface_checked", "abandoned")

    def __init__(self):
        self.buf = b""
        self.preface_checked = False
        self.abandoned = False

    def feed(self, data: bytes) -> int:
        if self.abandoned:
            return 0
        try:
            self.buf += data
            count = 0
            if not self.preface_checked:
                if len(self.buf) < len(H2_PREFACE):
                    if not H2_PREFACE.startswith(self.buf):
                        self.preface_checked = True
                    else:
                        return 0  # wait for more bytes to confirm/deny preface
                else:
                    self.preface_checked = True
                    if self.buf.startswith(H2_PREFACE):
                        self.buf = self.buf[len(H2_PREFACE):]
            while len(self.buf) >= 9:
                length = int.from_bytes(self.buf[0:3], "big")
                ftype = self.buf[3]
                total = 9 + length
                if len(self.buf) < total:
                    if total > MAX_SCAN_BUFFER:
                        self.abandoned = True
                        self.buf = b""
                    break
                if ftype == RST_STREAM_FRAME_TYPE:
                    count += 1
                self.buf = self.buf[total:]
            if len(self.buf) > MAX_SCAN_BUFFER:
                self.abandoned = True
                self.buf = b""
            return count
        except Exception:
            self.abandoned = True
            self.buf = b""
            return 0

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
    "inline_mitigated_total": 0,   # connections torn down by inline mitigation
}
_per_source = {}           # ip -> connection count (lifetime total)
_active = {}               # ip -> set of (client_writer, victim_writer)
_client_reset_per_source = {}  # ip -> lifetime count of client->victim RST_STREAM
_server_reset_per_source = {}  # ip -> lifetime count of victim->client RST_STREAM
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


async def _pump(reader, writer, counter_key, scanner=None, reset_counts=None, ip=None,
                conn=None, direction=None, client_writer=None, victim_writer=None):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            n_rst = scanner.feed(data) if scanner is not None else 0
            with _lock:
                _stats[counter_key] += len(data)
                if n_rst and reset_counts is not None and ip is not None:
                    reset_counts[ip] = reset_counts.get(ip, 0) + n_rst
            # Experimental inline mitigation: enforce a per-connection reset
            # budget. Default path (INLINE_MITIGATION false) never enters here.
            if INLINE_MITIGATION and n_rst and conn is not None and not conn["tripped"]:
                conn[direction] += n_rst
                if conn["client_rst"] + conn["server_rst"] >= CONN_RESET_BUDGET:
                    conn["tripped"] = True
                    with _lock:
                        _stats["inline_mitigated_total"] += 1
                    try:
                        if client_writer is not None:
                            client_writer.write(GOAWAY_ENHANCE_YOUR_CALM)
                            await client_writer.drain()
                    except Exception:
                        pass
                    break
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
        # If this connection was tripped, make sure both ends are torn down so
        # the peer pump unblocks immediately.
        if conn is not None and conn.get("tripped"):
            for w in (client_writer, victim_writer):
                try:
                    if w is not None:
                        w.close()
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
    c2v_scanner = H2ResetScanner()
    v2c_scanner = H2ResetScanner()
    conn = {"client_rst": 0, "server_rst": 0, "tripped": False}
    try:
        await asyncio.gather(
            _pump(client_reader, victim_writer, "bytes_c2s", c2v_scanner, _client_reset_per_source, ip,
                  conn=conn, direction="client_rst", client_writer=client_writer, victim_writer=victim_writer),
            _pump(victim_reader, client_writer, "bytes_s2c", v2c_scanner, _server_reset_per_source, ip,
                  conn=conn, direction="server_rst", client_writer=client_writer, victim_writer=victim_writer),
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
                # per_source is a lifetime total (useful for visibility/debugging)
                # but must NOT drive mitigation target selection: in a long-running
                # guard it permanently favors whichever source attacked first,
                # even after that source is gone. active_per_source is a live
                # snapshot (current open connections) and is what the detector
                # should use to pick "the busiest source right now".
                active_per_source = {ip: len(pairs) for ip, pairs in _active.items() if pairs}
                self._json(200, {
                    "blocklist": dict(_blocklist),
                    "per_source": dict(_per_source),
                    "active_per_source": active_per_source,
                    # Lifetime counts of RST_STREAM frames seen per source, by
                    # direction. Like per_source these are cumulative and never
                    # reset -- the detector turns them into *rates* (deltas
                    # between polls) before picking a mitigation target, for
                    # the same reason active_per_source replaced per_source
                    # there (see pick_top_source's docstring in detector.py).
                    "client_reset_per_source": dict(_client_reset_per_source),
                    "server_reset_per_source": dict(_server_reset_per_source),
                })
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
                "# HELP guard_inline_mitigated_total connections torn down by inline per-connection mitigation",
                "# TYPE guard_inline_mitigated_total counter",
                f"guard_inline_mitigated_total {s['inline_mitigated_total']}",
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
