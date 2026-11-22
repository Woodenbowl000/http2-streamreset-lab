#!/usr/bin/env python3
"""
victim-exporter — turns the victim Tomcat's HTTP/2 debug log into Prometheus
metrics for the stream-reset DoS lab. Standard-library only (no pip deps).

This is the proposal's Week-1 primary detection-signal source: instead of
instrumenting Tomcat's code, we enable `org.apache.coyote.http2` FINE logging
and parse the resulting stream-state events out of band. That keeps the victim
a stock, pinned, vulnerable Tomcat.

Signals produced (Prometheus text format on :9110/metrics)
----------------------------------------------------------
victim_client_resets      counter  client-initiated RST_STREAM (Rapid Reset signal)
victim_server_resets      counter  server-initiated RST_STREAM (MadeYouReset signal)
victim_requests           counter  HTTP/2 requests dispatched to the servlet
victim_streams_opened     counter  HTTP/2 streams opened
victim_streams_closed     counter  HTTP/2 streams closed
victim_open_streams       gauge    opened - closed (protocol-layer active streams)
victim_inflight_requests  gauge    dispatched - completed (app-layer active work)
victim_mismatch_ratio     gauge    inflight / max(open_streams,1)  [MadeYouReset metric]
victim_log_lines          counter  lines parsed (health)
victim_up                 gauge    1 while the exporter is reading a log

Signal source — the HTTP/2 stream state machine
-----------------------------------------------
Tomcat 10.1.43's `org.apache.coyote.http2` logger (at level ALL) emits one line
per stream state transition:

    Connection [C], Stream [S], State changed from [X] to [Y]

A normal request walks  null -> IDLE -> OPEN -> HALF_CLOSED_REMOTE -> CLOSED_TX
and is then recycled ("... have been recycled"). We map:

    -> OPEN                stream opened                 (streams_opened, open_streams+1)
    -> HALF_CLOSED_REMOTE  full request dispatched       (requests, inflight+1)
    -> CLOSED_*            protocol stream closed        (streams_closed, open_streams-1)
         CLOSED_RST_RX     client-initiated RST_STREAM   (victim_client_resets) [Rapid Reset]
         CLOSED_RST_TX     server-initiated RST_STREAM   (victim_server_resets) [MadeYouReset]
    recycled               backend work truly finished   (inflight-1)

The MadeYouReset signal falls straight out of this: under the attack the server
resets a stream (CLOSED_RST_TX, so open_streams drops) *while the servlet keeps
running* — the stream is not recycled until the backend work completes, so
inflight stays high. mismatch_ratio = inflight / max(open_streams,1) therefore
climbs, even though victim_client_resets never moves (the attacker sends no
RST_STREAM). This was verified against Tomcat 10.1.43: a stream reset ~1 ms
after opening still recorded a full ~500 ms backend service time in the access
log before being recycled. See docs/MADEYOURESET.md.

De-dup: each (connection, stream) pair is counted once per event; connection ids
are unique per TCP connection, so stream-id reuse across connections is safe.
Terminal (recycled) streams are pruned to bound memory under a sustained attack.
"""
import glob
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.environ.get("VICTIM_LOG_DIR", "/victim-logs")
LOG_GLOB = os.environ.get("VICTIM_LOG_GLOB", "catalina.*.log")
EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "9110"))
# A dispatched stream normally recycles within the backend service time. If a
# connection is torn down (e.g. the guard blocks the attacker), Tomcat abandons
# its in-flight streams WITHOUT a per-stream "recycled" log line, which would
# otherwise leave inflight stuck high forever. Reap such orphaned streams after
# this many seconds so the gauge returns to baseline once an attack stops. It
# must comfortably exceed the largest real backend time (the ?ms=N endpoint caps
# at 10 s), so legitimate slow requests are never reaped early.
INFLIGHT_TIMEOUT = float(os.environ.get("INFLIGHT_TIMEOUT", "12.0"))

_lock = threading.Lock()
M = {
    "victim_client_resets": 0,
    "victim_server_resets": 0,
    "victim_requests": 0,
    "victim_streams_opened": 0,
    "victim_streams_closed": 0,
    "victim_log_lines": 0,
    "victim_open_streams": 0,
    "victim_inflight_requests": 0,
    "victim_mismatch_ratio": 0.0,
    "victim_up": 0,
}
_TYPES = {
    "victim_client_resets": "counter",
    "victim_server_resets": "counter",
    "victim_requests": "counter",
    "victim_streams_opened": "counter",
    "victim_streams_closed": "counter",
    "victim_log_lines": "counter",
    "victim_open_streams": "gauge",
    "victim_inflight_requests": "gauge",
    "victim_mismatch_ratio": "gauge",
    "victim_up": "gauge",
}

RE_STATE = re.compile(
    r"Connection \[(\d+)\], Stream \[(\d+)\], State changed from \[\w+\] to \[(\w+)\]")
RE_RECYCLE = re.compile(r"Connection \[(\d+)\], Stream \[(\d+)\].*recycled")

seen_open = set()        # keys that incremented open_streams (-> OPEN)
seen_dispatch = set()    # keys dispatched to the backend (-> HALF_CLOSED_REMOTE)
seen_closed = set()      # keys that decremented open_streams (first -> CLOSED_*)
seen_reset = set()       # keys already classified as a client/server reset
seen_recycle = set()     # keys that recycled (true backend completion)
inflight_at = {}         # key -> dispatch time, for still-in-flight streams


def _prune(key):
    """Drop a fully-finished (closed + recycled) stream from the tracking sets."""
    for s in (seen_open, seen_dispatch, seen_closed, seen_reset, seen_recycle):
        s.discard(key)
    inflight_at.pop(key, None)


def process_line(line: str):
    with _lock:
        M["victim_log_lines"] += 1

        m = RE_STATE.search(line)
        if m:
            conn, stream, to = m.group(1), m.group(2), m.group(3)
            key = (conn, stream)
            if to == "OPEN":
                if key not in seen_open:
                    seen_open.add(key)
                    M["victim_streams_opened"] += 1
                    M["victim_open_streams"] += 1
            elif to == "HALF_CLOSED_REMOTE":
                # full request received -> dispatched to the servlet (app work)
                if key not in seen_dispatch:
                    seen_dispatch.add(key)
                    M["victim_requests"] += 1
                    inflight_at[key] = time.time()
            elif to.startswith("CLOSED"):
                if key not in seen_closed:
                    seen_closed.add(key)
                    M["victim_streams_closed"] += 1
                    M["victim_open_streams"] = max(0, M["victim_open_streams"] - 1)
                if key not in seen_reset:
                    if to == "CLOSED_RST_RX":
                        seen_reset.add(key)
                        M["victim_client_resets"] += 1   # Rapid Reset signal
                    elif to == "CLOSED_RST_TX":
                        seen_reset.add(key)
                        M["victim_server_resets"] += 1   # MadeYouReset signal
            _recompute()
            return

        r = RE_RECYCLE.search(line)
        if r:
            key = (r.group(1), r.group(2))
            # inflight drops only on true backend completion, not on the reset,
            # so a reset-but-still-processing stream stays counted as in flight.
            if key in seen_dispatch and key not in seen_recycle:
                seen_recycle.add(key)
                inflight_at.pop(key, None)
            _recompute()
            if key in seen_closed:
                _prune(key)


def _recompute():
    """Refresh the inflight gauge + mismatch ratio from the live tracking state."""
    M["victim_inflight_requests"] = len(inflight_at)
    M["victim_mismatch_ratio"] = (
        M["victim_inflight_requests"] / max(M["victim_open_streams"], 1)
    )


def reaper_loop():
    """Periodically drop in-flight streams whose connection was torn down without
    a recycle log line, so the gauge drains back to baseline after an attack."""
    while True:
        time.sleep(1.0)
        now = time.time()
        with _lock:
            stale = [k for k, t in inflight_at.items() if now - t > INFLIGHT_TIMEOUT]
            for k in stale:
                inflight_at.pop(k, None)
            if stale:
                _recompute()


def newest_log():
    files = glob.glob(os.path.join(LOG_DIR, LOG_GLOB))
    return max(files, key=os.path.getmtime) if files else None


def tail_loop():
    # Only re-glob the log directory (a real filesystem scan) periodically --
    # NOT on every line. Under a flood, Tomcat's FINE-level HTTP/2 logging can
    # emit thousands of lines/sec; re-globbing every single one turns this
    # thread into a CPU/syscall hot loop that can starve the HTTP server
    # thread (same process, same GIL) past the detector's poll timeout --
    # exactly when the detector most needs a response. Log rotation is rare;
    # checking for it once a second is still effectively instant to notice.
    ROTATION_CHECK_INTERVAL = 1.0
    current = None
    fh = None
    last_check = 0.0
    while True:
        now = time.time()
        if fh is None or (now - last_check) >= ROTATION_CHECK_INTERVAL:
            target = newest_log()
            last_check = now
            if target is None:
                with _lock:
                    M["victim_up"] = 0
                time.sleep(1.0)
                continue
            if target != current:
                if fh:
                    fh.close()
                fh = open(target, "r", errors="replace")
                fh.seek(0, os.SEEK_END)
                current = target
                with _lock:
                    M["victim_up"] = 1
        line = fh.readline()
        if line:
            try:
                process_line(line)
            except Exception:
                pass
        else:
            time.sleep(0.05)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        with _lock:
            snap = dict(M)
        out = []
        for name, val in snap.items():
            out.append(f"# TYPE {name} {_TYPES[name]}")
            if isinstance(val, float):
                out.append(f"{name} {val:.6f}")
            else:
                out.append(f"{name} {val}")
        body = ("\n".join(out) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    threading.Thread(target=tail_loop, daemon=True).start()
    threading.Thread(target=reaper_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", EXPORTER_PORT), Handler)
    print(f"victim-exporter :{EXPORTER_PORT} reading {LOG_DIR}/{LOG_GLOB}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
