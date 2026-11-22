#!/usr/bin/env python3
"""
victim-exporter — turns the victim Tomcat's real signals into Prometheus
metrics for the stream-reset DoS lab. Standard-library only (no pip deps).

Hybrid instrumentation (deliberate, not an oversight -- see below):
  * victim_inflight_requests comes from InflightValve (victim/valve/, a real
    custom Tomcat Valve), polled over plain HTTP from :8080/__inflight_metrics.
  * Everything else -- open_streams, client/server reset counts -- still comes
    from parsing Tomcat's `org.apache.coyote.http2` FINE-level debug log.

Why hybrid, not log-only or JMX-only: inflight_requests has a clean, robust,
zero-log-parsing path via a Valve, because a Valve's invoke() genuinely blocks
for the real backend duration regardless of what the HTTP/2 layer does to the
stream underneath it (verified against this exact webapp -- see
victim/valve/InflightValve.java). open_streams does NOT have an equivalent
clean path: verified directly against a live Tomcat 10.1.43 JVM (attached via
the Attach API and listed every registered MBean) that stock Tomcat exposes
no HTTP/2 stream-concurrency count over JMX -- only connector-level aggregate
stats (GlobalRequestProcessor: requestCount, bytes, timing) and per-worker-
thread state (RequestProcessor: thread-pool occupancy, not stream state).
Getting open_streams any other way would mean a bytecode-instrumenting Java
agent -- a much larger, riskier change than a Valve for a metric the log
already gives us reliably. So that piece stays log-based on purpose.

Signals produced (Prometheus text format on :9110/metrics)
----------------------------------------------------------
victim_client_resets      counter  client-initiated RST_STREAM (Rapid Reset signal)       [log]
victim_server_resets      counter  server-initiated RST_STREAM (MadeYouReset signal)       [log]
victim_requests           counter  HTTP/2 requests dispatched to the servlet               [log]
victim_streams_opened     counter  HTTP/2 streams opened                                   [log]
victim_streams_closed     counter  HTTP/2 streams closed                                   [log]
victim_open_streams       gauge    opened - closed (protocol-layer active streams)         [log]
victim_inflight_requests  gauge    real backend-work-in-progress count                     [Valve]
victim_mismatch_ratio     gauge    inflight / max(open_streams,1)  [MadeYouReset metric]
victim_log_lines          counter  lines parsed (health)
victim_up                 gauge    1 while the exporter is reading a log

Signal source — the HTTP/2 stream state machine (open_streams + resets)
-------------------------------------------------------------------------
Tomcat 10.1.43's `org.apache.coyote.http2` logger (at level ALL) emits one line
per stream state transition:

    Connection [C], Stream [S], State changed from [X] to [Y]

A normal request walks  null -> IDLE -> OPEN -> HALF_CLOSED_REMOTE -> CLOSED_TX
and is then recycled ("... have been recycled"). We map:

    -> OPEN                stream opened                 (streams_opened, open_streams+1)
    -> CLOSED_*            protocol stream closed        (streams_closed, open_streams-1)
         CLOSED_RST_RX     client-initiated RST_STREAM   (victim_client_resets) [Rapid Reset]
         CLOSED_RST_TX     server-initiated RST_STREAM   (victim_server_resets) [MadeYouReset]

(HALF_CLOSED_REMOTE/recycle-based inflight tracking was removed -- that's now
InflightValve's job, for real, not inferred from log text.)

De-dup: each (connection, stream) pair is counted once per event; connection ids
are unique per TCP connection, so stream-id reuse across connections is safe.
"""
import glob
import os
import re
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_DIR = os.environ.get("VICTIM_LOG_DIR", "/victim-logs")
LOG_GLOB = os.environ.get("VICTIM_LOG_GLOB", "catalina.*.log")
EXPORTER_PORT = int(os.environ.get("EXPORTER_PORT", "9110"))
VALVE_METRICS_URL = os.environ.get(
    "VALVE_METRICS_URL", "http://victim:8080/__inflight_metrics")
VALVE_POLL_INTERVAL = float(os.environ.get("VALVE_POLL_INTERVAL", "0.5"))

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

# Tomcat logs the HTTP/2 connection id in HEXADECIMAL (e.g. "Connection [b0d]")
# but the stream id in decimal (e.g. "Stream [48765]"). The connection id MUST
# be matched as hex -- a plain \d+ silently matches only the first ~9
# connections of a freshly-started Tomcat (ids 1-9, where hex and decimal
# coincide) and then stops matching every id containing a-f, which freezes the
# reset/stream counters after enough connections accumulate. (conn, stream) is
# only used as a de-dup key, so the exact base doesn't matter as long as every
# line is captured.
RE_STATE = re.compile(
    r"Connection \[([0-9a-fA-F]+)\], Stream \[(\d+)\], State changed from \[\w+\] to \[(\w+)\]")

seen_open = set()        # keys that incremented open_streams (-> OPEN)
seen_dispatch = set()    # keys counted as a dispatched request (-> HALF_CLOSED_REMOTE)
seen_closed = set()      # keys that decremented open_streams (first -> CLOSED_*)
seen_reset = set()       # keys already classified as a client/server reset


def process_line(line: str):
    with _lock:
        M["victim_log_lines"] += 1

        m = RE_STATE.search(line)
        if not m:
            return
        conn, stream, to = m.group(1), m.group(2), m.group(3)
        key = (conn, stream)
        if to == "OPEN":
            if key not in seen_open:
                seen_open.add(key)
                M["victim_streams_opened"] += 1
                M["victim_open_streams"] += 1
                _recompute()  # open_streams moved; mismatch_ratio's denominator changed
        elif to == "HALF_CLOSED_REMOTE":
            # full request received -> dispatched to the servlet (just a
            # counter now; InflightValve tracks the actual in-progress work)
            if key not in seen_dispatch:
                seen_dispatch.add(key)
                M["victim_requests"] += 1
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
            _recompute()  # open_streams moved; mismatch_ratio's denominator changed
            # Fully terminal (closed) streams no longer need tracking at all
            # -- bounds memory under a sustained attack, same as before.
            for s in (seen_open, seen_dispatch, seen_closed, seen_reset):
                s.discard(key)


def _recompute():
    """Refresh mismatch_ratio from the two independent signals: inflight
    (real, from InflightValve) and open_streams (from the log)."""
    M["victim_mismatch_ratio"] = (
        M["victim_inflight_requests"] / max(M["victim_open_streams"], 1)
    )


def valve_poll_loop():
    """Poll InflightValve's real counter directly over HTTP -- a plain GET
    straight to the victim (bypassing the guard entirely, same as the log
    tail does via the shared volume: this is our own internal metrics
    collection, not attacker-observable traffic). Advisory only: if the
    victim is still starting up or briefly unreachable, keep the last known
    value rather than erroring the whole exporter."""
    pattern = re.compile(r"victim_inflight_requests_valve\s+(\d+)")
    while True:
        try:
            with urllib.request.urlopen(VALVE_METRICS_URL, timeout=2.0) as r:
                body = r.read().decode("utf-8", "replace")
            m = pattern.search(body)
            if m:
                with _lock:
                    M["victim_inflight_requests"] = int(m.group(1))
                    _recompute()
        except Exception:
            pass
        time.sleep(VALVE_POLL_INTERVAL)


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
    #
    # Also must detect the file being replaced AT THE SAME PATH, not just a
    # different path -- confirmed directly: restarting only the victim
    # container (e.g. after rebuilding the image) starts a fresh Tomcat whose
    # logging may recreate the same dated filename, leaving a long-running
    # exporter's already-open handle pointing at the old, now-unlinked inode,
    # which never receives another byte. Comparing inodes (the classic
    # logrotate-safe "tail -F" check), not just the path string, catches this.
    ROTATION_CHECK_INTERVAL = 1.0
    current = None
    current_ino = None
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
            try:
                disk_ino = os.stat(target).st_ino
            except OSError:
                disk_ino = None
            if target != current or disk_ino != current_ino:
                if fh:
                    fh.close()
                fh = open(target, "r", errors="replace")
                fh.seek(0, os.SEEK_END)
                current = target
                current_ino = disk_ino
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
    threading.Thread(target=valve_poll_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", EXPORTER_PORT), Handler)
    print(f"victim-exporter :{EXPORTER_PORT} reading {LOG_DIR}/{LOG_GLOB} "
          f"+ polling {VALVE_METRICS_URL}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
