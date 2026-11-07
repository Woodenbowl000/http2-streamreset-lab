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

Reset counting de-dupes by (connection, stream): a single reset can emit several
log lines while the servlet thread unwinds, so each (conn, stream) pair is
counted once per direction.

NOTE (honest limitation): inflight/open_streams/mismatch_ratio derived from the
debug log are approximate and are the MadeYouReset research scaffold. The Rapid
Reset demo depends only on victim_client_resets, which is reliable.
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

RE_CONN_STREAM = re.compile(r"Connection \[(\d+)\], Stream \[(\d+)\]")
RE_RST_RX = re.compile(r"CLOSED_RST_RX")
RE_RST_TX = re.compile(r"CLOSED_RST_TX")
RE_SERVICE = re.compile(r"StreamProcessor\.service")
RE_FINISH = re.compile(r"StreamProcessor\.finishResponse")

seen_client = set()
seen_server = set()
seen_open = set()
seen_fin = set()
seen_closed = set()


def process_line(line: str):
    with _lock:
        M["victim_log_lines"] += 1
        m = RE_CONN_STREAM.search(line)
        conn = m.group(1) if m else None
        stream = m.group(2) if m else None
        key = (conn, stream) if conn and stream else None

        if key and RE_RST_RX.search(line):
            if key not in seen_client:
                seen_client.add(key)
                M["victim_client_resets"] += 1
                if key not in seen_closed:
                    seen_closed.add(key)
                    M["victim_streams_closed"] += 1
                    M["victim_open_streams"] = max(0, M["victim_open_streams"] - 1)
        elif key and RE_RST_TX.search(line):
            if key not in seen_server:
                seen_server.add(key)
                M["victim_server_resets"] += 1
                if key not in seen_closed:
                    seen_closed.add(key)
                    M["victim_streams_closed"] += 1
                    M["victim_open_streams"] = max(0, M["victim_open_streams"] - 1)

        if key and RE_SERVICE.search(line):
            if key not in seen_open:
                seen_open.add(key)
                M["victim_streams_opened"] += 1
                M["victim_requests"] += 1
                M["victim_open_streams"] += 1
                M["victim_inflight_requests"] += 1
        elif key and RE_FINISH.search(line):
            if key not in seen_fin:
                seen_fin.add(key)
                M["victim_inflight_requests"] = max(0, M["victim_inflight_requests"] - 1)

        M["victim_mismatch_ratio"] = (
            M["victim_inflight_requests"] / max(M["victim_open_streams"], 1)
        )


def newest_log():
    files = glob.glob(os.path.join(LOG_DIR, LOG_GLOB))
    return max(files, key=os.path.getmtime) if files else None


def tail_loop():
    current = None
    fh = None
    while True:
        target = newest_log()
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
    httpd = ThreadingHTTPServer(("0.0.0.0", EXPORTER_PORT), Handler)
    print(f"victim-exporter :{EXPORTER_PORT} reading {LOG_DIR}/{LOG_GLOB}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
