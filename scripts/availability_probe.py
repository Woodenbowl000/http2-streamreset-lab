#!/usr/bin/env python3
"""
availability_probe.py -- measures the service availability a *legitimate* user
experiences at the victim, so the evaluation can quantify the rubric's
"reducing attack impact while preserving service availability" directly, not
just via the detector's internal signals.

It opens a few honest HTTP/2 connections to the guard entrypoint and, for a
fixed duration, sends well-formed GET requests back to back, recording for each
one whether it completed and how long it took. It prints a JSON summary with the
success rate and latency percentiles, and optionally appends a CSV row tagged
with a phase label.

Intended use: run this continuously as a canary while driving the lab through
idle -> legitimate load -> attack -> attack+mitigation, once with the attacker
and once with StreamShield's mitigation enabled, and compare the success rate
and latency across phases.

    # host needs: pip install -r scripts/requirements.txt   (h2)
    python3 scripts/availability_probe.py --duration 30 --label attack-no-mitigation

SAFETY: like every tool in this lab it only talks to the local victim. The
target must be loopback or a private (RFC-1918) address; there is no override.
"""
import argparse
import csv
import ipaddress
import json
import os
import socket
import statistics
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events


def assert_local_target(host: str):
    if host in ("localhost", "guard", "victim"):
        return
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except Exception as e:
        print(f"[safety] cannot resolve {host!r}: {e}", file=sys.stderr)
        sys.exit(2)
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback):
            print(f"[safety] refusing: {host} -> {a} is not a private/lab address.",
                  file=sys.stderr)
            sys.exit(2)


def one_request(host, port, path, timeout):
    """Open a connection, send a single GET, read the full response. Returns the
    wall-clock latency in milliseconds on success, or None on any failure."""
    s = None
    try:
        cfg = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=cfg)
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        conn.initiate_connection()
        s.sendall(conn.data_to_send())
        t0 = time.time()
        sid = conn.get_next_available_stream_id()
        headers = [(":method", "GET"), (":path", path),
                   (":scheme", "http"), (":authority", f"{host}:{port}")]
        conn.send_headers(sid, headers, end_stream=True)
        s.sendall(conn.data_to_send())
        ended = False
        while not ended:
            data = s.recv(65535)
            if not data:
                return None  # connection closed before the response ended
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.StreamReset) and event.stream_id == sid:
                    return None  # our stream was reset -> request failed
                if isinstance(event, h2.events.StreamEnded) and event.stream_id == sid:
                    ended = True
            out = conn.data_to_send()
            if out:
                s.sendall(out)
        return (time.time() - t0) * 1000.0
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def worker(host, port, path, timeout, deadline, results, lock):
    while time.time() < deadline:
        ms = one_request(host, port, path, timeout)
        with lock:
            if ms is None:
                results["fail"] += 1
            else:
                results["ok"] += 1
                results["latencies"].append(ms)


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1)))))
    return values[k]


def main():
    ap = argparse.ArgumentParser(description="legitimate-user availability probe (lab-only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/?ms=200")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--clients", type=int, default=4)
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--label", default="probe", help="phase label recorded in the CSV")
    ap.add_argument("--csv", default="", help="optional path to append a summary row to")
    args = ap.parse_args()

    assert_local_target(args.host)

    results = {"ok": 0, "fail": 0, "latencies": []}
    lock = threading.Lock()
    deadline = time.time() + args.duration
    threads = [threading.Thread(target=worker,
                                args=(args.host, args.port, args.path, args.timeout,
                                      deadline, results, lock))
               for _ in range(args.clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = results["ok"] + results["fail"]
    lat = results["latencies"]
    summary = {
        "label": args.label,
        "requests": total,
        "ok": results["ok"],
        "fail": results["fail"],
        "success_rate_pct": round(100.0 * results["ok"] / total, 1) if total else 0.0,
        "latency_ms_p50": round(pct(lat, 50), 1) if lat else None,
        "latency_ms_p95": round(pct(lat, 95), 1) if lat else None,
        "latency_ms_mean": round(statistics.mean(lat), 1) if lat else None,
    }
    print(json.dumps(summary, indent=2))

    if args.csv:
        new = not os.path.exists(args.csv)
        with open(args.csv, "a", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary.keys()))
            if new:
                w.writeheader()
            w.writerow(summary)
        print(f"[probe] appended summary to {args.csv}")


if __name__ == "__main__":
    main()
