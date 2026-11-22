#!/usr/bin/env python3
"""
detector — the detection + mitigation brain of the stream-reset DoS lab.

Every POLL_INTERVAL seconds it scrapes:
    * victim-exporter  -> aggregate reset counters + mismatch_ratio
    * guard            -> per-source connection counts (who is talking)

and derives two signals:

  Rapid Reset  (CVE-2023-44487):
      client_reset_rate = d(victim_client_resets)/dt, EWMA-smoothed.
      Alert when it stays above RAPID_RESET_RATE_THRESHOLD. Well-precedented:
      a browser resets streams a handful of times a minute; a flood is 100s-1000s/s.

  MadeYouReset (CVE-2025-8671):
      mismatch_ratio = inflight_requests / max(open_streams,1), EWMA-smoothed.
      Alert when it exceeds MISMATCH_RATIO_THRESHOLD. Reset-rate monitoring is
      blind to this attack because the *server* resets its own streams, so this
      backend-side ratio is the detection contribution.

Mitigation (Tier 1): on alert, if auto-mitigation is enabled (or a dashboard
Mitigate button is pressed), block a source at the guard for a cooldown
window. The victim sees every connection as coming from the guard, so "is
there an attack" is read from the victim's aggregate reset rate, while "who is
attacking" is read from the guard's real per-source view -- which now
includes per-source RST_STREAM counts by direction (see guard.py's
H2ResetScanner), so each attack's mitigation can target the source actually
causing *that* pattern: Rapid Reset mitigation picks the top client-reset-rate
source, MadeYouReset mitigation picks the top server-reset-rate source. These
can be two different IPs, and the two are tracked and blocked independently.

HTTP API (for the dashboard):
    GET  /state      full JSON state + rolling history for charts
    GET  /metrics    Prometheus metrics
    POST /mode       {"auto": true|false}
    POST /mitigate   mitigate now (manual button)
    POST /unmitigate clear the guard blocklist
    POST /reset      clear history/baselines
"""
import json
import os
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VICTIM_EXPORTER = os.environ.get("VICTIM_EXPORTER_URL", "http://victim-exporter:9110/metrics")
GUARD_METRICS = os.environ.get("GUARD_METRICS_URL", "http://guard:9120/metrics")
GUARD_BLOCKLIST = os.environ.get("GUARD_BLOCKLIST_URL", "http://guard:9120/blocklist")
GUARD_BLOCK = os.environ.get("GUARD_BLOCK_URL", "http://guard:9120/block")
GUARD_UNBLOCK = os.environ.get("GUARD_CLEAR_URL", "http://guard:9120/clear")

POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "1.0"))
EWMA_ALPHA = float(os.environ.get("EWMA_ALPHA", "0.4"))
RAPID_RESET_RATE_THRESHOLD = float(os.environ.get("RAPID_RESET_RATE_THRESHOLD", "50"))
MISMATCH_RATIO_THRESHOLD = float(os.environ.get("MISMATCH_RATIO_THRESHOLD", "3.0"))
BLOCK_COOLDOWN = float(os.environ.get("BLOCK_COOLDOWN", "60"))
AUTO_MITIGATE = os.environ.get("AUTO_MITIGATE", "false").lower() == "true"
CONTROL_PORT = int(os.environ.get("DETECTOR_PORT", "9130"))
HISTORY = int(os.environ.get("HISTORY_POINTS", "180"))

_state = {
    "auto_mitigate": AUTO_MITIGATE,
    "alert": "NORMAL",            # NORMAL | RAPID_RESET | MADEYOURESET
    "client_reset_rate": 0.0,
    "server_reset_rate": 0.0,
    "mismatch_ratio": 0.0,
    "mitigation_active": False,
    "blocked": {},
    # Per-source attribution (from guard's RST_STREAM-by-direction counts):
    # which IP is *currently* generating each signal's reset rate, if any.
    # Populated every poll cycle; used to target mitigation per attack type
    # instead of just "whoever holds the most live connections".
    "top_client_reset_source": None,
    "top_server_reset_source": None,
    "thresholds": {
        "rapid_reset_rate": RAPID_RESET_RATE_THRESHOLD,
        "mismatch_ratio": MISMATCH_RATIO_THRESHOLD,
    },
    "last_action": "",
    "history": deque(maxlen=HISTORY),
}
_lock = threading.Lock()
_reset_ewma = threading.Event()   # set by POST /reset to clear smoothing state


def _get(url, timeout=2.0):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _post(url, obj, timeout=2.0):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def parse_prom(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            name = parts[0].split("{")[0]
            try:
                out[name] = float(parts[1])
            except ValueError:
                pass
    return out


def pick_top_source():
    """Return the IP currently responsible for the most live connections at the
    guard. Uses active_per_source (a live snapshot) rather than per_source (a
    lifetime total that never resets) so mitigation targets whoever is actually
    attacking right now -- not whichever source happened to be busiest earliest
    in this guard's uptime. Falls back to the lifetime total only if nothing is
    currently active (e.g. a burst that already ended between polls)."""
    try:
        data = json.loads(_get(GUARD_BLOCKLIST))
        active = data.get("active_per_source", {})
        if active:
            ip, _ = max(active.items(), key=lambda kv: kv[1])
            return ip
        per = data.get("per_source", {})
        if not per:
            return None
        ip, _ = max(per.items(), key=lambda kv: kv[1])
        return ip
    except Exception:
        return None


def mitigate(reason, ip=None):
    """Block a source at the guard. If ip is not given, falls back to
    pick_top_source() (busiest live connection count) -- used for the
    generic/legacy path. Callers that know which attack signal they're
    responding to should pass the attributed source explicitly (see
    mitigate_signal) so Rapid Reset and MadeYouReset can each target their
    own real attacker even when both are live at once."""
    if ip is None:
        ip = pick_top_source()
    if not ip:
        with _lock:
            _state["last_action"] = f"{reason}: no source to block yet"
        return
    try:
        _post(GUARD_BLOCK, {"ip": ip, "cooldown": BLOCK_COOLDOWN})
        with _lock:
            _state["mitigation_active"] = True
            _state["blocked"][ip] = time.time() + BLOCK_COOLDOWN
            _state["last_action"] = f"{reason}: blocked {ip} for {int(BLOCK_COOLDOWN)}s"
    except Exception as e:
        with _lock:
            _state["last_action"] = f"{reason}: block failed: {e}"


def mitigate_signal(signal, reason):
    """signal: 'rapid_reset' (targets the attributed client-reset source) or
    'madeyoureset' (targets the attributed server-reset source). Falls back to
    pick_top_source() if no source has been attributed to that signal yet
    (e.g. called right as a scenario starts, before a rate baseline exists)."""
    key = "top_client_reset_source" if signal == "rapid_reset" else "top_server_reset_source"
    with _lock:
        ip = _state.get(key)
    mitigate(reason, ip=ip)  # mitigate() itself falls back to pick_top_source() if ip is None


def unmitigate():
    try:
        _post(GUARD_UNBLOCK, {})
    except Exception:
        pass
    with _lock:
        _state["mitigation_active"] = False
        _state["blocked"] = {}
        _state["last_action"] = "mitigation cleared"


def poll_loop():
    prev = None
    prev_t = None
    ewma_client = 0.0
    ewma_server = 0.0
    ewma_mismatch = 0.0
    # Per-source RST_STREAM lifetime counts from the previous poll, by
    # direction -- turned into a rate (delta/dt) each cycle, same reasoning as
    # the aggregate cr_rate/sr_rate below: the guard's counters never reset,
    # so only the delta between consecutive polls says who's active *now*.
    prev_src_client = {}
    prev_src_server = {}
    prev_src_t = None
    while True:
        t0 = time.time()
        if _reset_ewma.is_set():
            # drop smoothing + rate baselines so a new scenario starts clean
            prev = None
            prev_t = None
            ewma_client = ewma_server = ewma_mismatch = 0.0
            prev_src_client = {}
            prev_src_server = {}
            prev_src_t = None
            _reset_ewma.clear()
        vic = {}
        try:
            vic = parse_prom(_get(VICTIM_EXPORTER))
        except Exception:
            pass
        now = time.time()
        cr = vic.get("victim_client_resets", 0.0)
        sr = vic.get("victim_server_resets", 0.0)
        mismatch_raw = vic.get("victim_mismatch_ratio", 0.0)

        if prev is not None and prev_t is not None:
            dt = max(1e-3, now - prev_t)
            cr_rate = max(0.0, (cr - prev[0]) / dt)
            sr_rate = max(0.0, (sr - prev[1]) / dt)
        else:
            cr_rate = sr_rate = 0.0

        ewma_client = EWMA_ALPHA * cr_rate + (1 - EWMA_ALPHA) * ewma_client
        ewma_server = EWMA_ALPHA * sr_rate + (1 - EWMA_ALPHA) * ewma_server
        ewma_mismatch = EWMA_ALPHA * mismatch_raw + (1 - EWMA_ALPHA) * ewma_mismatch

        prev = (cr, sr)
        prev_t = now

        # Per-source attribution: who is *currently* causing each signal.
        top_client_src = None
        top_server_src = None
        try:
            guard_data = json.loads(_get(GUARD_BLOCKLIST))
            cur_src_client = guard_data.get("client_reset_per_source", {})
            cur_src_server = guard_data.get("server_reset_per_source", {})
            if prev_src_t is not None:
                sdt = max(1e-3, now - prev_src_t)
                client_rates = {ip: max(0.0, (c - prev_src_client.get(ip, 0)) / sdt)
                                for ip, c in cur_src_client.items()}
                server_rates = {ip: max(0.0, (c - prev_src_server.get(ip, 0)) / sdt)
                                 for ip, c in cur_src_server.items()}
                if client_rates:
                    ip, r = max(client_rates.items(), key=lambda kv: kv[1])
                    if r > 0.5:  # small noise floor
                        top_client_src = ip
                if server_rates:
                    # MadeYouReset's defining trait -- the one that makes it
                    # invisible to reset-rate monitoring in the first place --
                    # is that the SERVER resets streams while the CLIENT
                    # itself stays quiet. A source with a high server-reset
                    # rate but ALSO a high client-reset rate is almost
                    # certainly a Rapid Reset attacker whose server-side
                    # resets are just a side effect of its own flood (Tomcat
                    # can emit real server RST_STREAM frames as a side effect
                    # of handling a heavy client-reset flood), not a genuine
                    # MadeYouReset technique. Score by server rate divided by
                    # (1 + that same source's own client rate) so such
                    # sources are heavily discounted rather than just
                    # averaged down -- a pure MadeYouReset source (near-zero
                    # client rate) keeps ~full credit; a Rapid Reset source
                    # (large client rate) gets suppressed close to zero.
                    def _server_score(ip):
                        return server_rates[ip] / (1.0 + client_rates.get(ip, 0.0))
                    ip = max(server_rates, key=_server_score)
                    if server_rates[ip] > 0.5 and _server_score(ip) > 0.1:
                        top_server_src = ip
            prev_src_client = cur_src_client
            prev_src_server = cur_src_server
            prev_src_t = now
        except Exception:
            pass

        # classify
        alert = "NORMAL"
        if ewma_client >= RAPID_RESET_RATE_THRESHOLD:
            alert = "RAPID_RESET"
        elif ewma_mismatch >= MISMATCH_RATIO_THRESHOLD and ewma_server > 1.0:
            alert = "MADEYOURESET"

        with _lock:
            _state["client_reset_rate"] = round(ewma_client, 2)
            _state["server_reset_rate"] = round(ewma_server, 2)
            _state["mismatch_ratio"] = round(ewma_mismatch, 3)
            _state["alert"] = alert
            _state["top_client_reset_source"] = top_client_src
            _state["top_server_reset_source"] = top_server_src
            auto = _state["auto_mitigate"]
            # expire blocks in local view
            for ip, exp in list(_state["blocked"].items()):
                if exp < now:
                    del _state["blocked"][ip]
            if not _state["blocked"]:
                _state["mitigation_active"] = False
            _state["history"].append({
                "t": round(now, 1),
                "client_reset_rate": round(ewma_client, 2),
                "server_reset_rate": round(ewma_server, 2),
                "mismatch_ratio": round(ewma_mismatch, 3),
                "alert": alert,
                "mitigation_active": _state["mitigation_active"],
            })

        if auto and alert == "RAPID_RESET":
            mitigate_signal("rapid_reset", f"auto/{alert}")
        elif auto and alert == "MADEYOURESET":
            mitigate_signal("madeyoureset", f"auto/{alert}")

        dt = POLL_INTERVAL - (time.time() - t0)
        if dt > 0:
            time.sleep(dt)


class API(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj, default=list).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/state"):
            with _lock:
                snap = dict(_state)
                snap["history"] = list(_state["history"])
                snap["blocked"] = dict(_state["blocked"])
            self._json(200, snap)
        elif self.path == "/metrics":
            with _lock:
                s = dict(_state)
            lines = [
                "# TYPE detector_client_reset_rate gauge",
                f"detector_client_reset_rate {s['client_reset_rate']}",
                "# TYPE detector_server_reset_rate gauge",
                f"detector_server_reset_rate {s['server_reset_rate']}",
                "# TYPE detector_mismatch_ratio gauge",
                f"detector_mismatch_ratio {s['mismatch_ratio']}",
                "# TYPE detector_alert gauge",
                f'detector_alert{{state="{s["alert"]}"}} 1',
                "# TYPE detector_mitigation_active gauge",
                f"detector_mitigation_active {1 if s['mitigation_active'] else 0}",
            ]
            body = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json(404, {"error": "not found"})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return {}

    def do_POST(self):
        if self.path == "/mode":
            d = self._read_json()
            with _lock:
                _state["auto_mitigate"] = bool(d.get("auto", False))
            self._json(200, {"auto_mitigate": _state["auto_mitigate"]})
        elif self.path == "/mitigate":
            d = self._read_json()
            kind = d.get("kind")  # optional: "rapid_reset" | "madeyoureset", from
            # the dashboard's per-panel buttons. Each targets the source
            # attributed to that specific signal (see mitigate_signal / the
            # guard's per-source RST_STREAM-by-direction counts), so the two
            # buttons can correctly block two different IPs when both attacks
            # are live at once. No kind -> generic fallback (busiest live
            # connection count, the pre-attribution behavior).
            if kind in ("rapid_reset", "madeyoureset"):
                mitigate_signal(kind, f"manual/{kind}")
            else:
                mitigate("manual")
            with _lock:
                self._json(200, {"ok": True, "last_action": _state["last_action"]})
        elif self.path == "/unmitigate":
            unmitigate()
            self._json(200, {"ok": True})
        elif self.path == "/reset":
            with _lock:
                _state["history"].clear()
            _reset_ewma.set()
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})


def main():
    threading.Thread(target=poll_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), API)
    print(f"detector API/metrics :{CONTROL_PORT} (auto_mitigate={AUTO_MITIGATE})", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
