#!/usr/bin/env python3
"""
adaptive_experiment.py -- the "detection survives pacing" experiment.

Motivation. The standard, vendor-adopted defence against MadeYouReset is a
per-connection stream-reset limit: close a connection once it has produced more
than a budget of RST_STREAM frames (the paper's "Stream Reset Limits"). That
defence keys on the RATE of resets. StreamShield's mismatch-ratio / phantom-count
detector keys on the DIVERGENCE between backend work and open streams. This
experiment shows there is a regime an attacker can choose -- slow, long-backend
MadeYouReset -- in which the reset rate stays under the reset-limit budget (so
the standard fix never fires) while the mismatch ratio stays high (so StreamShield
still detects it). That regime is the novel result: a detector that catches an
attack the production fix is tuned to miss.

How it works. For each pacing value in a sweep, it runs a MadeYouReset attack of
fixed duration with a long backend time, polls the detector throughout, and
records the peak mismatch ratio and phantom count, whether the detector alerted,
and the measured server-reset rate. It then marks, for a configurable reset-limit
policy (budget over a window), whether that policy WOULD have fired, and whether
StreamShield did. The interesting rows are "reset-limit: no, StreamShield: yes".

Run (stack up, from the repo root):
    pip install -r scripts/requirements.txt          # matplotlib (plot is optional)
    python3 scripts/adaptive_experiment.py

Outputs docs/adaptive.csv and, if matplotlib is present, docs/adaptive.png.
Nothing here changes the lab; it only drives the attacker and reads the detector.
"""
import csv
import json
import os
import subprocess
import time
import urllib.request

DETECTOR = os.environ.get("DETECTOR_URL", "http://127.0.0.1:9130")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_CSV = os.path.join(ROOT, "docs", "adaptive.csv")
OUT_PNG = os.path.join(ROOT, "docs", "adaptive.png")

# Sweep of inter-reset pacing in seconds (bigger = slower attack = fewer
# resets/sec). Tune to taste; the point is to walk from "fast" down to a rate
# below the reset-limit budget.
GAPS = [0.004, 0.02, 0.05, 0.1, 0.2, 0.4, 0.8]
DURATION = int(os.environ.get("ADAPT_DURATION", "20"))
CONNECTIONS = int(os.environ.get("ADAPT_CONNECTIONS", "3"))
BACKEND_MS = int(os.environ.get("ADAPT_BACKEND_MS", "2000"))   # long backend work
# Reset-limit policy to compare against: budget resets per window seconds, per
# connection. 100 resets / 10 s = 10 resets/s/connection is a representative
# "Stream Reset Limits" setting (vendors close around 100 resets).
RESET_BUDGET = float(os.environ.get("RESET_BUDGET", "100"))
RESET_WINDOW = float(os.environ.get("RESET_WINDOW", "10"))
RESET_LIMIT_RATE = RESET_BUDGET / RESET_WINDOW        # resets/s/connection to trip the fix


def post(path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else b""
    req = urllib.request.Request(DETECTOR + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass


def get_state():
    with urllib.request.urlopen(DETECTOR + "/state", timeout=3) as r:
        return json.loads(r.read())


def run_attack_async(gap):
    cmd = ["docker", "compose", "run", "--rm", "attacker", "madeyoureset",
           "--host", "guard", "--port", "8080", "--path", f"/?ms={BACKEND_MS}",
           "--duration", str(DURATION), "--connections", str(CONNECTIONS),
           "--gap", str(gap)]
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def measure(gap):
    """Run one attack at this pacing, poll the detector, return peak signals."""
    post("/reset")
    post("/unmitigate")
    post("/mode", {"auto": False})     # measure detection, do not mitigate
    time.sleep(2)
    proc = run_attack_async(gap)
    peak_mismatch = 0.0
    peak_phantom = 0.0
    peak_server_rate = 0.0
    alerted = False
    t_end = time.time() + DURATION + 2
    while time.time() < t_end:
        try:
            s = get_state()
            peak_mismatch = max(peak_mismatch, float(s.get("mismatch_ratio", 0.0)))
            peak_phantom = max(peak_phantom, float(s.get("phantom_streams", 0.0)))
            peak_server_rate = max(peak_server_rate, float(s.get("server_reset_rate", 0.0)))
            if s.get("alert") == "MADEYOURESET":
                alerted = True
        except Exception:
            pass
        time.sleep(0.5)
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    # server_reset_rate from the detector is aggregate across connections; divide
    # by the connection count for a per-connection rate to compare with the
    # per-connection reset-limit policy.
    per_conn_reset_rate = peak_server_rate / max(CONNECTIONS, 1)
    reset_limit_fires = per_conn_reset_rate >= RESET_LIMIT_RATE
    streamshield_detects = alerted or peak_mismatch >= 3.0
    return {
        "gap_s": gap,
        "per_conn_reset_rate": round(per_conn_reset_rate, 2),
        "peak_mismatch_ratio": round(peak_mismatch, 2),
        "peak_phantom_streams": round(peak_phantom, 1),
        "reset_limit_fires": reset_limit_fires,
        "streamshield_detects": streamshield_detects,
        "evasion_window": (not reset_limit_fires) and streamshield_detects,
    }


def main():
    rows = []
    print(f"reset-limit policy: {RESET_BUDGET:.0f} resets / {RESET_WINDOW:.0f}s "
          f"= {RESET_LIMIT_RATE:.1f} resets/s/conn to trip\n")
    header = f"{'gap(s)':>7} {'reset/s/conn':>12} {'mismatch':>9} {'phantom':>8} {'reset-limit':>12} {'StreamShield':>13} {'EVASION':>8}"
    print(header)
    for gap in GAPS:
        r = measure(gap)
        rows.append(r)
        print(f"{r['gap_s']:>7} {r['per_conn_reset_rate']:>12} {r['peak_mismatch_ratio']:>9} "
              f"{r['peak_phantom_streams']:>8} {str(r['reset_limit_fires']):>12} "
              f"{str(r['streamshield_detects']):>13} {str(r['evasion_window']):>8}")
    post("/reset")
    post("/unmitigate")

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n[adaptive] wrote {OUT_CSV}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        gaps = [r["gap_s"] for r in rows]
        rr = [r["per_conn_reset_rate"] for r in rows]
        mm = [r["peak_mismatch_ratio"] for r in rows]
        fig, ax1 = plt.subplots(figsize=(7, 4))
        ax1.set_xscale("log")
        ax1.plot(gaps, rr, "o-", color="tab:red", label="reset rate / conn")
        ax1.axhline(RESET_LIMIT_RATE, color="tab:red", ls="--", lw=1,
                    label=f"reset-limit budget ({RESET_LIMIT_RATE:.0f}/s)")
        ax1.set_xlabel("inter-reset pacing gap (s, log)")
        ax1.set_ylabel("server resets /s /connection", color="tab:red")
        ax2 = ax1.twinx()
        ax2.plot(gaps, mm, "s-", color="tab:blue", label="mismatch ratio")
        ax2.axhline(3.0, color="tab:blue", ls="--", lw=1, label="mismatch threshold (3.0)")
        ax2.set_ylabel("peak mismatch ratio", color="tab:blue")
        ax1.set_title("Pacing the attack below the reset-limit, still caught by the ratio")
        fig.tight_layout()
        fig.savefig(OUT_PNG, dpi=130)
        print(f"[adaptive] wrote {OUT_PNG}")
    except Exception as e:
        print(f"[adaptive] plot skipped ({e})")


if __name__ == "__main__":
    main()
