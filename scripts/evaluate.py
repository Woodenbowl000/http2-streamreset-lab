#!/usr/bin/env python3
"""
evaluate.py — runs the three evaluation scenarios from the proposal back to back
against the running lab and produces the project's central evaluation artifact:
a plot of the detection signals across (1) idle baseline, (2) legitimate load
spike, and (3) an actual Rapid Reset attack with automatic mitigation.

The point it demonstrates: the detector does NOT just trip on any load spike.
Legitimate concurrent traffic keeps the client-reset rate near zero; only the
attack drives it across the threshold, at which point auto-mitigation knocks it
back down and keeps the victim serving.

Outputs:
    docs/evaluation.csv   raw time series
    docs/evaluation.png   the plot

Usage (stack must be up):  python3 scripts/evaluate.py
Requires matplotlib on the host running it (see scripts/requirements.txt).
"""
import csv
import json
import os
import subprocess
import threading
import time
import urllib.request

DETECTOR = os.environ.get("DETECTOR_URL", "http://127.0.0.1:9130")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_CSV = os.path.join(ROOT, "docs", "evaluation.csv")
OUT_PNG = os.path.join(ROOT, "docs", "evaluation.png")

samples = []
phases = []
_stop = False
_t0 = None


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


def poller():
    while not _stop:
        try:
            s = get_state()
            samples.append({
                "t": round(time.time() - _t0, 2),
                "client_reset_rate": s.get("client_reset_rate", 0.0),
                "server_reset_rate": s.get("server_reset_rate", 0.0),
                "mismatch_ratio": s.get("mismatch_ratio", 0.0),
                "alert": s.get("alert", "NORMAL"),
                "mitigation_active": 1 if s.get("mitigation_active") else 0,
            })
        except Exception:
            pass
        time.sleep(0.5)


def scenario(mode, duration, connections=6, path="/?ms=200"):
    subprocess.run(
        ["docker", "compose", "run", "--rm", "attacker", mode,
         "--host", "guard", "--port", "8080", "--path", path,
         "--duration", str(duration), "--connections", str(connections)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def mark(label):
    phases.append({"label": label, "start": round(time.time() - _t0, 2)})


def main():
    global _t0, _stop
    print(">> resetting detector + clearing mitigation")
    post("/reset")
    post("/unmitigate")
    post("/mode", {"auto": False})

    _t0 = time.time()
    th = threading.Thread(target=poller, daemon=True)
    th.start()

    print(">> phase 1/3: idle baseline (12s)")
    mark("idle")
    time.sleep(12)

    print(">> phase 2/3: legitimate load spike (20s, 6 honest clients)")
    mark("legitimate load")
    scenario("legit", 20, connections=6, path="/?ms=200")

    print(">> gap (4s)")
    mark("idle")
    time.sleep(4)

    print(">> phase 3/3: Rapid Reset attack (24s) with AUTO-MITIGATION enabled")
    post("/mode", {"auto": True})
    mark("attack + auto-mitigate")
    scenario("rapid-reset", 24, connections=8, path="/?ms=0")

    print(">> cooldown (6s)")
    mark("recovered")
    time.sleep(6)

    _stop = True
    th.join(timeout=2)
    post("/mode", {"auto": False})
    post("/unmitigate")

    write_outputs()


def write_outputs():
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["t", "client_reset_rate", "server_reset_rate",
                                          "mismatch_ratio", "alert", "mitigation_active"])
        w.writeheader()
        w.writerows(samples)
    print(f">> wrote {OUT_CSV} ({len(samples)} samples)")
    try:
        plot()
        print(f">> wrote {OUT_PNG}")
    except Exception as e:
        print(f">> plot skipped ({e}); CSV still written")


def plot():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    ts = [s["t"] for s in samples]
    crr = [s["client_reset_rate"] for s in samples]
    mit = [s["mitigation_active"] for s in samples]

    try:
        thr = get_state()["thresholds"]["rapid_reset_rate"]
    except Exception:
        thr = 50

    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(11, 5.2))
    # Phase backgrounds — deliberately NOT green, so the green mitigation wash
    # reads unambiguously as "defending".
    colors = {
        "idle": "#12161c", "legitimate load": "#132a33",
        "attack + auto-mitigate": "#2d1416", "recovered": "#12161c",
    }
    bounds = phases + [{"label": None, "start": ts[-1] if ts else 0}]
    for i in range(len(phases)):
        start = bounds[i]["start"]
        end = bounds[i + 1]["start"]
        ax.axvspan(start, end, color=colors.get(phases[i]["label"], "#12161c"), alpha=0.9, zorder=0)
        ax.text((start + end) / 2, 0.94, phases[i]["label"], transform=ax.get_xaxis_transform(),
                ha="center", va="top", fontsize=9, color="#c9d1d9",
                bbox=dict(boxstyle="round,pad=0.25", fc="#00000066", ec="none"))

    ax.plot(ts, crr, color="#f85149", lw=2, label="client reset rate (/s)", zorder=3)
    ax.axhline(thr, color="#8b949e", ls="--", lw=1.2, label=f"alert threshold ({thr}/s)", zorder=2)

    # shade when mitigation is active
    first = True
    for i in range(1, len(ts)):
        if mit[i]:
            ax.axvspan(ts[i - 1], ts[i], color="#2ea043", alpha=0.12, zorder=1,
                       label="mitigation active" if first else None)
            first = False

    ax.set_xlabel("time (s)")
    ax.set_ylabel("client reset rate (resets/s)")
    ax.set_title("HTTP/2 Rapid Reset — detection across idle, legitimate load, and attack",
                 fontsize=12, color="#e6edf3")
    ax.grid(True, color="#30363d", lw=0.5)
    ax.set_xlim(0, ts[-1] if ts else 1)
    ax.set_ylim(bottom=0)
    handles, labels = ax.get_legend_handles_labels()
    seen = dict(zip(labels, handles))
    ax.legend(seen.values(), seen.keys(), loc="upper left", framealpha=0.3, fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=140)


if __name__ == "__main__":
    main()
