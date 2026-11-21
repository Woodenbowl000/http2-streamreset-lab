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


def scenario(mode, duration, connections=6, path="/?ms=200", extra=None):
    cmd = ["docker", "compose", "run", "--rm", "attacker", mode,
           "--host", "guard", "--port", "8080", "--path", path,
           "--duration", str(duration), "--connections", str(connections)]
    if extra:
        cmd += extra
    subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def mark(label):
    phases.append({"label": label, "start": round(time.time() - _t0, 2)})


def reset_clean():
    """Clear history, smoothing, and mitigation so the next phase starts fresh."""
    post("/reset")
    post("/unmitigate")
    post("/mode", {"auto": False})
    time.sleep(2)


def main():
    global _t0, _stop
    print(">> resetting detector + clearing mitigation")
    reset_clean()

    _t0 = time.time()
    th = threading.Thread(target=poller, daemon=True)
    th.start()

    # ---- Baseline + legitimate load (both detection signals must stay calm) ----
    print(">> phase 1: idle baseline (10s)")
    mark("idle")
    time.sleep(10)

    print(">> phase 2: legitimate load spike (18s, 6 honest clients)")
    mark("legitimate load")
    scenario("legit", 18, connections=6, path="/?ms=200")

    print(">> gap (4s)")
    mark("idle")
    time.sleep(4)

    # ---- Rapid Reset: caught by the client reset-rate ----
    print(">> phase 3: Rapid Reset attack (20s) with AUTO-MITIGATION")
    post("/mode", {"auto": True})
    mark("Rapid Reset\n+ mitigate")
    scenario("rapid-reset", 20, connections=8, path="/?ms=0")
    post("/mode", {"auto": False})

    print(">> recover (8s)")
    mark("recovered")
    time.sleep(8)

    # ---- MadeYouReset: INVISIBLE to reset-rate, caught by mismatch_ratio ----
    print(">> clearing smoothing before MadeYouReset phase")
    post("/reset")
    post("/unmitigate")
    mark("idle")
    time.sleep(6)

    print(">> phase 4: MadeYouReset attack (20s, zero-increment) with AUTO-MITIGATION")
    post("/mode", {"auto": True})
    mark("MadeYouReset\n+ mitigate")
    scenario("madeyoureset", 20, connections=3, path="/?ms=500",
             extra=["--primitive", "zero-increment", "--gap", "0.006"])
    post("/mode", {"auto": False})

    print(">> recover (16s — let inflight drain)")
    mark("recovered")
    time.sleep(16)

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

    ts = [s["t"] for s in samples]
    crr = [s["client_reset_rate"] for s in samples]
    mmr = [max(s["mismatch_ratio"], 1e-3) for s in samples]  # >0 for log axis
    mit = [s["mitigation_active"] for s in samples]

    try:
        th = get_state()["thresholds"]
        thr_rapid = th["rapid_reset_rate"]
        thr_mis = th["mismatch_ratio"]
    except Exception:
        thr_rapid, thr_mis = 50, 3.0

    def band_color(label):
        if label.startswith("Rapid Reset"):
            return "#2d1416"
        if label.startswith("MadeYouReset"):
            return "#2a1030"
        if label.startswith("legitimate"):
            return "#132a33"
        return "#12161c"

    plt.style.use("dark_background")
    fig, (axA, axB) = plt.subplots(2, 1, figsize=(12, 7.4), sharex=True)
    bounds = phases + [{"label": None, "start": ts[-1] if ts else 0}]

    for ax in (axA, axB):
        for i in range(len(phases)):
            start, end = bounds[i]["start"], bounds[i + 1]["start"]
            ax.axvspan(start, end, color=band_color(phases[i]["label"]), alpha=0.9, zorder=0)
        # mitigation wash (green = defending)
        first = True
        for i in range(1, len(ts)):
            if mit[i]:
                ax.axvspan(ts[i - 1], ts[i], color="#2ea043", alpha=0.14, zorder=1,
                           label="mitigation active" if first else None)
                first = False

    # phase labels across the top of the upper panel
    for i in range(len(phases)):
        start, end = bounds[i]["start"], bounds[i + 1]["start"]
        axA.text((start + end) / 2, 0.985, phases[i]["label"], transform=axA.get_xaxis_transform(),
                 ha="center", va="top", fontsize=8, color="#c9d1d9",
                 bbox=dict(boxstyle="round,pad=0.25", fc="#00000088", ec="none"))

    # Panel A — Rapid Reset signal
    axA.plot(ts, crr, color="#f85149", lw=2, label="client reset rate (/s)", zorder=3)
    axA.axhline(thr_rapid, color="#8b949e", ls="--", lw=1.2,
                label=f"Rapid Reset threshold ({thr_rapid}/s)", zorder=2)
    axA.set_ylabel("client reset rate\n(resets/s)")
    axA.set_ylim(bottom=0)
    axA.set_title("HTTP/2 stream-reset DoS — one detector, two attacks, two signals",
                  fontsize=13, color="#e6edf3")
    axA.grid(True, color="#30363d", lw=0.5)
    h, l = axA.get_legend_handles_labels()
    axA.legend(dict(zip(l, h)).values(), dict(zip(l, h)).keys(),
               loc="upper left", framealpha=0.35, fontsize=8.5)

    # Panel B — MadeYouReset signal (log scale: the attack spans orders of magnitude)
    axB.plot(ts, mmr, color="#d2a8ff", lw=2, label="mismatch ratio (inflight / open streams)", zorder=3)
    axB.axhline(thr_mis, color="#8b949e", ls="--", lw=1.2,
                label=f"MadeYouReset threshold ({thr_mis})", zorder=2)
    axB.set_yscale("log")
    axB.set_ylabel("mismatch ratio\n(log scale)")
    axB.set_xlabel("time (s)")
    axB.grid(True, which="both", color="#30363d", lw=0.5)
    h, l = axB.get_legend_handles_labels()
    axB.legend(dict(zip(l, h)).values(), dict(zip(l, h)).keys(),
               loc="upper left", framealpha=0.35, fontsize=8.5)

    axB.set_xlim(0, ts[-1] if ts else 1)
    # annotate the key point: reset-rate is BLIND to MadeYouReset
    for ph in phases:
        if ph["label"].startswith("MadeYouReset"):
            axA.annotate("reset-rate stays flat\n(blind to MadeYouReset)",
                         xy=(ph["start"] + 10, max(crr) * 0.12 + 1),
                         fontsize=8.5, color="#f0b72f", ha="center")
    fig.tight_layout()
    fig.savefig(OUT_PNG, dpi=140)


if __name__ == "__main__":
    main()
