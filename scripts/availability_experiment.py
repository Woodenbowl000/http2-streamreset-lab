#!/usr/bin/env python3
"""
availability_experiment.py -- produces the whole availability table in one run,
so the "preserves service availability" claim is a measurement, not an assertion.

It runs three phases back to back, each with a set of honest HTTP/2 clients
hitting the victim while it records their success rate and latency:
  1. Legitimate load (baseline) -- no attack.
  2. Attack, no mitigation      -- a MadeYouReset runs; auto-mitigation OFF.
  3. Attack, with mitigation    -- the same attack; auto-mitigation ON, so the
                                   detector blocks the attacking source.

Expected shape: phase 2 lowers the success rate and raises latency for the
honest clients; phase 3 brings them back toward the phase-1 baseline.

Run (stack up, from the repo root):
    pip install -r scripts/requirements.txt
    python3 scripts/availability_experiment.py

Writes docs/availability.csv and prints the table. It only drives the attacker
and the detector and measures as a normal client; it changes nothing in the lab.
"""
import csv
import json
import os
import subprocess
import threading
import time
import urllib.request

from availability_probe import one_request, pct   # same folder (scripts/)

DETECTOR = os.environ.get("DETECTOR_URL", "http://127.0.0.1:9130")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_CSV = os.path.join(ROOT, "docs", "availability.csv")

HOST = os.environ.get("PROBE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PROBE_PORT", "8080"))
PATH = os.environ.get("PROBE_PATH", "/?ms=200")
CLIENTS = int(os.environ.get("PROBE_CLIENTS", "4"))
DURATION = int(os.environ.get("AV_DURATION", "30"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "5.0"))
# Attack used for phases 2 and 3.
ATK_PATH = os.environ.get("AV_ATK_PATH", "/?ms=500")
ATK_CONNS = int(os.environ.get("AV_ATK_CONNS", "3"))


def post(path, obj=None):
    data = json.dumps(obj).encode() if obj is not None else b""
    req = urllib.request.Request(DETECTOR + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=3).read()
    except Exception:
        pass


def run_phase(label, attack=False, auto_mit=False):
    post("/reset")
    post("/unmitigate")
    post("/mode", {"auto": auto_mit})
    time.sleep(2)

    results = {"ok": 0, "fail": 0, "latencies": []}
    lock = threading.Lock()
    deadline = time.time() + DURATION

    def worker():
        while time.time() < deadline:
            ms = one_request(HOST, PORT, PATH, TIMEOUT)
            with lock:
                if ms is None:
                    results["fail"] += 1
                else:
                    results["ok"] += 1
                    results["latencies"].append(ms)

    threads = [threading.Thread(target=worker) for _ in range(CLIENTS)]
    for t in threads:
        t.start()

    proc = None
    if attack:
        proc = subprocess.Popen(
            ["docker", "compose", "run", "--rm", "attacker", "madeyoureset",
             "--host", "guard", "--port", "8080", "--path", ATK_PATH,
             "--duration", str(DURATION), "--connections", str(ATK_CONNS)],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for t in threads:
        t.join()
    if proc is not None:
        try:
            proc.wait(timeout=15)
        except Exception:
            proc.kill()

    post("/unmitigate")
    post("/mode", {"auto": False})

    lat = results["latencies"]
    total = results["ok"] + results["fail"]
    return {
        "phase": label,
        "requests": total,
        "success_rate_pct": round(100.0 * results["ok"] / total, 1) if total else 0.0,
        "latency_ms_p50": round(pct(lat, 50), 1) if lat else None,
        "latency_ms_p95": round(pct(lat, 95), 1) if lat else None,
    }


def main():
    phases = [
        ("Legitimate load (baseline)", dict(attack=False, auto_mit=False)),
        ("Attack, no mitigation",      dict(attack=True,  auto_mit=False)),
        ("Attack, with mitigation",    dict(attack=True,  auto_mit=True)),
    ]
    rows = []
    print(f"{'phase':<28} {'success%':>9} {'p50(ms)':>8} {'p95(ms)':>8} {'reqs':>6}")
    for label, kw in phases:
        r = run_phase(label, **kw)
        rows.append(r)
        print(f"{r['phase']:<28} {r['success_rate_pct']:>9} "
              f"{str(r['latency_ms_p50']):>8} {str(r['latency_ms_p95']):>8} {r['requests']:>6}")

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["phase", "requests", "success_rate_pct",
                                          "latency_ms_p50", "latency_ms_p95"])
        w.writeheader()
        w.writerows(rows)
    print(f"\n[availability] wrote {OUT_CSV}")

    # Figure for the report's fig:availability slot (docs/figures/fig-availability.png).
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        labels = ["baseline", "attack\n(no mit.)", "attack\n(mitigated)"]
        succ = [r["success_rate_pct"] for r in rows]
        p50 = [r["latency_ms_p50"] or 0 for r in rows]
        p95 = [r["latency_ms_p95"] or 0 for r in rows]
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(6, 5), sharex=True)
        ax1.bar(labels, succ, color=["tab:green", "tab:red", "tab:blue"])
        ax1.set_ylabel("success rate (%)")
        ax1.set_ylim(0, 105)
        ax1.set_title("Legitimate-user availability per phase")
        x = range(len(labels))
        ax2.bar([i - 0.18 for i in x], p50, width=0.36, label="p50", color="tab:gray")
        ax2.bar([i + 0.18 for i in x], p95, width=0.36, label="p95", color="tab:orange")
        ax2.set_xticks(list(x))
        ax2.set_xticklabels(labels)
        ax2.set_ylabel("latency (ms)")
        ax2.legend()
        fig.tight_layout()
        figpath = os.path.join(ROOT, "docs", "figures", "fig-availability.png")
        os.makedirs(os.path.dirname(figpath), exist_ok=True)
        fig.savefig(figpath, dpi=130)
        print(f"[availability] wrote {figpath}")
    except Exception as e:
        print(f"[availability] plot skipped ({e})")


if __name__ == "__main__":
    main()
