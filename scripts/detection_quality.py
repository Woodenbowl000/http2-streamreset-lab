#!/usr/bin/env python3
"""
detection_quality.py -- turns the single-trace demo into a statistical result.

For each attack it measures DETECTION LATENCY (seconds from attack start to the
first correct alert) over several trials, and over a set of BENIGN workloads it
measures the FALSE-POSITIVE rate (how often a legitimate burst raises any alert).
This is what lets the paper say "detects within X s, Y% false positives over Z
benign runs" instead of showing one hand-picked run.

Run (stack up, from the repo root):
    pip install -r scripts/requirements.txt
    python3 scripts/detection_quality.py --trials 5

Outputs docs/detection_quality.csv and a printed summary. It only drives the
attacker and reads the detector; it changes nothing in the lab.
"""
import argparse
import csv
import json
import os
import statistics
import subprocess
import time
import urllib.request

DETECTOR = os.environ.get("DETECTOR_URL", "http://127.0.0.1:9130")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT_CSV = os.path.join(ROOT, "docs", "detection_quality.csv")

# Benign workloads that must NOT raise an alert (the control set): vary the
# concurrency and the backend time so the false-positive claim covers a range,
# not one gentle run.
BENIGN = [
    {"connections": 6, "path": "/?ms=200"},
    {"connections": 12, "path": "/?ms=200"},
    {"connections": 8, "path": "/?ms=800"},
    {"connections": 16, "path": "/?ms=50"},
]
# Attacks we expect to be detected, with the alert each should raise.
ATTACKS = [
    {"mode": "rapid-reset", "alert": "RAPID_RESET", "args": ["--connections", "8", "--path", "/?ms=0"]},
    {"mode": "madeyoureset", "alert": "MADEYOURESET", "args": ["--connections", "3", "--path", "/?ms=500"]},
]
DURATION = int(os.environ.get("DQ_DURATION", "20"))


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


def run_async(mode, extra):
    cmd = ["docker", "compose", "run", "--rm", "attacker", mode,
           "--host", "guard", "--port", "8080", "--duration", str(DURATION)] + extra
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clean():
    post("/reset")
    post("/unmitigate")
    post("/mode", {"auto": False})
    time.sleep(2)


def attack_trial(mode, want_alert, extra):
    """Return detection latency in seconds, or None if never detected."""
    clean()
    t0 = time.time()
    proc = run_async(mode, extra)
    latency = None
    t_end = t0 + DURATION + 3
    while time.time() < t_end:
        try:
            if get_state().get("alert") == want_alert:
                latency = time.time() - t0
                break
        except Exception:
            pass
        time.sleep(0.25)
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    return latency


def benign_trial(cfg):
    """Return True if the benign run wrongly raised any alert (a false positive)."""
    clean()
    proc = run_async("legit", ["--connections", str(cfg["connections"]), "--path", cfg["path"]])
    false_pos = False
    t_end = time.time() + DURATION + 2
    while time.time() < t_end:
        try:
            if get_state().get("alert") != "NORMAL":
                false_pos = True
        except Exception:
            pass
        time.sleep(0.25)
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    return false_pos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    args = ap.parse_args()

    rows = []

    print("== detection latency (attacks) ==")
    for a in ATTACKS:
        lats = []
        for i in range(args.trials):
            lat = attack_trial(a["mode"], a["alert"], a["args"])
            lats.append(lat)
            rows.append({"kind": "attack", "label": a["mode"], "trial": i + 1,
                         "detected": lat is not None,
                         "latency_s": round(lat, 2) if lat is not None else ""})
            print(f"  {a['mode']:>13} trial {i+1}: "
                  + (f"{lat:.2f}s" if lat is not None else "NOT DETECTED"))
        ok = [x for x in lats if x is not None]
        tp = 100.0 * len(ok) / len(lats)
        if ok:
            print(f"  -> {a['mode']}: detected {tp:.0f}% of trials, "
                  f"median latency {statistics.median(ok):.2f}s, "
                  f"p95 {sorted(ok)[max(0, int(0.95*(len(ok)-1)))]:.2f}s")
        else:
            print(f"  -> {a['mode']}: never detected")

    print("\n== false positives (benign workloads) ==")
    fp_count = 0
    for cfg in BENIGN:
        for i in range(args.trials):
            fp = benign_trial(cfg)
            fp_count += 1 if fp else 0
            rows.append({"kind": "benign", "label": f"c{cfg['connections']} {cfg['path']}",
                         "trial": i + 1, "detected": fp, "latency_s": ""})
            print(f"  benign {cfg['connections']:>2} conns {cfg['path']:>9} trial {i+1}: "
                  + ("FALSE POSITIVE" if fp else "ok"))
    total_benign = len(BENIGN) * args.trials
    print(f"\n  -> false-positive rate: {fp_count}/{total_benign} "
          f"= {100.0*fp_count/total_benign:.1f}%")

    clean()
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["kind", "label", "trial", "detected", "latency_s"])
        w.writeheader()
        w.writerows(rows)
    print(f"[dq] wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
