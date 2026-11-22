#!/usr/bin/env python3
"""
calibrate.py -- derive the detector thresholds from the benign baseline instead
of assuming them. The report argues thresholds should be chosen from data; this
script does it mechanically: it drives a set of legitimate workloads, watches the
highest value each detection signal reaches under that honest load (the "benign
ceiling"), and recommends a threshold a safety factor above it.

Run (stack up, from the repo root):
    pip install -r scripts/requirements.txt
    python3 scripts/calibrate.py

It prints the recommended RAPID_RESET_RATE_THRESHOLD and MISMATCH_RATIO_THRESHOLD
to set on the detector service in docker-compose.yml. It changes nothing itself.
"""
import json
import os
import subprocess
import time
import urllib.request

DETECTOR = os.environ.get("DETECTOR_URL", "http://127.0.0.1:9130")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Benign workloads to profile (vary concurrency and backend time so the ceiling
# is measured over a range of honest load, not one gentle burst).
BENIGN = [
    {"connections": 6, "path": "/?ms=200"},
    {"connections": 12, "path": "/?ms=200"},
    {"connections": 16, "path": "/?ms=50"},
    {"connections": 8, "path": "/?ms=800"},
]
DURATION = int(os.environ.get("CAL_DURATION", "15"))
SAFETY_FACTOR = float(os.environ.get("CAL_SAFETY_FACTOR", "3.0"))
# Floors so a near-zero benign ceiling does not yield a hair-trigger threshold.
RESET_FLOOR = float(os.environ.get("CAL_RESET_FLOOR", "20"))
MISMATCH_FLOOR = float(os.environ.get("CAL_MISMATCH_FLOOR", "2.0"))


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


def run_legit(cfg):
    cmd = ["docker", "compose", "run", "--rm", "attacker", "legit",
           "--host", "guard", "--port", "8080", "--duration", str(DURATION),
           "--connections", str(cfg["connections"]), "--path", cfg["path"]]
    return subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ceil_reset = 0.0
    ceil_mismatch = 0.0
    for cfg in BENIGN:
        post("/reset")
        post("/mode", {"auto": False})
        time.sleep(2)
        proc = run_legit(cfg)
        t_end = time.time() + DURATION + 2
        peak_r = peak_m = 0.0
        while time.time() < t_end:
            try:
                s = get_state()
                peak_r = max(peak_r, float(s.get("client_reset_rate", 0.0)))
                peak_m = max(peak_m, float(s.get("mismatch_ratio", 0.0)))
            except Exception:
                pass
            time.sleep(0.5)
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        ceil_reset = max(ceil_reset, peak_r)
        ceil_mismatch = max(ceil_mismatch, peak_m)
        print(f"benign {cfg['connections']:>2} conns {cfg['path']:>9}: "
              f"reset ceiling {peak_r:.1f}/s, mismatch ceiling {peak_m:.2f}")

    post("/reset")
    rec_reset = max(RESET_FLOOR, round(ceil_reset * SAFETY_FACTOR, 1))
    rec_mismatch = max(MISMATCH_FLOOR, round(ceil_mismatch * SAFETY_FACTOR, 2))
    print("\n=== recommended thresholds (benign ceiling x "
          f"{SAFETY_FACTOR:g}, with floors) ===")
    print(f"  benign reset ceiling    = {ceil_reset:.1f}/s  ->  "
          f"RAPID_RESET_RATE_THRESHOLD: \"{rec_reset:g}\"")
    print(f"  benign mismatch ceiling = {ceil_mismatch:.2f}   ->  "
          f"MISMATCH_RATIO_THRESHOLD:   \"{rec_mismatch:g}\"")
    print("\nSet these on the detector service in docker-compose.yml and rebuild.")


if __name__ == "__main__":
    main()
