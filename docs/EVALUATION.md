# Evaluation

The detector's thresholds are **derived from data, not assumed**. The evaluation
runs the same victim under three scenarios and plots the detection signal for
each, so the threshold is chosen where the attack curve cleanly separates from
the benign curves.

Run it (stack must be up):

```bash
pip install -r scripts/requirements.txt
python3 scripts/evaluate.py      # writes docs/evaluation.csv and docs/evaluation.png
```

## Scenarios

1. **Idle baseline** — victim under no load. Establishes the resting reset rate.
2. **Legitimate load spike** — 6 honest HTTP/2 clients hammering the work
   endpoint. This is the control: a real traffic burst that must *not* trip the
   detector.
3. **Rapid Reset attack** — 8 connections flooding `HEADERS`+`RST_STREAM`, with
   **auto-mitigation enabled** so the full autonomous loop is exercised.

## Result (representative run)

| Scenario | Client reset rate (max) | Client reset rate (mean) | Alert |
|---|---|---|---|
| Idle baseline | 0.0 /s | 0.0 /s | NORMAL |
| Legitimate load spike | 0.0 /s | 0.0 /s | NORMAL |
| Rapid Reset attack | ~600 /s | ~96 /s | **RAPID_RESET** |
| After auto-mitigation | ~0 /s | ~0 /s | NORMAL |

![evaluation](evaluation.png)

## Reading the plot

- Idle and legitimate-load phases sit flat on the x-axis: **honest traffic does
  not reset streams**, so the client-reset-rate detector stays silent. This is
  the direct answer to "does it just trip on any load spike?" — no.
- The attack phase spikes an order of magnitude above the `50/s` threshold.
- The green band is the window where mitigation was active; the rate collapses
  back to zero once the attacking source is blocked at the guard.

## Choosing the threshold

Any value in the wide gap between the benign ceiling (~0/s here) and the attack
floor (tens to hundreds /s) works. `50/s` is used as a safe default with large
margin on both sides. On a noisier real workload you would set it a few × above
the legitimate ceiling observed in scenario 2.

## Honest limitations

- The reset signal comes from parsing Tomcat's debug log, which captures the
  large majority (not 100%) of individual resets — fine for a **rate-based**
  detector with this much margin, but not an exact per-stream audit.
- There is a short measurement lag (log flush + tail + EWMA) between enforcement
  and the measured rate returning to zero; enforcement at the guard is immediate
  (see `guard_blocked_connections_total`).
