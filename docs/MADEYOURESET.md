# MadeYouReset (CVE-2025-8671) — Week-1 research spike

MadeYouReset is the novel, resume/research-worthy half of this project. It is
**scaffolded, not finished**, exactly as the proposal's Section 8 fallback plan
intends: the working, demoable deliverable is Rapid Reset; MadeYouReset is the
forward-looking contribution to develop if time allows.

## Why reset-rate monitoring is blind to it

In Rapid Reset the **client** floods `RST_STREAM`, so a client-reset-rate counter
catches it. In MadeYouReset the client sends *spec-legal but crafted* frames
(e.g. `WINDOW_UPDATE` with increment 0, `PRIORITY`/frames on a half-closed or
idle stream) that make the **server reset its own stream** — while the backend
keeps processing the request. No client reset flood ever appears.

## The detection contribution: mismatch ratio

Detection moves to the backend:

```
mismatch_ratio(t) = inflight_requests(t) / max(open_streams(t), 1)
```

- `inflight_requests` — app-layer work actually in progress.
- `open_streams` — protocol-layer streams the connector still considers open.

Under normal load the ratio hovers near 1. Under MadeYouReset, `open_streams`
stays bounded by the server's concurrent-stream limit while `inflight_requests`
climbs, so the ratio climbs. It is EWMA-smoothed and alerted above a threshold
chosen from evaluation data. The lab already exposes `victim_mismatch_ratio`,
`victim_server_resets`, and a `MADEYOURESET` alert path in the detector.

## What is already wired

- The victim (Tomcat 10.1.43) is vulnerable to CVE-2025-8671.
- Server-initiated resets are detectable in the debug log as `CLOSED_RST_TX`
  and counted as `victim_server_resets`.
- The detector raises `MADEYOURESET` when the smoothed mismatch ratio exceeds
  `MISMATCH_RATIO_THRESHOLD` and server resets are occurring.
- `attacker/attack.py madeyoureset` sends a first candidate crafted frame
  (`WINDOW_UPDATE` increment 0) as a starting point.

## The open task (this is the research)

1. **Find the trigger.** Run `./scripts/scenario.sh madeyoureset` and watch
   `victim_server_resets` / `CLOSED_RST_TX` in the victim log. Try the candidate
   patterns (WINDOW_UPDATE inc 0; PRIORITY on idle stream; DATA/HEADERS on a
   half-closed-remote stream). Keep the pattern(s) this pinned Tomcat actually
   resets on.
2. **Sustain it.** Turn the winning pattern into a sustained client (like the
   rapid-reset worker) that keeps many requests "in flight" at the backend while
   the server resets their streams.
3. **Tighten `inflight` / `open_streams`.** The current gauges are debug-log
   approximations. For a precise metric, add a Tomcat `Valve` that increments
   `inflight` in `invoke()` and decrements on true completion, and read
   `open_streams` from the HTTP/2 connector. (Proposal §5.2.)
4. **Re-run the three-scenario evaluation** on `mismatch_ratio` and pick the
   threshold, exactly as done for Rapid Reset.

## Fallbacks (from the proposal)

If the crafted-frame trigger does not land in time, Rapid Reset remains the
complete working deliverable and MadeYouReset is written up analytically with
the CVE, disclosure, and mismatch-ratio design as the proposed contribution.
