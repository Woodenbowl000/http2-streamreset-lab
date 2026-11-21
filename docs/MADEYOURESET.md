# MadeYouReset (CVE-2025-8671)

MadeYouReset is the novel, research/resume-worthy half of this project. It is
now **implemented and verified end-to-end** against the pinned victim (Tomcat
10.1.43): reproduce → detect → mitigate, with the mismatch-ratio detector and
the two-panel evaluation plot.

## Why reset-rate monitoring is blind to it

In Rapid Reset the **client** floods `RST_STREAM`, so a client-reset-rate counter
catches it. In MadeYouReset the client sends *spec-legal but crafted* frames on a
stream whose request is already in flight; the frame is a protocol violation, so
the **server resets its own stream** (`RST_STREAM`, i.e. state `CLOSED_RST_TX`)
while the backend keeps processing the request. The attacker never sends a
single `RST_STREAM`, so client-reset-rate monitoring sees nothing. These are the
"Phantom Streams": closed at the protocol layer, alive at the application layer,
and bypassing the concurrent-stream limit because the protocol slot is freed the
instant the server resets.

## The detection contribution: mismatch ratio

Detection moves to the backend:

```
mismatch_ratio(t) = inflight_requests(t) / max(open_streams(t), 1)
```

- `inflight_requests` — app-layer work actually in progress (dispatched to the
  servlet and not yet truly completed/recycled).
- `open_streams` — protocol-layer streams the connector still considers open.

Under normal load the ratio hovers near 1 (every open stream has one unit of
work). Under MadeYouReset, `open_streams` collapses toward 0 (every stream is
reset the moment it opens) while `inflight_requests` climbs (the servlets keep
running), so the ratio climbs by orders of magnitude. It is EWMA-smoothed and
alerted above `MISMATCH_RATIO_THRESHOLD`, gated on server resets actually
occurring (`ewma_server > 1`).

## How it is built

**Attacker (`attacker/attack.py madeyoureset`).** A raw HTTP/2 frame engine
(stdlib sockets + `hpack` to encode the request HEADERS; the high-level `h2`
client will not emit malformed frames). For each stream it sends a complete GET
(`HEADERS`+`END_STREAM`, so the backend dispatches it) and then one crafted
frame that makes the server reset that stream. It **never** sends `RST_STREAM`.
Two modes:

- `--probe` — single diagnostic pass over all five paper primitives, reporting
  which ones this Tomcat resets its own stream on (stream error) vs. closes the
  whole connection on (connection error).
- sustained (default) — `--connections` workers, `--primitive`, paced by `--gap`
  seconds, accumulating phantom streams while a servlet stays busy for the
  backend time set by the path (`/?ms=N`).

**Signal (`victim/exporter/exporter.py`).** The exporter parses Tomcat's HTTP/2
stream-state-machine log lines
(`State changed from [X] to [Y]`) plus stream `recycle` events:

| event | meaning | metric |
|---|---|---|
| `-> OPEN` | stream opened | `victim_streams_opened`, `open_streams+1` |
| `-> HALF_CLOSED_REMOTE` | full request dispatched to servlet | `victim_requests`, `inflight+1` |
| `-> CLOSED_RST_RX` | **client** RST_STREAM | `victim_client_resets` (Rapid Reset) |
| `-> CLOSED_RST_TX` | **server** RST_STREAM | `victim_server_resets` (MadeYouReset) |
| `-> CLOSED_*` | protocol stream closed | `open_streams-1` |
| `recycled` | backend work truly finished | `inflight-1` |

`inflight` drops only on true completion (`recycled`), never on the reset — which
is exactly why a reset-but-still-processing stream stays counted. A reaper drops
streams orphaned by a torn-down connection after `INFLIGHT_TIMEOUT`, so the gauge
returns to baseline once an attack stops.

## Primitives — which ones land against Tomcat 10.1.43

The paper lists five primitives. Against this pinned Tomcat (`--probe` result):

| Primitive | Crafted frame | Tomcat response | Usable? |
|---|---|---|---|
| Zero-Increment | `WINDOW_UPDATE` increment 0 | stream `RST_STREAM` (PROTOCOL_ERROR) | **yes** |
| Window-Overflow | `WINDOW_UPDATE` overflowing 2³¹−1 | stream `RST_STREAM` (FLOW_CONTROL_ERROR) | **yes** |
| Priority-Length | `PRIORITY` frame ≠ 5 octets | stream `RST_STREAM` (FRAME_SIZE_ERROR) | **yes** |
| HHC | `HEADERS` on a half-closed stream | connection `GOAWAY` | no (connection error) |
| DHC | `DATA` on a half-closed stream | connection `GOAWAY` | no (connection error) |

**Honest finding:** this Tomcat treats a HEADERS/DATA frame on a half-closed
stream as a *connection* error (`GOAWAY`), which tears down the whole connection
and so cannot accumulate phantom streams. The three WINDOW_UPDATE/PRIORITY
primitives produce clean *stream* errors and are the working triggers. The
default is `zero-increment`.

### A required victim-config correction

For the crafted frames to produce clean per-stream resets rather than Tomcat's
overhead-protection closing the whole connection, `maxConcurrentStreams`'s
sibling `overheadCountFactor` must actually disable the overhead protection.
The lab intends this (see the victim Dockerfile: "overhead protection disabled
so the attack is reproducible"), but `overheadCountFactor="-1"` does **not**
disable it — the crafted frames still tripped `ConnectionException: Too much
overhead so the connection will be closed`. Setting `overheadCountFactor="0"`
disables it as intended, and the three primitives then reset streams cleanly.
(Tomcat's overhead protection reacting to these frames is itself a coarse,
connection-level defence — an interesting secondary observation for the report —
but the lab disables it to isolate and study the MadeYouReset stream-reset
mechanism and its backend-side detection, which is the contribution.)

## Verified result (representative run)

Sustained `zero-increment`, `/?ms=500`, 3 connections, paced:

- **Phantom streams are real.** A stream reset ~1 ms after opening still records
  a full ~500 ms backend service time in the access log before being recycled
  (`GET /?ms=500 → 200, %D ≈ 500 000 µs`). At steady state thousands of streams
  are reset-but-not-recycled.
- **Detector fires.** `mismatch_ratio` climbs from ~0 to well over 100 (threshold
  3.0) and the alert flips to `MADEYOURESET` within ~2 s — while
  `client_reset_rate` stays **exactly 0** the whole time (`victim_client_resets`
  never moves). This is the detection gap, made visible.
- **Tier-1 mitigation works.** Auto-mitigation blocks the attacking source at the
  guard; `victim_server_resets` stops, the alert clears to `NORMAL`, and the
  mismatch ratio drains back to baseline.

See `docs/evaluation.png` (the two-panel "one detector, two attacks, two signals"
plot) and `docs/EVALUATION.md`.

## Reproduce

```bash
docker compose up --build -d
./scripts/scenario.sh madeyoureset-probe          # which primitives land
./scripts/scenario.sh madeyoureset 20 3           # sustained attack (watch :8088)
python3 scripts/evaluate.py                        # regenerate the plot
```

## Limitations (honest)

- `inflight`/`open_streams` are derived from Tomcat's debug log, not from
  in-process instrumentation. They are faithful for this rate/ratio detector
  (verified against the access log), but a production-grade metric would use a
  Tomcat `Valve` incrementing on `invoke()` and decrementing on true completion,
  reading `open_streams` from the HTTP/2 connector (proposal §5.2).
- Two of the five paper primitives are connection errors on this Tomcat version,
  so they are reported honestly rather than forced.
- The log-tailing exporter must keep up with the attack's log volume; verbose
  logging is therefore scoped to just the two loggers it parses, and the attack
  is paced (`--gap`) for a controlled, reproducible demo.
