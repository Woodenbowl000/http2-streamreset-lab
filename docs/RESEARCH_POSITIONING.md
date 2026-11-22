# StreamShield — research positioning and path to publication

Written for: Group 9 (StreamShield) and the course advisor. This is an internal
planning document, not the paper. It records what the literature already
contains, what in StreamShield is genuinely new, what is not, and the concrete
work needed to turn the CEP into a publishable paper. Every external claim below
is grounded in a source read during the literature search (listed at the end).

## 1. One-paragraph verdict

StreamShield's attack side (Rapid Reset, MadeYouReset) is **not** novel: the
MadeYouReset attack was published at **IEEE S&P 2026** by Bar Nahum, Bremler-Barr
and Harel, which is the authoritative source and must be cited and treated as
prior art, not as our contribution. StreamShield's **defence side has a real,
defensible novelty**, but only if it is framed precisely: we build and evaluate
an **online detector that measures the protocol-versus-backend divergence**
(our `mismatch_ratio`) that the S&P paper names "Phantom Streams" and explicitly
calls *difficult to measure*, and we do it in a **reproducible, containerized
reproduce-detect-mitigate testbed**. That is a *systems and detection*
contribution, publishable at a **workshop or a solid journal**, not at a top-4
conference on its own. The connection-scoped reset-budget mitigation we added is
the **standard industry fix** ("Stream Reset Limits") and must be presented as an
implementation of known defence, not as new.

## 2. The state of the art (what already exists)

### 2.1 The attacks are published and well-covered
- **MadeYouReset — IEEE S&P 2026**, Bar Nahum, Bremler-Barr, Harel, Tel Aviv
  University. Title: *MadeYouReset: Exploiting HTTP/2 Server-Side Resets for
  Large-Scale DoS*. This paper defines **Phantom Streams** as the discrepancy
  between protocol-level stream state and backend execution, enumerates the
  crafted-frame primitives, tests many implementations (Netty, Jetty, Tomcat,
  H2O, Rust `h2`, Apple SwiftNIO), and devotes a section to detection and
  mitigation. **This is prior art for everything about the attack.**
- **Rapid Reset — CVE-2023-44487** (Google/Cloudflare/AWS, Oct 2023). The direct,
  client-initiated case; same Phantom Streams root cause.

### 2.2 What the S&P paper already says about defence (read closely)
This is the most important part for us, because it bounds our novelty.
- **Detection (their §8.1):** their proposed detection signal is *"an unusually
  high number of RST_STREAM frames"* in the **server-to-client** direction. They
  note many IDS/firewalls watch one direction only and miss it, and that
  detection needs visibility beneath TLS (a WAF or reverse proxy). They do **not**
  build a detector, do not propose a work-vs-stream ratio as a detection signal,
  and do not evaluate detection.
- **Mitigation (their §8.2):** three strategies. (1) **Stream Reset Limits** —
  close the connection after N client-or-server RST_STREAMs; they report *all*
  vulnerable vendors adopted this (e.g. patched Netty closes after ~30). (2)
  **Backend Concurrency Limits** — bound in-flight backend work per connection,
  independent of the active-stream counter; they call this effective in principle
  but say measuring/enforcing *"asymmetry between frontend streams and backend
  work on a per-connection basis"* is **"difficult"**, and **"further amplified"**
  in proxy deployments; only Go `net/http2` and HAProxy do partial versions. (3)
  **End-to-end cancellation** — propagate cancel into the backend; hard, high
  developer burden.

### 2.3 Detection prior art we must compare against
- **FineLame (USENIX ATC 2019):** eBPF, detects *asymmetric* application-layer
  DoS in-flight by modelling per-request resource use (ReDoS, Billion Laughs,
  Slowloris).
- **Coda (IEEE TSC 2023):** eBPF, runtime detection of application-layer
  CPU-exhaustion DoS **in containers**, flags a connection whose CPU time differs
  statistically from legitimate ones.
- Both watch **per-request resource cost**. StreamShield watches a **protocol
  invariant** (in-flight requests vs open streams). That is the clean technical
  difference, and these two are the baselines a reviewer will ask about.
- Older HTTP/2 DoS detection: slow-rate HTTP/2 DoS detection (2017), low-rate
  HTTP/2 DoS (2015), "Slow HTTP/2 DoS in the Wild" (event-sequence detection,
  2022). Flow-based HTTP(S) DDoS detection: **Tanchun** (2026, decryption-free
  flow + deep learning). None of these detect server-induced stream-reset abuse.

### 2.4 The cloud-native DoS lineage we belong to (and should cite)
The same group that found MadeYouReset built a decade of "indirection / economic"
DoS-on-cloud-elasticity work. Our container framing sits directly in it:
- **Yo-Yo attack** — DDoS on cloud auto-scaling, INFOCOM 2017.
- **Kubernetes Yo-Yo** detection, CLOSER 2021.
- **Tandem attack** — DDoS on microservice auto-scaling, INFOCOM 2024.
- **Cost of Retrying** — exploiting retry mechanisms, CoNEXT 2023.
Framing StreamShield as "detecting an indirection DoS in a containerized service"
connects it to this line rather than leaving it as a one-off lab.

## 3. StreamShield's defensible novelty (state it exactly like this)

1. **The mismatch ratio as an online *detection* signal.** The S&P paper poses
   measuring the frontend-stream / backend-work asymmetry as a *mitigation* and
   calls it "difficult to measure," especially behind a proxy. StreamShield
   *measures* it (`inflight / max(open_streams,1)`), shows it separates benign
   from attack by two orders of magnitude, and raises alerts on it. Reframing
   their "hard-to-measure mitigation quantity" into a working detection invariant
   is the core contribution.
2. **A unified two-signal detector and an empirical detection gap.** One detector
   covers both attacks (client reset rate for Rapid Reset, mismatch ratio for
   MadeYouReset) and *shows with a measurement* that reset-rate monitoring is
   blind to MadeYouReset (client reset rate pinned at 0 while the ratio exceeds
   100). The S&P paper argues this blindness qualitatively; we demonstrate it.
3. **A reproducible, containerized reproduce→detect→mitigate testbed** against a
   pinned vulnerable server, with the attacks, the detector, the enforcement
   point, and a one-command evaluation. This is the experimentation/systems
   contribution and the natural fit for a testbed-friendly venue.
4. **Availability-centric evaluation and an honest attribution analysis.** We
   measure the availability a legitimate user actually experiences (success rate,
   latency) before and after mitigation, and we document precisely why per-source
   attribution of MadeYouReset is unreliable behind an L4 proxy.

### 3b. Additional novelty now implemented in the repo

Beyond the mismatch ratio, the following were added so the contribution is not a
single idea (all additive; the verified detect/mitigate path is unchanged):

5. **Direct phantom-stream count** (`victim_phantom_streams = inflight -
   open_streams`, exporter + detector). An absolute measure of the paper's
   Phantom Streams, steadier than the ratio when open-streams is near zero, and
   read directly as "requests running for already-closed streams." Companion
   signal to the ratio.
6. **Paced-attacker robustness result** (`scripts/adaptive_experiment.py`). The
   strongest new result: there is a regime (slow resets, long backend time) where
   a MadeYouReset stays under the reset-limit budget, so the vendor fix never
   fires, while the mismatch ratio still detects it. This is the clearest
   statement of what a divergence-based detector adds over the rate-based fix.
   *(Implemented; run it to produce the numbers/plot.)*
7. **Detection-quality harness** (`scripts/detection_quality.py`): detection
   latency and false-positive rate over repeated trials and a range of benign
   workloads — turns the single trace into a statistical claim.
8. **Data-driven threshold calibration** (`scripts/calibrate.py`): derives the
   thresholds from the measured benign ceiling rather than assuming them.

None of these are verified by a run yet (no Docker in the authoring environment);
the code compiles and is additive. Validate on a real stack before quoting
numbers.

## 4. What is NOT novel (be honest, or a reviewer will be for you)

- **The attacks** — prior art (S&P 2026, CVE-2023-44487).
- **The "Phantom Streams" concept and term** — theirs; cite it, do not reinvent
  it. Our `mismatch_ratio` is a *measurement* of their phenomenon.
- **Connection-scoped reset-budget + GOAWAY(ENHANCE_YOUR_CALM)** — this is their
  **Stream Reset Limits**, the fix every vendor shipped. Present StreamShield's
  version as *implementing and validating the standard defence in the testbed*,
  not as new. (The report has been corrected to say this.)
- **Rate-based client-reset detection** — the known Rapid Reset signal; we use it
  as the deliberately-blind baseline, which is fine, but it is not new.

## 5. The gap, as a single thesis sentence

> Existing defences against HTTP/2 stream-reset DoS either count reset frames
> (blind to, or coarse against, the server-induced variant) or enforce
> per-connection limits; **none provides an online detector that measures the
> protocol-vs-backend "Phantom Streams" divergence directly** and distinguishes a
> genuine attack from a benign load spike — which is what StreamShield does, in a
> reproducible containerized testbed.

## 6. What a reviewer will demand — the roadmap to clear the bar

The CEP demonstrates the idea; a paper needs the idea to survive scrutiny. In
rough priority:

1. **More than one server implementation.** Right now only Tomcat 10.1.43. The
   mismatch-ratio claim is strongest if it holds across implementations the S&P
   paper lists (Netty, Jetty, H2O). At minimum, test two. This is the single
   biggest lift from "lab" to "paper."
2. **Baseline comparison.** Run StreamShield's detector head-to-head against (a)
   server-reset-rate counting (the S&P paper's own proposal) and (b) a
   resource-exhaustion detector in the spirit of Coda/FineLame. Show what the
   mismatch ratio catches or does earlier/cleaner.
3. **Detection quality, not just a trace.** Report detection latency, and a
   ROC/precision-recall style result over many runs and a *range* of benign
   workloads (bursty, slow-backend, high-concurrency), so the false-positive
   claim is statistical, not a single run. Pick thresholds on a train split,
   report on a test split.
4. **Adaptive attacker.** Show what a MadeYouReset attacker who *paces* resets to
   stay under a reset-budget does to (a) the reset-limit mitigation and (b) the
   mismatch-ratio detector. If the ratio still catches a slowed attack that reset
   limits miss, that is a strong result.
5. **Container resource evidence.** Tie detection to measured cgroup CPU/memory
   (cAdvisor is already in the stack) so the "containerized impact" framing is
   backed by numbers, connecting to the Yo-Yo/Tandem lineage.
6. **Complete the availability table** (scripts/availability_probe.py) for both
   mitigations, so "preserves availability" is quantified.
7. **In-process instrumentation.** Replace the log-derived `open_streams` with a
   connector-level read so the signal is not tied to debug-log parsing; this
   removes the most obvious methodological objection.

## 7. Candidate venues (ranked by realistic fit)

Do a preprint on **arXiv** first (establishes a timestamp and is citable), then:

1. **CSET** (Cyber Security Experimentation and Test; from 2026 co-located with
   ACSAC, IEEE proceedings). Best fit: it rewards reproducible testbeds and
   rigorous methodology. Check the 2027 cycle dates.
2. **ARES — Emerging Network Security (ENS) workshop** (lists "DDoS Detection &
   Mitigation"). Realistic, recurring, accepts systems/testbed security work.
3. **Journal route — *Computers & Security* (Elsevier) or *IEEE Access*.** Good
   if the evaluation in §6 is built out; no fixed deadline. *IEEE Transactions on
   Services Computing* (where Coda appeared) is the stretch target if the
   multi-implementation + baseline work is done well.
4. **MADWeb (NDSS workshop)** and **WTMC** — web/measurement security workshops;
   fit if framed as a measurement of the detection gap.

Honest expectation: with the current single-implementation lab, aim for a
workshop (ARES ENS / CSET) or *IEEE Access*. With §6 items 1–4 done, a stronger
journal (*Computers & Security* / TSC) becomes realistic. The attack itself
cannot carry a top-4 paper because it is already published.

## 8. Revised framing for the paper

- **Working title:** *StreamShield: Detecting the Phantom-Stream Divergence of
  HTTP/2 Stream-Reset DoS in Containerized Services.*
- **Thesis:** server-induced stream resets create a measurable gap between
  protocol state and backend work; monitoring that gap detects an attack that
  reset-frame counting cannot, without per-source attribution.
- **Contributions:** (1) the mismatch-ratio detector and the detection-gap
  demonstration; (2) a containerized reproduce-detect-mitigate testbed; (3) an
  availability-centric and attribution-honest evaluation; (4) comparison against
  reset-rate and resource-exhaustion baselines across N server implementations
  (the work of §6).
- **Related work must cite:** the S&P 2026 MadeYouReset paper (prominently, as
  prior art), Rapid Reset, FineLame, Coda, and the Yo-Yo / Tandem cloud-native
  DoS lineage.

## 9. Immediate next steps (checklist)

- [ ] Read the full S&P 2026 PDF together; agree on exactly which claims are
      theirs vs ours (Section 2.2 above is the summary).
- [x] Correct every place the report implies the attack or the reset-limit fix is
      our novelty (done; abstract, intro bullet, §5, §6.4).
- [x] Add a Related Work section to the report (done; §\ref{sec:related}).
- [x] Add a second detection signal (phantom-stream count) and the paced-attacker,
      detection-quality, and calibration harnesses (done; needs a run to produce
      numbers).
- [ ] RUN the new harnesses on a real stack: `scripts/adaptive_experiment.py`
      (the headline evasion result), `scripts/detection_quality.py`,
      `scripts/calibrate.py`, `scripts/availability_probe.py`; paste numbers in.
- [ ] Stand up a second server implementation (Netty or Jetty) in the testbed.
- [ ] Build the baseline comparison against server-reset-rate and a Coda-style
      resource threshold.
- [ ] Post an arXiv preprint; then target CSET 2027 / ARES ENS or Computers &
      Security.

## Sources consulted (primary)

- Bar Nahum, Bremler-Barr, Harel. *MadeYouReset: Exploiting HTTP/2 Server-Side
  Resets for Large-Scale DoS.* IEEE S&P 2026. (full text read)
- Bremler-Barr, Brosh, Sides. *DDoS Attack on Cloud Auto-scaling Mechanisms.*
  INFOCOM 2017. Bremler-Barr et al. *Tandem Attack.* INFOCOM 2024.
- Demoulin et al. *FineLame.* USENIX ATC 2019. Zhan et al. *Coda.* IEEE TSC 2023.
- CVE-2023-44487 (Rapid Reset); CVE-2025-8671 + CERT/CC VU#767506 (MadeYouReset);
  Google/Cloudflare/CERT-EU mitigation guidance; Imperva and Jetty advisories.
- Deepness Lab publication list (deepness-lab.org). Tanchun (arXiv 2610.18406),
  eBPF security SLR (arXiv 2608.27511) for related-work breadth.
