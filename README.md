# HTTP/2 Stream-Reset Denial-of-Service Lab

A containerized, local-only laboratory for reproducing, observing, and mitigating
two HTTP/2 denial-of-service techniques:

| Technique | CVE | What it does |
|---|---|---|
| Rapid Reset | CVE-2023-44487 | The client rapidly creates streams and immediately sends `RST_STREAM` for each one. |
| MadeYouReset | CVE-2025-8671 | The client sends crafted protocol frames that cause the server to reset streams while the servlet continues processing. |

This repository provides both a vulnerable target and defensive components:

```text
attacker -> guard -> victim -> victim-exporter -> detector -> dashboard
                \                                      /
                 ---------- blocklist control ----------
```

The project is intended for **authorized academic and security lab use only**.
It runs on an isolated Docker network and deliberately uses a pre-patch Tomcat
server. Do not expose this stack to the public internet or run the attacker
against systems you do not own.

---

## What you will demonstrate

1. Normal HTTP/2 traffic does not trigger an alert.
2. Rapid Reset produces a high client-initiated reset rate.
3. MadeYouReset produces a high backend mismatch ratio while the client reset
   rate remains at or near zero.
4. Automatic or manual mitigation blocks the responsible source IP at the guard.
5. After mitigation, the victim and detector return toward their normal state.

---

## Repository layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Starts and connects the lab services |
| `attacker/` | HTTP/2 traffic generator and crafted-frame attack engine |
| `victim/` | Pinned Tomcat 10.1.43 victim, servlet, and log configuration |
| `victim/exporter/` | Parses Tomcat HTTP/2 logs into metrics |
| `guard/` | Raw TCP/HTTP/2 proxy and source-IP blocklist |
| `detection/` | Detection logic, EWMA smoothing, API, and mitigation control |
| `dashboard/` | Browser UI for charts, scenarios, and mitigation |
| `scripts/` | Scenario runner and full evaluation runner |
| `prometheus/` | Optional Prometheus configuration |
| `docs/` | Evaluation and technical documentation |

---

## Architecture

### Victim

The victim is Apache Tomcat `10.1.43`, with HTTP/2 enabled over cleartext h2c.
The servlet in `victim/webapp/index.jsp` accepts `?ms=N`, where `N` is a simulated
backend-processing delay from 0 to 10,000 milliseconds.

For example:

```text
/?ms=500
```

simulates 500 milliseconds of backend work.

### Victim exporter

Tomcat's HTTP/2 debug logger exposes stream state transitions. The exporter tails
the Tomcat log and calculates:

- `victim_client_resets`
- `victim_server_resets`
- `victim_open_streams`
- `victim_inflight_requests`
- `victim_mismatch_ratio`

The key MadeYouReset metric is:

```text
mismatch_ratio = inflight_requests / max(open_streams, 1)
```

Normal traffic normally keeps the ratio near `1`. MadeYouReset can push it far
above `1` because backend work continues after the protocol stream has been reset.

### Guard

The guard is an L4 TCP proxy in front of Tomcat. It:

- forwards HTTP/2 bytes unchanged;
- counts resets seen in each traffic direction;
- tracks live connections per source IP;
- closes active connections from a blocked source;
- refuses future connections from a blocked source.

### Detector

The detector polls the exporter and guard once per second.

| Signal | Detects |
|---|---|
| EWMA-smoothed client reset rate | Rapid Reset |
| EWMA-smoothed mismatch ratio plus server reset activity | MadeYouReset |

Default thresholds are:

| Setting | Default |
|---|---:|
| Rapid Reset client reset rate | 50 resets/second |
| MadeYouReset mismatch ratio | 3.0 |
| EWMA smoothing factor | 0.4 |
| Block cooldown | 60 seconds |
| Automatic mitigation | Disabled |

### Dashboard

The dashboard provides live charts and controls on `http://localhost:8088`.

The dashboard can launch only fixed, predefined lab scenarios. It cannot be
used to specify an arbitrary target or arbitrary attacker command.

---

## Requirements

Install all of the following before starting:

### Docker

- Docker Engine or Docker Desktop
- Docker Compose v2
- Linux containers enabled

Verify the tools:

```powershell
docker version
docker compose version
```

`docker compose version` must work. The older `docker-compose` command is not
required.

### Dashboard attack buttons

The dashboard's Run buttons launch attacker containers through Docker.
Consequently, Docker Desktop must be running with Linux containers enabled.

On Windows, use the repository in a normal local directory such as:

```text
M:\IS CEP\http2-streamreset-lab
```

The dashboard Docker socket mount is a Unix-oriented Docker feature. The lab
has been designed for Docker Desktop with its Linux container engine.

### Optional host evaluation

The evaluation script needs Python and Matplotlib on the host:

```powershell
py -m pip install -r scripts/requirements.txt
```

The attacker, victim, detector, exporter, guard, and dashboard dependencies
are installed inside Docker containers and do not need to be installed
manually on the host.

---

## Quick start

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)
installed and **running** (wait for "Engine running"), and Python 3 on the host
if you want to run the evaluation scripts. The first `docker compose up --build`
pulls the base images and takes a few minutes.

Open a terminal at the repository root.

The repository root is the directory containing `docker-compose.yml`.

### Windows PowerShell

```powershell
cd "M:\IS CEP\http2-streamreset-lab"
docker compose up --build -d
docker compose ps
```

### macOS/Linux

```bash
cd /path/to/http2-streamreset-lab
docker compose up --build -d
docker compose ps
```

Wait until the container list reports the core services as running.

Open the dashboard:

```text
http://localhost:8088
```

The dashboard is intentionally bound to loopback so it is not exposed to other
machines on the local network.

Other endpoints:

| Endpoint | Purpose |
|---|---|
| `http://localhost:8088` | Live lab dashboard |
| `http://localhost:8080` | Guard HTTP/2 entry point |
| `http://localhost:9130/state` | Detector state JSON |
| `http://localhost:9130/metrics` | Detector metrics |
| `http://localhost:9090` | Prometheus, only with the metrics profile |
| `http://localhost:8081` | cAdvisor, only with the metrics profile |

---

## Run the lab scenarios

The Bash scenario runner is available on Linux, macOS, Git Bash, and WSL:

```bash
./scripts/scenario.sh legit
./scripts/scenario.sh rapid-reset
./scripts/scenario.sh madeyoureset-probe
./scripts/scenario.sh madeyoureset 20 3
```

On Windows PowerShell without Bash, run the equivalent `docker compose` commands:

```powershell
docker compose run --rm attacker legit --host guard --port 8080 --path "/?ms=200" --duration 30 --connections 6

docker compose run --rm attacker rapid-reset --host guard --port 8080 --path "/?ms=0" --duration 30 --connections 6

docker compose run --rm attacker madeyoureset --host guard --port 8080 --path "/?ms=500" --duration 20 --connections 3 --probe

docker compose run --rm attacker madeyoureset --host guard --port 8080 --path "/?ms=500" --duration 20 --connections 3 --primitive zero-increment
```

### 1. Legitimate load

```bash
./scripts/scenario.sh legit
```

This sends normal HTTP/2 requests that wait for the response.

Expected dashboard result:

- `NORMAL`
- Client reset rate near zero
- Mismatch ratio near `1`

### 2. Rapid Reset

```bash
./scripts/scenario.sh rapid-reset
```

This creates multiple HTTP/2 connections and floods `HEADERS` plus `RST_STREAM`.

Expected dashboard result:

- `RAPID_RESET`
- High client reset rate
- Source IP attributed to the Rapid Reset signal

To mitigate manually, click **Mitigate Rapid Reset** in the dashboard.

To enable automatic mitigation, enable **Auto-mitigate on alert** before
starting the attack.

### 3. MadeYouReset probe

```bash
./scripts/scenario.sh madeyoureset-probe
```

This sends each supported crafted frame once and reports whether Tomcat:

- returns `RST_STREAM`, making the primitive usable; or
- returns `GOAWAY`, making it a connection-level event.

For the pinned Tomcat version, the working primitives are normally:

- `zero-increment`
- `window-overflow`
- `priority-length`

### 4. Sustained MadeYouReset

```bash
./scripts/scenario.sh madeyoureset 20 3
```

The arguments are:

```text
duration in seconds
number of attacker connections
optional primitive
```

Example using the window-overflow primitive:

```bash
./scripts/scenario.sh madeyoureset 20 3 window-overflow
```

Expected dashboard result:

- `MADEYOURESET`
- Client reset rate remains at or near zero
- Server reset activity is present
- Mismatch ratio rises substantially

---

## Run from the dashboard

The dashboard has direct buttons for:

- Run Rapid Reset
- Mitigate Rapid Reset
- Run MadeYouReset
- Mitigate MadeYouReset
- Clear mitigation
- Toggle automatic mitigation

These buttons launch fixed 30-second Rapid Reset and 20-second MadeYouReset
scenarios. Docker Desktop must be running and Linux containers must be selected.

To reset a scenario cleanly:

1. Click **Clear mitigation**.
2. Wait for the mismatch ratio to drain.
3. Run the next scenario.

---

## Run the full evaluation

The evaluation runner executes:

1. Idle baseline
2. Legitimate load
3. Rapid Reset
4. MadeYouReset
5. Recovery periods

Install Matplotlib on the host:

```powershell
py -m pip install -r scripts/requirements.txt
```

Then run:

```powershell
py scripts/evaluate.py
```

The script writes:

```text
docs/evaluation.csv
docs/evaluation.png
```

The CSV contains the time series; the PNG contains the two-panel detection plot.
The stack must be running before starting the evaluation.

---

## Optional metrics stack

Start Prometheus and cAdvisor:

```powershell
docker compose --profile metrics up -d
```

Prometheus is available at `http://localhost:9090`.

cAdvisor is available at `http://localhost:8081`.

Stop the optional services:

```powershell
docker compose --profile metrics down
```

---

## Useful commands

### Inspect service status

```powershell
docker compose ps
```

### View logs

```powershell
docker compose logs
docker compose logs -f detector
docker compose logs -f guard
docker compose logs -f victim
docker compose logs -f victim-exporter
```

### Inspect detector state

From PowerShell:

```powershell
Invoke-RestMethod http://localhost:9130/state
```

Or open:

```text
http://localhost:9130/state
```

### Inspect detector metrics

```text
http://localhost:9130/metrics
```

### Clear active mitigation

The guard control port is available only inside the Docker network. To clear
the blocklist from the host, use the detector's public API:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:9130/unmitigate
```

The dashboard **Clear mitigation** button performs the same action. The detector
normally performs source attribution and blocking automatically or through the
dashboard's per-attack mitigation buttons.

### Restart all core services

```powershell
docker compose restart
```

### Stop the lab

```powershell
docker compose down
```

This stops and removes the containers and project network.

### Remove containers and the lab log volume

```powershell
docker compose down -v
```

This deletes the shared victim-log volume. The Docker images remain cached.

---

## Tuning the detector

The detector environment variables are configured in `docker-compose.yml`:

| Variable | Default | Meaning |
|---|---:|---|
| `RAPID_RESET_RATE_THRESHOLD` | 50 | Client reset rate required for an alert |
| `MISMATCH_RATIO_THRESHOLD` | 3.0 | Backend mismatch ratio required for an alert |
| `EWMA_ALPHA` | 0.4 | EWMA smoothing; larger values react faster |
| `BLOCK_COOLDOWN` | 60 | Block duration in seconds |
| `AUTO_MITIGATE` | false | Blocks automatically when an alert fires |
| `POLL_INTERVAL` | 1.0 | Detector polling interval in seconds |

After changing values, recreate the detector:

```powershell
docker compose up -d --build detector
```

Use the evaluation data to choose thresholds that separate legitimate load
from attack traffic.

---

## Troubleshooting

### Docker is not running

Start Docker Desktop, wait for it to report that the engine is running, and
retry:

```powershell
docker info
docker compose ps
```

### Port already in use

The core lab publishes:

```text
8080  guard
8088  dashboard
9130  detector
```

Check processes or containers using those ports, stop the conflicting service,
and retry `docker compose up --build -d`.

### Dashboard cannot launch attacks

Confirm that:

- Docker Desktop is running.
- Linux containers are enabled.
- The dashboard container is running.
- The Docker socket is mounted.

Check:

```powershell
docker compose logs dashboard
docker compose ps dashboard
```

Then retry the dashboard button or use `docker compose run --rm attacker`.

### Windows cannot execute `scenario.sh`

Use one of these options:

1. Run it from Git Bash or WSL.
2. Run the equivalent PowerShell `docker compose run --rm attacker ...`
   command listed above.

Do not run a Bash script using Windows Command Prompt.

### Detector says `NORMAL` during an attack

Check logs and metrics:

```powershell
docker compose logs -f detector
Invoke-RestMethod http://localhost:9130/state
```

Common causes:

- The victim was not started successfully.
- The attacker could not reach the guard.
- The request target or primitive is incorrect.
- The detector baseline has not been reset.
- The attacker container is blocked or has stopped.

For a clean detector reset, use the dashboard **Clear mitigation** button or
send:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:9130/reset
```

### MadeYouReset does not trigger

Run the probe first:

```powershell
docker compose run --rm attacker madeyoureset --host guard --port 8080 --path "/?ms=500" --probe
```

Confirm that at least one primitive reports `SERVER RST_STREAM`.

The default sustained primitive is `zero-increment`.

### No data appears in the dashboard

Check all core services:

```powershell
docker compose ps
docker compose logs -f detector victim-exporter guard
```

Then verify:

```text
http://localhost:9130/state
```

The exporter is internal to the Docker network and is not published directly
to the host. Query its state through the detector API or container logs instead.

### Containers or images need to be rebuilt

After changing source files or Dockerfiles:

```powershell
docker compose down
docker compose up --build -d
```

To rebuild one service:

```powershell
docker compose up -d --build detector
```

---

## Security and safety

Before running the lab, review [docs/SAFETY.md](docs/SAFETY.md).

Important restrictions:

- Keep the lab on a private Docker network.
- Do not publish the dashboard beyond loopback.
- Do not expose Tomcat directly to the internet.
- Do not point the attacker at a public or third-party address.
- Use the lab only on systems you own or are authorized to test.
- Treat Tomcat 10.1.43 and the crafted-frame client as intentionally vulnerable
  tooling.

The target is pinned specifically for reproducibility. It is not a production
deployment or a hardened reverse proxy configuration.

---

## Documentation

- [docs/EVALUATION.md](docs/EVALUATION.md): scenario method and threshold selection
- [docs/MADEYOURESET.md](docs/MADEYOURESET.md): MadeYouReset implementation details
- [docs/SAFETY.md](docs/SAFETY.md): scope and safety restrictions
