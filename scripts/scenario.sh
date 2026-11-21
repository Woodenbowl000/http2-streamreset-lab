#!/usr/bin/env bash
# Run a lab scenario against the running stack. The attacker runs as a container
# so the guard sees it as a distinct source IP and can block it.
#
#   ./scripts/scenario.sh legit               [duration] [connections]
#   ./scripts/scenario.sh rapid-reset         [duration] [connections]
#   ./scripts/scenario.sh madeyoureset        [duration] [connections] [primitive]
#   ./scripts/scenario.sh madeyoureset-probe
#   ./scripts/scenario.sh idle                [duration]
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-}"
DUR="${2:-30}"
CONN="${3:-6}"
PRIM="${4:-zero-increment}"   # zero-increment | window-overflow | priority-length

if [[ -z "$MODE" ]]; then
  echo "usage: $0 {idle|legit|rapid-reset|madeyoureset|madeyoureset-probe} [duration] [connections] [primitive]"; exit 1
fi

case "$MODE" in
  rapid-reset)
    echo ">> Rapid Reset attack: ${CONN} connections for ${DUR}s"
    docker compose run --rm attacker rapid-reset --host guard --port 8080 \
      --path "/?ms=0" --duration "$DUR" --connections "$CONN" ;;
  legit)
    echo ">> Legitimate load: ${CONN} honest clients for ${DUR}s"
    docker compose run --rm attacker legit --host guard --port 8080 \
      --path "/?ms=200" --duration "$DUR" --connections "$CONN" ;;
  madeyoureset)
    echo ">> MadeYouReset attack: primitive=${PRIM}, ${CONN} connections for ${DUR}s"
    docker compose run --rm attacker madeyoureset --host guard --port 8080 \
      --path "/?ms=500" --duration "$DUR" --connections "$CONN" --primitive "$PRIM" ;;
  madeyoureset-probe)
    echo ">> MadeYouReset probe: which crafted frames make this Tomcat reset its own stream"
    docker compose run --rm attacker madeyoureset --host guard --port 8080 --path "/?ms=500" --probe ;;
  idle)
    echo ">> Idle baseline for ${DUR}s (no traffic)"
    docker compose run --rm attacker idle --duration "$DUR" ;;
  *)
    echo "unknown mode: $MODE"; exit 1 ;;
esac
