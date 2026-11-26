#!/usr/bin/env bash
# Backend hot reload without extra tools: rebuild and restart the Go backend when a
# .go file, go.mod or go.sum changes. Port defaults to 8790 so it does not clash with
# the SSH tunnel to the lab ARTEX (127.0.0.1:8787) or dev.sh (8787/8788).
#
# Needs a PostgreSQL DSN: set ARTEX_PG_DSN (see config.example.json), e.g.
#   export ARTEX_PG_DSN='postgres://artex:PASSWORD@127.0.0.1:5433/artex?sslmode=disable'
# Do not commit the DSN; keep it in your shell or in an untracked file.
set -uo pipefail
cd "$(dirname "$0")/.."
ADDR="${ARTEX_DEV_ADDR:-127.0.0.1:8790}"
BIN="$(mktemp -d)/artex-dev"
PID=""

stamp() { find . \( -path ./web -o -path ./.git -o -path ./node_modules \) -prune -o \
  \( -name '*.go' -o -name go.mod -o -name go.sum \) -print0 | xargs -0 stat -c '%Y %n' 2>/dev/null | sort | md5sum; }

start() {
  echo "[dev-watch] building…"
  if go build -o "$BIN" ./cmd/artex; then
    "$BIN" -addr "$ADDR" &
    PID=$!
    echo "[dev-watch] backend pid $PID on http://$ADDR"
  else
    echo "[dev-watch] build failed; waiting for next change"
    PID=""
  fi
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; PID=""; }
trap 'stop; exit 0' INT TERM EXIT

last="$(stamp)"
start
while true; do
  sleep 1
  now="$(stamp)"
  if [ "$now" != "$last" ]; then
    last="$now"
    echo "[dev-watch] change detected, restarting"
    stop
    start
  elif [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
    echo "[dev-watch] backend exited; fix the error and save a file to restart"
    PID=""
  fi
done
