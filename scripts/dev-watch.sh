#!/usr/bin/env bash
# Backend hot reload without extra tools: rebuild and restart the Go backend when a
# .go file, go.mod, go.sum, or an embedded asset (db/migrations/*.sql, db/schema.sql,
# knowledge/data/*.json) changes. Port defaults to 127.0.0.1:8790 so it does not
# clash with an SSH tunnel to a lab ARTEX (127.0.0.1:8787) or default dev.sh (8787/8788).
#
# Environment variables:
#   ARTEX_DEV_ADDR   backend listen address (default 127.0.0.1:8790)
#   ARTEX_DEV_PROXY  optional traffic proxy listen address (passed as -proxy)
#   ARTEX_PG_DSN     PostgreSQL DSN (see config.example.json / docker-compose.yml);
#                    never commit credentials — keep them in your shell or untracked config.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ADDR="${ARTEX_DEV_ADDR:-127.0.0.1:8790}"
PROXY="${ARTEX_DEV_PROXY:-}"
TMPDIR_WATCH="$(mktemp -d)"
BIN="${TMPDIR_WATCH}/artex-dev"
PID=""

stamp() { find . \( -path ./web -o -path ./.git -o -path ./node_modules \) -prune -o \
  \( -name '*.go' -o -name go.mod -o -name go.sum \
     -o -path './db/migrations/*.sql' -o -path './db/schema.sql' -o -path './knowledge/data/*.json' \) \
  -print0 | xargs -0 stat -c '%Y %n' 2>/dev/null | sort | md5sum; }

start() {
  echo "[dev-watch] building…"
  # -buildvcs=false: a git worktree or shallow clone can fail VCS stamping (git exit 128).
  if go build -buildvcs=false -o "$BIN" ./cmd/artex; then
    local -a args=(-addr "$ADDR")
    if [ -n "$PROXY" ]; then
      args+=(-proxy "$PROXY")
    fi
    "$BIN" "${args[@]}" &
    PID=$!
    echo "[dev-watch] backend pid $PID on http://$ADDR${PROXY:+ (proxy $PROXY)}"
  else
    echo "[dev-watch] build failed; waiting for next change"
    PID=""
  fi
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null || true; [ -n "$PID" ] && wait "$PID" 2>/dev/null || true; PID=""; }
cleanup() { stop; rm -rf "$TMPDIR_WATCH"; }
trap 'cleanup; exit 0' INT TERM EXIT

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
