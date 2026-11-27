#!/usr/bin/env bash
# Dev mode: run the Go backend (with hot reload via scripts/dev-watch.sh) + traffic proxy
# together with the Next.js dev server (HMR + /api reverse-proxied to the backend).
#
# Configurable ports/addresses:
#   ARTEX_DEV_ADDR    backend listen address (default 127.0.0.1:8787)
#   ARTEX_DEV_PROXY   traffic proxy listen address (default 127.0.0.1:8788; empty disables -proxy)
#   ARTEX_WEB_PORT    Next.js dev server port (default 5173)
#   ARTEX_DEV_WATCH   1 (default) to auto-rebuild/restart backend on .go changes; 0 for plain go run
#   AUTOPENTEST_API   override frontend /api proxy target (defaults to http://<ARTEX_DEV_ADDR>)
#
# PostgreSQL: expects a running PostgreSQL instance (e.g. `docker compose up -d postgres`
# using docker-compose.yml) and ARTEX_PG_DSN or config.json configured outside git.
set -euo pipefail
cd "$(dirname "$0")"

ADDR="${ARTEX_DEV_ADDR:-127.0.0.1:8787}"
PROXY="${ARTEX_DEV_PROXY-127.0.0.1:8788}"
WEB_PORT="${ARTEX_WEB_PORT:-5173}"
WATCH="${ARTEX_DEV_WATCH:-1}"

if [ -z "${AUTOPENTEST_API:-}" ]; then
  case "$ADDR" in
    :*) AUTOPENTEST_API="http://127.0.0.1${ADDR}" ;;
    *)  AUTOPENTEST_API="http://${ADDR}" ;;
  esac
fi

# On exit, kill all child processes in this process group (backend + frontend).
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

if [ "$WATCH" = "1" ]; then
  ARTEX_DEV_ADDR="$ADDR" ARTEX_DEV_PROXY="$PROXY" bash ./scripts/dev-watch.sh &
else
  declare -a args=(-addr "$ADDR")
  if [ -n "$PROXY" ]; then
    args+=(-proxy "$PROXY")
  fi
  go run ./cmd/artex "${args[@]}" &
fi

# Frontend hot reload (Next.js dev server, /api reverse-proxied to AUTOPENTEST_API).
( cd web && AUTOPENTEST_API="$AUTOPENTEST_API" npm run dev -- -p "$WEB_PORT" ) &

echo "[dev] backend http://${ADDR#http://} (api=${AUTOPENTEST_API}) / proxy ${PROXY:-off} / frontend http://localhost:${WEB_PORT}  (Ctrl-C to exit)"
wait
