#!/usr/bin/env bash
# Opt-in full ARTEX startup proof using disposable rootless Docker resources.
# No Compose project, published port, existing database, or real credential.
set -euo pipefail

cd "$(dirname "$0")/.."
image=${ARTEX_FULL_PROOF_IMAGE:-artex:sandbox-local}
pg_image=${ARTEX_FULL_PROOF_PG_IMAGE:-postgres:16-alpine}
options=$(docker info --format '{{json .SecurityOptions}}')
if [[ $options != *'"name=rootless"'* ]]; then
  echo 'The active Docker daemon must be rootless.' >&2
  exit 1
fi
image_id=$(docker image inspect "$image" --format '{{.Id}}')
pg_image_id=$(docker image inspect "$pg_image" --format '{{.Id}}')
socket=${ARTEX_ROOTLESS_DOCKER_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock}
if [[ ! -S $socket ]]; then
  echo 'Rootless Docker socket not found.' >&2
  exit 1
fi
socket=$(realpath -e "$socket")

proof_root=$(mktemp -d /tmp/artex-full-proof.XXXXXXXX)
suffix=${proof_root##*.}
network=artex-full-proof-$suffix
postgres=artex-full-pg-$suffix
server=artex-full-server-$suffix
cleanup() {
  docker rm -f "$server" "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$proof_root"
}
trap cleanup EXIT
umask 077
mkdir -p "$proof_root/data" "$proof_root/keys"
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')

docker network create "$network" >/dev/null
ARTEX_SANDBOX_DEPLOY_DIR="$proof_root/deploy" \
  scripts/prepare-rootless-sandbox.sh "$image_id" "$network" \
  "$proof_root/data" "$PWD/skills" >/dev/null
docker run -d --rm --name "$postgres" --network "$network" \
  --env POSTGRES_USER=artex_proof --env POSTGRES_DB=artex_proof \
  --env POSTGRES_PASSWORD="$password" \
  --env POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  "$pg_image_id" >/dev/null

ready=0
for ((attempt=0; attempt<45; attempt++)); do
  if docker exec "$postgres" pg_isready -h 127.0.0.1 -U artex_proof -d artex_proof >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ $ready != 1 ]]; then
  echo 'Disposable PostgreSQL did not become ready.' >&2
  exit 1
fi

docker run -d --rm --name "$server" --network "$network" --user 0:0 \
  --security-opt=no-new-privileges \
  --mount "type=bind,src=$proof_root/data,dst=/app/data" \
  --mount "type=bind,src=$proof_root/keys,dst=/app/keys" \
  --mount "type=bind,src=$PWD/skills,dst=/app/skills" \
  --mount "type=bind,src=$proof_root/deploy/config.json,dst=/app/config.sandbox.json,readonly" \
  --mount "type=bind,src=$socket,dst=/run/artex-docker.sock" \
  --env ARTEX_CONFIG=/app/config.sandbox.json \
  --env ARTEX_JWT_KEY_DIR=/app/keys \
  --env DOCKER_HOST=unix:///run/artex-docker.sock \
  --env ARTEX_PG_HOST="$postgres" --env ARTEX_PG_PORT=5432 \
  --env ARTEX_PG_USER=artex_proof --env ARTEX_PG_DBNAME=artex_proof \
  --env ARTEX_PG_PASSWORD="$password" --env ARTEX_PG_SSLMODE=disable \
  --entrypoint /app/artex "$image_id" -addr 127.0.0.1:8787 -proxy '' >/dev/null

healthy=0
for ((attempt=0; attempt<60; attempt++)); do
  docker logs "$server" > "$proof_root/server.log" 2>&1 || true
  if rg -q '\[isolation\] self-test passed' "$proof_root/server.log" && \
     docker exec "$server" curl -fsS http://127.0.0.1:8787/api/health > "$proof_root/health.json" 2>/dev/null; then
    healthy=1
    break
  fi
  if [[ $(docker inspect "$server" --format '{{.State.Running}}' 2>/dev/null || true) != true ]]; then
    break
  fi
  sleep 1
done
if [[ $healthy != 1 ]]; then
  echo 'Full ARTEX image did not pass isolated startup.' >&2
  rg '\[config\]|\[isolation\]|\[sandbox\]|\[exec\]|open stores' "$proof_root/server.log" >&2 || true
  exit 1
fi

if ! rg -q '\[sandbox\].*use disposable containers' "$proof_root/server.log"; then
  echo 'ARTEX started without the configured task sandbox.' >&2
  rg '\[sandbox\]' "$proof_root/server.log" >&2 || true
  exit 1
fi
if ! docker exec "$server" docker info --format '{{json .SecurityOptions}}' | rg -q 'name=rootless'; then
  echo 'Root server cannot reach the rootless Docker daemon.' >&2
  exit 1
fi
if docker exec -u 10001:10001 "$server" docker info >/dev/null 2>&1; then
  echo 'Executor UID 10001 unexpectedly reached the Docker daemon.' >&2
  exit 1
fi
python3 - "$proof_root/health.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    health = json.load(stream)
if health.get("ok") is not True:
    raise SystemExit("GET /api/health did not report ok")
PY
echo 'PASS: full ARTEX startup, root/UID 10001 isolation, sandbox configuration, PostgreSQL and rootless Docker socket.'
