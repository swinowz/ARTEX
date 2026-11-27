#!/usr/bin/env bash
# Prove root-server / executor-UID isolation against disposable PostgreSQL.
# Uses only new, uniquely named Docker resources; never invokes Compose.
set -euo pipefail

cd "$(dirname "$0")/.."

security_options=$(docker info --format '{{json .SecurityOptions}}')
if [[ "$security_options" != *'"name=rootless"'* ]]; then
  echo 'The active Docker daemon is not rootless.' >&2
  exit 1
fi

pg_image=${ARTEX_PROOF_PG_IMAGE:-postgres:16-alpine}
test_image=${ARTEX_PROOF_TEST_IMAGE:-python:3.12-slim}
pg_image_id=$(docker image inspect "$pg_image" --format '{{.Id}}')
test_image_id=$(docker image inspect "$test_image" --format '{{.Id}}')
proof_dir=$(mktemp -d /tmp/artex-isolation-proof.XXXXXXXX)
suffix=$(basename "$proof_dir" | sed 's/^artex-isolation-proof\.//')
network="artex-isolation-proof-$suffix"
postgres="artex-isolation-pg-$suffix"
cleanup() {
  docker rm -f "$postgres" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$proof_dir"
}
trap cleanup EXIT

go test -c ./server -o "$proof_dir/isolation.test"
chmod 0755 "$proof_dir" "$proof_dir/isolation.test"
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
docker network create "$network" >/dev/null
docker run -d --rm --name "$postgres" --network "$network" \
  --env POSTGRES_USER=artex_proof --env POSTGRES_DB=artex_proof \
  --env POSTGRES_PASSWORD="$password" \
  --env POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
  "$pg_image_id" >/dev/null

ready=0
for ((attempt=0; attempt<30; attempt++)); do
  if docker exec "$postgres" pg_isready -U artex_proof -d artex_proof >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo 'Disposable PostgreSQL did not become ready.' >&2
  exit 1
fi

docker run --rm --network "$network" --user 0:0 \
  --security-opt=no-new-privileges \
  --mount "type=bind,src=$proof_dir/isolation.test,dst=/proof/isolation.test,readonly" \
  --env "ARTEX_ISOLATION_PROOF_DSN=postgres://artex_proof:$password@$postgres:5432/artex_proof?sslmode=disable" \
  --entrypoint /proof/isolation.test "$test_image_id" -test.v -test.run '^TestIsolationSelfTest(WithPostgres|DetectsDockerSocketAsRoot)$'

echo 'PASS: root server, executor UID 10001, and SCRAM-protected PostgreSQL on an isolated rootless Docker network.'
