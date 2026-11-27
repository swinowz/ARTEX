#!/usr/bin/env bash
# Opt-in rootless Docker-in-Docker proof. Starts only disposable containers.
# ARTEX_NESTED_TEST_IMAGE must name a local image; its immutable ID is used.
set -euo pipefail

cd "$(dirname "$0")/.."
image=${ARTEX_NESTED_TEST_IMAGE:?Set ARTEX_NESTED_TEST_IMAGE to a local image with sh, bash and python3}
options=$(docker info --format '{{json .SecurityOptions}}')
if [[ $options != *'"name=rootless"'* ]]; then
  echo 'The active Docker daemon must be rootless.' >&2
  exit 1
fi
image_id=$(docker image inspect "$image" --format '{{.Id}}')
if [[ ! $image_id =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo 'Could not resolve an immutable local image ID.' >&2
  exit 1
fi
socket=${ARTEX_ROOTLESS_DOCKER_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock}
if [[ ! -S $socket ]]; then
  echo 'Rootless Docker socket not found.' >&2
  exit 1
fi
socket=$(realpath -e "$socket")

proof_root=$(mktemp -d /tmp/artex-nested-proof.XXXXXXXX)
suffix=${proof_root##*.}
outer=artex-nested-server-$suffix
task_id=$((100000 + $(od -An -N4 -tu4 /dev/urandom)))
session_key=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
cleanup() {
  docker rm -f "$outer" "artex-task-$task_id" "artex-session-$session_key" >/dev/null 2>&1 || true
  rm -rf "$proof_root"
}
trap cleanup EXIT
mkdir -p "$proof_root/data" "$proof_root/skills"
printf 'skill=ok\n' > "$proof_root/skills/proof"
printf 'server-only\n' > "$proof_root/server-secret"
CGO_ENABLED=0 go test -c ./sandbox -o "$proof_root/nested.test"
chmod 0755 "$proof_root/nested.test"

docker_mount=()
if ! docker run --rm --network none --entrypoint /bin/sh "$image_id" -c 'command -v docker >/dev/null'; then
  docker_cli=${ARTEX_NESTED_DOCKER_CLI:-$(command -v docker)}
  docker_cli=$(realpath -e "$docker_cli")
  docker_mount=(--mount "type=bind,src=$docker_cli,dst=/usr/bin/docker,readonly")
fi

docker run --rm --name "$outer" --network none --user 0:0 \
  --security-opt=no-new-privileges \
  --mount "type=bind,src=$proof_root/nested.test,dst=/proof/nested.test,readonly" \
  --mount "type=bind,src=$proof_root/data,dst=/app/data" \
  --mount "type=bind,src=$proof_root/skills,dst=/app/skills,readonly" \
  --mount "type=bind,src=$proof_root/server-secret,dst=/app/server-secret,readonly" \
  --mount "type=bind,src=$socket,dst=/run/artex-docker.sock" \
  "${docker_mount[@]}" \
  --env DOCKER_HOST=unix:///run/artex-docker.sock \
  --env ARTEX_NESTED_TEST_IMAGE="$image_id" \
  --env ARTEX_NESTED_HOST_DATA="$proof_root/data" \
  --env ARTEX_NESTED_HOST_SKILLS="$proof_root/skills" \
  --env ARTEX_NESTED_TASK_ID="$task_id" \
  --env ARTEX_NESTED_SESSION_KEY="$session_key" \
  --entrypoint /proof/nested.test "$image_id" \
  -test.v -test.run '^TestNestedRootlessIntegration$'
