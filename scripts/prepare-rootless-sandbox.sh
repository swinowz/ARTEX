#!/usr/bin/env bash
# Generate the opt-in Compose override inputs without starting any service.
# Usage: prepare-rootless-sandbox.sh IMAGE NETWORK HOST_DATA_DIR HOST_SKILL_DIR
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $# != 4 ]]; then
  echo "usage: $0 IMAGE NETWORK HOST_DATA_DIR HOST_SKILL_DIR" >&2
  exit 2
fi
image=$1
network=$2
data_dir=$3
skill_dir=$4

if [[ ! $network =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ || $network == host || $network == default ]]; then
  echo 'Provide an existing, explicitly named Docker network (or none).' >&2
  exit 2
fi
options=$(docker info --format '{{json .SecurityOptions}}')
if [[ $options != *'"name=rootless"'* ]]; then
  echo 'The active Docker daemon must be rootless.' >&2
  exit 1
fi
docker network inspect "$network" >/dev/null
image_id=$(docker image inspect "$image" --format '{{.Id}}')
if [[ ! $image_id =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo 'Could not resolve an immutable local image ID.' >&2
  exit 1
fi
if [[ ! -d $data_dir || ! -d $skill_dir ]]; then
  echo 'Host data and skill directories must already exist.' >&2
  exit 2
fi
data_dir=$(realpath -e "$data_dir")
skill_dir=$(realpath -e "$skill_dir")
socket=${ARTEX_ROOTLESS_DOCKER_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/docker.sock}
if [[ ! -S $socket ]]; then
  echo 'The rootless Docker socket does not exist.' >&2
  exit 1
fi
socket=$(realpath -e "$socket")

deploy_dir=${ARTEX_SANDBOX_DEPLOY_DIR:-keys/sandbox-deploy}
config_file=$deploy_dir/config.json
env_file=$deploy_dir/compose.env
if [[ -e $config_file || -e $env_file ]]; then
  echo "Refusing to overwrite $config_file or $env_file; remove them to regenerate." >&2
  exit 1
fi
umask 077
mkdir -p -m 0700 "$deploy_dir"
chmod 0700 "$deploy_dir"
config_file=$(realpath -m "$config_file")
env_file=$(realpath -m "$env_file")

# Compose's env-file parser and Docker's mount parser require these sources to be
# unambiguous. Normal shell path characters are otherwise preserved in the JSON.
for path in "$data_dir" "$skill_dir" "$socket" "$config_file"; do
  if [[ $path == *$'\n'* || $path == *$'\r'* || $path == *','* || $path == *'#'* || $path == *' '* || $path == *'='* ]]; then
    echo "Unsupported whitespace or mount separator in path: $path" >&2
    exit 2
  fi
done

python3 - "$config_file" "$image_id" "$network" "$data_dir" "$skill_dir" "${ARTEX_SANDBOX_BASE_CONFIG:-}" <<'PY'
import json
import sys

path, image, network, data, skills, base_path = sys.argv[1:]
config = {}
if base_path:
    with open(base_path, encoding="utf-8") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise ValueError("the base ARTEX config must be a JSON object")
config["sandbox"] = {
    "rootless": True,
    "image": image,
    "network": network,
    "uid": 0,
    "gid": 0,
    "host_data_dir": data,
    "host_skill_dir": skills,
}
with open(path, "x", encoding="utf-8") as stream:
    json.dump(config, stream, indent=2)
    stream.write("\n")
PY

cat > "$env_file" <<EOF
ARTEX_SANDBOX_HOST_DATA_DIR=$data_dir
ARTEX_SANDBOX_HOST_SKILL_DIR=$skill_dir
ARTEX_SANDBOX_CONFIG_FILE=$config_file
ARTEX_ROOTLESS_DOCKER_SOCKET=$socket
EOF

echo "Wrote $config_file and $env_file; no services were started."
echo "Validate with: docker compose --env-file .env --env-file $env_file -f docker-compose.yml -f docker-compose.sandbox.yml config --quiet"
