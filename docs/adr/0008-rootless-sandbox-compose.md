# ADR-0008: Opt-in rootless Docker deployment for task containers

Status: opt-in deployment recipe; full runtime-image and ARTEX startup proofs passed, mission dispatch unverified (2026-11-26), issue #33.

The standard `docker-compose.yml` keeps its current behavior. Operators who want
task containers use `docker-compose.sandbox.yml` as a second file. ARTEX itself
runs as root inside a rootless Docker container; its ordinary local agent
processes still drop to UID/GID 10001. The root server alone receives the
rootless daemon socket and Docker CLI. Task containers receive neither socket
nor server credentials. Their UID/GID is 0 inside the rootless daemon's user
namespace so they can write their host bind workspace; they are not host root.
The runtime image copies the Docker 29.2.1 CLI from a digest-pinned official
image. Debian bookworm's Docker CLI uses API 1.41 and was rejected by the
tested rootless daemon, which requires API 1.44 or newer.

The daemon resolves bind sources on the **host**. The override uses absolute host
paths for `data` and `skills`, and the generated config records those paths as
`sandbox.host_data_dir` and `sandbox.host_skill_dir`. ARTEX supplies `/app/data`
and `/app/skills` as the corresponding runtime paths. Each task gets only its
own workspace as a writable bind and the skills tree as a read-only bind.
The task image must be a local immutable ID containing the commands and
dependencies needed by configured Bash, MCP stdio, skill, and custom tools. The
full ARTEX runtime image has the bundled toolchain; a small proof image does not.

Prepare inputs in a dedicated checkout with dedicated `data/` and `keys/`:

```sh
mkdir -p -m 0700 data keys
# Build the full runtime image, and create an operator-controlled task network.
docker compose build artex
docker network create artex-task-egress
scripts/prepare-rootless-sandbox.sh artex:local artex-task-egress \
  "$(realpath data)" "$(realpath skills)"
docker compose --env-file .env --env-file keys/sandbox-deploy/compose.env \
  -f docker-compose.yml -f docker-compose.sandbox.yml config --quiet
```

The script verifies a rootless daemon, local image, network, directories and
socket, then writes an owner-only JSON config and Compose env file. It starts no
services. If an existing ARTEX JSON config supplies agent, MCP or skill settings,
set `ARTEX_SANDBOX_BASE_CONFIG` to its path before running the script; the
generated config preserves those settings and replaces only `sandbox`.
After reviewing the rendered Compose configuration and completing
application-level validation, deploy under a dedicated Compose project name:

```sh
docker compose --env-file .env --env-file keys/sandbox-deploy/compose.env \
  -p artex-sandbox -f docker-compose.yml -f docker-compose.sandbox.yml up -d
```

The project must use its own database volume and host data/key directories; do
not point a second project at an active deployment's files. A Docker bridge
does not itself enforce target scope, so configure the named task network's
egress for the engagement.

The root server's startup isolation self-test includes a real PostgreSQL
passwordless connection attempt. `scripts/isolated-isolation-proof.sh` proved
that UID 10001 could not authenticate to a disposable SCRAM-protected
PostgreSQL container while the root server could. The self-test also rejects a
Docker Unix socket that UID 10001 can connect to.

`ARTEX_NESTED_TEST_IMAGE=<local image> scripts/nested-sandbox-proof.sh` proved
the nested rootless Docker path with a small local image and the rebuilt full
ARTEX runtime image: a root server
container reached the daemon, task and session containers ran commands, the
read-only skill mount and stdio bridge worked, and the children could not see
a server-only file or the daemon socket. The script removes its disposable
containers and workspace. This tests the sandbox service and mount translation;
it does not start the full ARTEX application or prove every configured MCP,
skill, custom tool or target-network policy. The disposable PostgreSQL
self-test also passed inside the full image, and Compose rendered the override
with generated inputs. Validate an application task and the selected tool
configuration before enabling the opt-in deployment.

`scripts/full-app-sandbox-proof.sh` started the full `artex:sandbox-local` image
with disposable PostgreSQL, a private Docker network, and temporary data and
keys. The actual startup self-test reported success; `/api/health` returned
`ok`, the sandbox startup path initialized, root could reach the rootless Docker
daemon, and UID 10001 could not. The script published no port and removed its
containers, network and workspace. This verifies startup wiring in the full
image, including the PostgreSQL probe. A mission dispatched through ARTEX and
configured MCP, skill and custom-tool behavior remain to be tested.
