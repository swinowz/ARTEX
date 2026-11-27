# mcp-nmap — bounded network discovery

Status: implemented 2026-11-27, issue #15. Binary `cmd/mcp-nmap`, package
`mcps/nmap`, skill `skills/network-recon`.

## Build

```sh
go build -o mcp-nmap ./cmd/mcp-nmap
```

The Docker runtime image builds and ships `/usr/local/bin/mcp-nmap`. In task
sandbox mode a stdio MCP runs inside the task container, so the task image must
also contain `mcp-nmap` and `nmap`; the full ARTEX runtime image does.

## Sign a mission for the `nmap` audience

```sh
go run ./cmd/artex-scope keygen -dir keys
cat > nmap-mission.json <<'EOF'
{
  "version": "artex.mission/v1",
  "mission_id": "lab-week-47",
  "server": "nmap",
  "issued_at": "2026-11-27T09:00:00Z",
  "not_before": "2026-11-27T09:00:00Z",
  "not_after": "2026-11-27T21:00:00Z",
  "allowed": [{"kind": "cidr", "value": "10.20.0.0/16"}],
  "excluded": [{"kind": "cidr", "value": "10.20.30.0/24"}],
  "operations": {"discover": {"allowed": true}},
  "budgets": {"total_ops": 100, "per_server": {"nmap": 100}}
}
EOF
go run ./cmd/artex-scope sign -key keys/mission.key -in nmap-mission.json -out nmap-mission.signed.json
```

## Register in ARTEX

```json
{
  "name": "nmap",
  "transport": "stdio",
  "command": "mcp-nmap",
  "args": [],
  "env": {
    "ARTEX_SCOPE_MANIFEST": "/app/keys/nmap-mission.signed.json",
    "ARTEX_SCOPE_PUBKEY": "/app/keys/mission.pub",
    "ARTEX_MCP_NMAP_ARTIFACT_DIR": "/app/data/mcp-nmap"
  },
  "enabled": true
}
```

Then grant the server to the `worker` agent (`PUT /api/agents/worker/visibility`)
and make `skills/network-recon` visible to that agent. Loading the skill unlocks
`mcp__nmap__discover`; the worker discovers its schema with `SearchExtraTools`
and calls it through `ExecuteExtraTool` (see `docs/mcp-contract.md`).

Without the two `ARTEX_SCOPE_*` variables the server refuses to start. For a
development-only unguarded server, `ARTEX_SCOPE_ALLOW_UNSCOPED=1` logs a warning
and denies every scan.

## Tool

`discover`:

| Input | Meaning |
|---|---|
| `target` (required) | Host, IP or CIDR (max 4096 addresses) inside the signed scope. |
| `ports` | `common` (default), `top100`, `top1000`, or an explicit list/range, max 1024 ports. |
| `profile` | `connect` (default) or `syn`. |

There is no `extra_args` and the tool rejects unknown fields. nmap always runs
with `-Pn -n --max-retries 2 --host-timeout 15m -oX -`, a profile flag, the port
flags and the approved addresses. A name is resolved once, checked against the
manifest, and nmap receives the approved IPs, not the name.

The result is parsed JSON: hosts, states, services and an artifact path. The raw
XML is written `0600` under `ARTEX_MCP_NMAP_ARTIFACT_DIR` (created `0700`).
`observed=false` means "not observed", never "no risk". A banner is an
observation, not a finding.

## Tests

```sh
go test ./mcps/nmap -count=1
```

Fixtures cover success, empty, interrupted and malformed XML; the scope-denied
path asserts nmap never ran; argument tests assert the closed flag set and the
absence of free-form input; the DNS test asserts the pinned IP is scanned rather
than the name. A loopback test (skipped without `nmap`) runs a real scan against
a local listener.

## Limits

- TCP only in this increment; UDP and OS fingerprinting are not exposed.
- SYN scans require privileges; connect scans are the default.
- A scan is one budgeted operation regardless of host count; the signed
  per-server budget still bounds the mission.
- The server enforces the signed mission for its own operations. It is not an
  egress firewall for native Bash (see `docs/mission-scope.md`).

## Licence

nmap is GPLv2 with the NPSL exception; the runtime image already ships the
binary. `mcp-nmap` invokes it as a separate process and copies no nmap code, so
ARTEX stays AGPL-3.0. This is the same distribution path as the existing
`nmap` package in the image.
