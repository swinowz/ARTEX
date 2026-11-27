# mcp-netexec and mcp-enum4linux — bounded AD/SMB inventory

Status: implemented, issue #17. Binaries `cmd/mcp-netexec`, `cmd/mcp-enum4linux`;
packages `mcps/netexec`, `mcps/enum4linux`; shared `mcps/adcore`; skill
`skills/ad-enum`; ADR-0010.

## Build

```sh
go build -o mcp-netexec ./cmd/mcp-netexec
go build -o mcp-enum4linux ./cmd/mcp-enum4linux
```

The Docker runtime image ships both binaries plus NetExec and enum4linux-ng in a
dedicated venv (`/opt/ad-tools`). In task sandbox mode a stdio MCP runs inside the
task container; the AD inventory servers are **not** supported there (the core
refuses credential injection in sandbox mode, and the sandbox images do not ship
the toolbox).

## Credentials: refs only

The operator does not provision anything for the tools. The core injects the
task's test accounts at spawn time when the server is flagged in the database
(`mcp_servers.task_credentials`, checkbox "Pass this task's test accounts at
spawn" in the MCP form):

- the accounts are `task_credentials` rows of the task (`save_task_credential`,
  or user-declared accounts), sealed at rest as before;
- they reach the child in one environment value, never in argv, never on disk;
- the model passes `credential_ref` = the row `id` it already sees in
  `list_task_credentials`;
- tool results show `{"ref": "12", "domain": "LAB.LOCAL"}` only — no username, no
  secret;
- a chat run (no task) and an empty list start the server in anonymous mode: only
  an omitted `credential_ref` works.

Sandbox mode is refused with `task credentials are not supported in sandbox mode`
(because `docker exec --env` would put the value in host-visible argv).

## Sign a mission

```sh
go run ./cmd/artex-scope keygen -dir keys
cat > ad-mission.json <<'EOF'
{
  "version": "artex.mission/v1",
  "mission_id": "lab-week-47",
  "server": "netexec",
  "issued_at": "2026-11-27T09:00:00Z",
  "not_before": "2026-11-27T09:00:00Z",
  "not_after": "2026-11-27T21:00:00Z",
  "allowed": [{"kind": "cidr", "value": "10.20.0.0/16"}],
  "excluded": [{"kind": "cidr", "value": "10.20.30.0/24"}],
  "operations": {"inventory": {"allowed": true}},
  "budgets": {"total_ops": 40, "per_server": {"netexec": 40}}
}
EOF
go run ./cmd/artex-scope sign -key keys/mission.key -in ad-mission.json -out keys/ad-mission.signed.json
```

One manifest per audience: sign a second one with `"server": "enum4linux"` and
`"operations": {"enumerate": {"allowed": true}}`.

## Register in ARTEX

```json
{
  "name": "netexec",
  "transport": "stdio",
  "command": "mcp-netexec",
  "args": [],
  "task_credentials": true,
  "env": {
    "ARTEX_SCOPE_MANIFEST": "/app/keys/ad-mission.signed.json",
    "ARTEX_SCOPE_PUBKEY": "/app/keys/mission.pub",
    "ARTEX_MCP_NETEXEC_ARTIFACT_DIR": "/app/data/mcp-netexec"
  },
  "enabled": true
}
```

Same shape for `enum4linux` (`command: mcp-enum4linux`,
`ARTEX_MCP_E4L_ARTIFACT_DIR`). Then grant both servers and the `ad-enum` skill to
the `worker` agent (`PUT /api/agents/worker/visibility`). Loading the skill
unlocks `mcp__netexec__inventory` and `mcp__enum4linux__enumerate`.

## Tools

### `inventory` (netexec)

| Input | Meaning |
|---|---|
| `target_refs` (required) | 1–16 hosts/IPs/CIDRs inside the scope; max 256 addresses per call. |
| `protocol` | `smb` (default) or `ldap`. |
| `credential_ref` | id of a task credential; omit for a null-session pass. |
| `profile_ref` | `inventory` (default) or `deep` (needs a credential). |

Checks: `inventory` → hosts, shares, users (SAMR/LDAP export), pass policy
(+ groups, computers, DC list over LDAP). `deep` → adds `--rid-brute 8192`,
`--loggedon-users` (SMB), `--find-delegation`, `--pso` (LDAP). Groups and
computers are LDAP-only in NetExec; the SMB result says so through `coverage`.

Fixed flags: `--no-progress --users-export <private>`, timeouts of 5 s per
protocol, and, with a credential, `-u <user> -p <file> --ufail-limit 1 -t 1`. The
password goes through a 0600 file, never argv; `-t 1` plus `--ufail-limit 1`
means at most one authentication attempt for the account, and a lockout stops the
run (`stopped.reason`). The NetExec workspace is created in a private temporary
directory and deleted before the result is returned: it stores the credential.

### `enumerate` (enum4linux-ng)

| Input | Meaning |
|---|---|
| `target_ref` (required) | One host or IP (a CIDR is refused). |
| `credential_ref` | Same as above; omit for a null session. |
| `profile_ref` | `inventory` (`-A`) or `deep` (`-A -Gm -R`). |

Output: the JSON export is parsed into the same result shape; `credentials` is
stripped from the export before it is stored, and the artifact is written `0600`.
Note the residual risk: enum4linux-ng takes the password on its own argv (and
passes it to `rpcclient -U user%pass`), so a same-uid process can read it while
the tool runs.

## Result

Both tools return the same shape:

- `domains` (policy and DCs when observed), `hosts`, `shares`, `objects`
  (users/groups/computers), `access` (admin relations);
- `coverage`: `collected`, `not_collected`, `permission_denied`, `unsupported`,
  `failed`, each gap with a reason;
- `candidates`: leads (`smb_signing_not_required`, `smb1_enabled`,
  `kerberos_delegation`) explicitly marked as *not* confirmed findings;
- `evidence`: verbatim (secret-masked) lines the model can quote with
  `record_fact`;
- `stopped`: `authentication_failed`, `account_locked_out`, `time_budget`,
  `no_data`;
- `artifacts`: redacted tool output under the artifact directory.

An empty list means "not observed", never "absent". A candidate is never a
finding: findings need bound, verified evidence (ADR-0004).

## Limits

- Read-only and closed: no spraying, relay, write, spidering, credential dumping,
  kerberoast/asreproast, AD CS change. The argument table has no passthrough.
- NetExec's workspace schema is asserted at read time; a schema change yields
  `failed{workspace_schema_unrecognized}` plus the raw log, never a silent empty
  result.
- One budget operation per `target_ref` (netexec) or per call (enum4linux), with
  a 10-minute wall clock.
- AD inventory inside a task sandbox container is not supported yet.

## Licence

NetExec is BSD-2-Clause, enum4linux-ng is GPLv3; both are invoked as separate
processes, exactly like nmap, so no code is linked into ARTEX (AGPL-3.0).
