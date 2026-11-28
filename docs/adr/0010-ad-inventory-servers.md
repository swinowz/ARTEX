# ADR-0010: AD inventory servers and per-run task credentials

Status: accepted (2026-11-27) — issue #17.

## Context

Issue #17 adds a Windows/Samba and Active Directory inventory capability:
`mcp-netexec` (`inventory`) and `mcp-enum4linux` (`enumerate`), plus the
`ad-enum` skill. The contract requires that a tool return domains, shares,
objects and access results with an explicit coverage split, and that **credentials
never appear in a tool result** — only a reference.

NetExec and enum4linux-ng both handle real accounts, and both are careless about
them: NetExec writes the plaintext password into its sqlite workspace and prints
it in the success line, and enum4linux-ng writes `credentials.password` into its
JSON export. A capability server therefore needs a credential source that never
passes through the model, and a way to keep the tools' own credential stores from
outliving the call.

## Decision

1. **Credentials are injected by the core, per run.** `mcp_servers` gains a
   `task_credentials` boolean (schema.sql `ADD COLUMN IF NOT EXISTS`, exposed in
   the MCP form). When it is set, `connectMCPForRun` resolves the task's
   `task_credentials` (already sealed at rest), serialises `{ref, domain,
   username, kind, secret}` and adds it to the child environment as
   `ARTEX_TASK_CREDENTIALS`. The model only sees the `ref` (the row id from
   `list_task_credentials`).
   - Nothing is written to disk, and the value never reaches the server's argv.
   - A chat run (no task) starts the server in anonymous mode.
   - Sandbox mode is refused: there the environment becomes `docker exec --env`
     argv, readable by any process of the same uid on the host, and the sandbox
     images do not ship the toolbox.
   - The unsealed value in the child environment is readable by a same-uid
     process, an existing property of the credential tools (#11). A broker with
     `SO_PEERCRED` or a restricted database role is the upgrade path; not this
     increment.
2. **No credential store of our own.** The list is loaded at spawn and held in
   memory for the run. `mcps/adcore` only parses it and answers `Get(ref)`.
3. **NetExec's workspace is ephemeral.** `NXC_PATH` points into a private
   `MkdirTemp` directory (0700) that is removed before the result is returned;
   `nxc.conf` sets `audit_mode = True`, and the password is handed over in a 0600
   file (`-p <path>`) rather than on argv. There is no at-rest database to
   encrypt because there is no at-rest database.
4. **enum4linux-ng's export is redacted.** The `credentials` key is deleted before
   the JSON is stored or returned; the artifact is written 0600. Its argv exposure
   is documented as a residual risk (upstream has no credential-file option).
5. **Coverage is explicit.** Both servers return `collected`, `not_collected`,
   `permission_denied`, `unsupported` and `failed`, each with a reason; a candidate
   (`smb_signing_not_required`, `kerberos_delegation`, …) is labelled as not a
   finding and stays `inferred` in the exploration graph.
6. **Bounded authentication.** With a credential the tools run one attempt for the
   account (`--ufail-limit 1 -t 1`) and report `stopped.reason =
   authentication_failed | account_locked_out`. There is no spraying: the skill
   forbids it and the closed argument table cannot express it.

## Files

- `db/schema.sql`, `db/config.go`, `server/server_mgmt.go` — `task_credentials`
  column and API.
- `server/mcpdiscover.go` — `connectMCPEnv`, `connectMCPForRun`,
  `withTaskCredentials`; `server/assembly.go` passes `pg.TaskCredentials`.
- `mcps/adcore` — credential envelope, coverage taxonomy, artifact writing,
  redaction, shared result types.
- `mcps/mcpserver` — the stdio JSON-RPC loop extracted from `mcps/nmap`.
- `mcps/netexec`, `mcps/enum4linux`, `cmd/mcp-netexec`, `cmd/mcp-enum4linux`.
- `skills/ad-enum/SKILL.md`, `docs/mcp-ad-enum.md`, `Dockerfile`, CI list,
  `docs/non-regression.md`.

## Consequences

- A capability server that needs accounts opts in with one boolean; no operator
  provisioning step, and no secret in the model's context through the tool.
- `list_task_credentials` still returns passwords to the model (pre-existing,
  #11). This ADR does not fix that, and the skill tells the worker to use the id
  and never quote the password.
- The netexec result depends on NetExec's sqlite workspace schema; the reader
  asserts the columns it needs and reports `workspace_schema_unrecognized`
  instead of returning an empty inventory.
- AD inventory is not available in task sandbox mode until a sandbox image ships
  the toolbox and the credential channel is revisited.
