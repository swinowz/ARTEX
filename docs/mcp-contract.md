# MCP capability-server contract

Status: verified 2026-11-27, issue #13. Test: `server/mcp_contract_test.go`
(`TestMCPContractEndToEnd`, Streamable HTTP + stdio).

This is the contract a capability server must satisfy to be usable by ARTEX
workers. It is proven end to end with a real worker and a deterministic model
script; no core file is changed to add a server.

## 1. Registration

`POST /api/mcp` with a `db.MCPServer` JSON body:

```json
{
  "name": "mcp-nmap",
  "transport": "http",            // "http" | "sse" | "stdio"
  "url": "http://127.0.0.1:9000/mcp",
  "command": "",                  // stdio only
  "args": [],                     // stdio only
  "env": {},                      // http/sse: extra headers; stdio: env
  "enabled": true,
  "insecure": false,
  "timeout_seconds": 120
}
```

- `enabled` must be sent explicitly; the zero value is `false`.
- On a new *enabled* server, registration runs discovery synchronously (45 s
  bound) and caches the tool names. A discovery failure is logged and recorded
  in `last_connect_ok/err`, but `POST /api/mcp` still returns `200 {"id": N}`.
  Always verify the cache/health after registering.
- `env` is sealed at rest and masked on read. It doubles as HTTP headers for
  `http`/`sse`, so `{"Authorization":"Bearer …"}` is the supported auth shape.

Relevant code: `server/server_mgmt.go:1047` (`pgSaveMCP`),
`db/config.go:1005` (`SaveMCP`), `db/schema.sql` (`mcp_servers`,
`mcp_tools_cache`).

## 2. Discovery and cache

`discoverAndCacheMCP` connects, calls `tools/list`, stores `name` +
`description` in `mcp_tools_cache`, and updates health
(`server/mcpdiscover.go:82`).

- Only name and description are cached; the input schema is fetched live per
  run (`cl.Tools` in `server/assembly.go:104`).
- `GET /api/mcp/{id}/tools` returns the cached `{name, description}` list for
  the UI. `POST /api/mcp/{id}/refresh` re-discovers on demand.
- Startup fills the cache for enabled servers that have none
  (`discoverEmptyMCPsOnStartup`).

## 3. Visibility

Two independent conditions must both hold for a worker to see a server:

1. the server is `enabled`;
2. an `agent_visibility` row exists for `(agent=worker, kind=mcp, resource=id)`
   — set by `PUT /api/agents/{key}/visibility` or the resource-side toggle.

A server named in a visible skill's `mcps:` frontmatter is **skill-gated**: its
tools are deferred *and locked* until that skill is invoked. A directly visible,
non-gated server is deferred but unlocked from session start.

## 4. Worker assembly and deferred tools

`wireAgentAugment` (`server/assembly.go:32`) connects each visible server for
the run, wraps every tool as `mcp__<server>__<tool>`, appends the
untrusted-output note to its description, and returns `DeferredInfo`:

- `Deferred` — every MCP tool name; its schema is withheld from the model.
- `GlobalNames` — tools listed in the cached system-prompt block.
- `Unlock` — call gate seeded with the global names.

Consequences for capability servers:

- The model cannot call `mcp__server__tool` directly. It must call
  `SearchExtraTools {"query":"select:mcp__server__tool"}` to obtain the schema,
  then `ExecuteExtraTool {"tool_name":"…","params":{…}}` to invoke it.
- The schema returned by `SearchExtraTools` is exactly the server's
  `inputSchema`; it is validated before the call.
- Clients are per-run and closed by the augment cleanup; a stdio server is
  spawned again for the next run.

## 5. Tool result shape

The MCP server must answer `tools/call` with the standard content array:

```json
{"content": [{"type": "text", "text": "host=10.0.0.5 port=445 state=open"}],
 "isError": false}
```

- Only `text` blocks are concatenated; other block types are ignored.
- `isError: true` becomes a tool error result.
- Output is truncated/spilled through `actool.Capture` (session output limits).
- The model receives the text inside ARTEX's untrusted-output envelope
  (`<<<UNTRUSTED_OUTPUT …>>>`), i.e. as data, never instructions.

## 6. Persisting results

Capability servers do not need a reporter. The worker's native tools persist the
returned text:

- `record_fact` — observations and negative results. Batch shape:
  `{"facts":[{"summary","detail","evidence","confidence":"observed|inferred","source":"tool_output|target_response|third_party_intel|operator_input|inference","intent_id","asset_ids","tested_asset_ids"}]}`.
  `evidence` should quote the tool output; unmatched evidence is stored as
  `provenance=unverified` rather than discarded.
- `report_finding` — a vulnerability: `{"vulnclass","name","severity","summary","evidence","intent_id","asset_ids","traffic_refs","counterevidence","confidence_rationale"}`.
  Non-HTTP evidence is supported (#8); HTTP traffic bindings are optional and
  the finding stays visible without them.
- `insert_assets` / `ingest_*` — structured asset ingestion.

There is no tool named `observations`; observations are `record_fact` items.

## 7. Reproduce

```sh
export ARTEX_PG_DSN='postgres://USER:PASSWORD@127.0.0.1:PORT/DB?sslmode=disable'
go test ./server -run TestMCPContractEndToEnd -count=1 -v
```

The test asserts, for both transports:

1. registration through the authenticated API caches `scan_host`;
2. granting worker visibility surfaces `mcp__<server>__scan_host` in the
   assembled tool set, deferred and globally advertised, with the untrusted
   note;
3. a scripted worker discovers the schema, calls the tool, and receives the
   server text;
4. `record_fact` stores the text in the exploration graph;
5. `report_finding` records a finding from the same evidence.

## 8. Not covered here

- Model judgment/quality (the script is deterministic).
- Skill-gated servers (covered by `server/assembly_test.go` and
  `agent/deferred_test.go`).
- Legacy SSE transport (covered by `mcphttp/client_sse_test.go`).
- stdio inside the Docker sandbox (covered by `server/mcp_sandbox_test.go` and
  ADR-0007).
- Target scope enforcement for a server's own network operations — that is
  issue #14, and every capability server must integrate it rather than rely on
  this contract.

## 9. Checklist for a new capability server (#15+)

- [ ] One bounded operation set; no free-form `args`/`extra_args` passthrough.
- [ ] Returns text that quotes the raw tool output needed for evidence.
- [ ] An empty result means "not observed", never "no risk".
- [ ] Validates the mission manifest and target scope locally (#14).
- [ ] Ships fixture-based tests for success, empty, interrupted and malformed
      output.
- [ ] Registers in this contract's test shape; no `engine`, planner, worker-loop
      or Reporter change.
