# ADR-0011: Authentication-material redaction at the provider boundary

Status: accepted (2026-11-27) — issue #11.

## Context

`task_credentials` are encrypted at rest, but the agent tools read them
decrypted: `list_task_credentials` and the worker's `graph_overview` put the
password in the model context, and every model call sends that context — and the
`llm records` copy of it — to the provider. Tool output is a second channel: a
lab run left NTDS-style hashes and tickets visible to the model through tool
results. There is no classification of what may leave the machine.

Issue #11 asks for four things: opaque references for secrets, redaction of tool
output before the model call, a per-task opt-out, and files staying on the
execution host.

## Decision

1. **Credentials surface as references only.** `list_task_credentials` and the
   graph overview return `{ref, domain, username, source, has_password, note}`;
   the value is resolved server-side by the tools that accept `credential_ref`
   (issue #17). `ref` is the task-credential row id.
2. **Redaction runs once, on the outgoing request body** in
   `quotaAwareTransport.RoundTrip` (`agent/provider.go`), before the recorder
   snapshots it. That is the only place that sees every source of model-visible
   text (system prompt, overview, tool results including Bash, facts, transcript)
   and it covers the `llm records` row by construction. A per-tool wrapper would
   miss `Bash`; redacting the transcript only would miss the system prompt.
3. **`redact.Text` is pattern-based**: NT/LM hash pairs, PEM private keys,
   password-like JSON fields, `domain\user:password` lines, and base64 runs of
   400+ characters (kiribi tickets, blobs). Patterns match spans with no
   unescaped quote, so the JSON body stays valid and clean bodies are left
   byte-identical.
4. **The per-task opt-out is `tasks.send_auth_material`** (default false, fixed at
   creation, console toggle). It travels as `agent.RunInfo.SendAuthMaterial` into
   the request context. The read fails closed: nil store, unknown task or query
   error keeps redaction on (the opposite of `coverage_enabled`, which fails
   open because it only affects tool availability).
5. **Evidence is out of scope.** Bound evidence (ADR-0004) is stored and read
   locally, so the deterministic finding verifier still compares quotes to the
   original bytes. Redaction happens on the way to the provider, never in the
   evidence store.

## Alternatives rejected

- **Redacting at each tool wrapper**: `Bash` (the largest leak channel) is a
  norma-built tool, and future tools would have to remember to wrap.
- **Redacting the conversation before marshalling**: requires reaching into
  norma's request builder; the body hook needs no such change.
- **Storing a sealed copy of the raw request in `llm records`**: keeps the leak
  in the database for whoever reads records, and the redacted copy is enough to
  debug a provider exchange.
- **Server-side password generation** in `save_task_credential` to hide the
  agent-chosen value: breaks the "register the account on the target" flow, where
  the agent needs the value it is about to set. The JSON rule masks it in the
  request instead.

## Consequences

- A worker still receives `ref`, `username`, `domain`; it can no longer type a
  stored password into `Bash`. Authenticated non-MCP work must go through a tool
  that accepts `credential_ref`, or the operator sets `send_auth_material=true`.
- Known gaps (documented in `docs/secrets-in-context.md`): unknown secret shapes,
  short base64 keys, secrets embedded in prose, and the opt-out path.
- `llm records` now store the redacted body; the pre-existing rows are unchanged.

## Files

- `redact/` (filter and tests).
- `agent/provider.go` (`redactAuthMaterial`), `agent/runinfo.go`,
  `agent/worker.go`, `agent/planner.go`, `agent/mainagent.go`.
- `agent/tools_creds.go` (reference-only views).
- `db/schema.sql`, `db/tasks.go`, `db/task_scope.go`,
  `db/task_archives_restore.go`, `server/server.go`, `server/dto.go`,
  `server/manager.go`, console create-task form.
- `docs/secrets-in-context.md`.
