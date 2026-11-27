# Secrets in the model context

Status: implemented for issue #11. Companion decision: `docs/adr/0011-auth-material-redaction.md`.

## What leaks, and where

Every model call sends the whole conversation to the provider: system prompt,
graph overview, tool results (including `Bash` output), recorded facts, the
transcript, and the `llm records` copy of the same bytes. Tool output is the
main entry point for real secrets: a `secretsdump`, an `impacket` ticket, a
read `.pem`, a `nxc` line.

Two controls run in this order, at one place: the outgoing HTTP request built by
norma, just before it is sent ([`agent/provider.go`](../agent/provider.go),
`quotaAwareTransport.RoundTrip`).

## 1. Credentials are references, never values

- Earlier work already injected `task_credentials` into opted-in MCP servers as
  a `ref` (`docs/mcp-ad-enum.md`).
- `list_task_credentials` and the worker's `graph_overview` now return
  `{ref, domain, username, source, has_password, note}`. The password column is
  never rendered: a tool that accepts `credential_ref` resolves it server-side
  (`mcp__netexec__inventory`, `mcp__enum4linux__enumerate`).
- The HTTP API keeps masking it for the console (`taskCredentialDTO`).

What remains: an account the agent itself creates knows the password it just
chose (it types it into `save_task_credential`); that JSON field is masked in the
outgoing request by the rule below, but the model still chose the value. That is
a new account, not a pre-existing secret.

## 2. Outgoing request redaction

`redact.Text` runs on the raw request body unless the task opts out. Because the
body is JSON, every pattern matches text that cannot contain an unescaped quote,
so the rewrite keeps the body valid (tested).

| Pattern | Replaced by |
|---|---|
| NT/LM hash pair `lm:nt` (32 hex `:` 32 hex) | `[REDACTED:ntlm-hash]` |
| PEM `-----BEGIN … PRIVATE KEY-----` … `-----END …` | `[REDACTED:private-key]` |
| JSON fields `password`/`passwd`/`pwd`/`secret`/`nthash`/`ntlm_hash`/`hash` | `"[REDACTED]"` |
| `DOMAIN\user:password` and `user@host:password` (value carrying a letter) | `[REDACTED:credential]` |
| base64/url-base64 run of 400+ characters (kirbi tickets, blobs) | `[REDACTED:blob]` |

The recorder snapshots the body **after** the rewrite, so the `llm records` row
holds the redacted bytes. Clean bodies are left byte-identical (no re-marshal,
no key reordering).

## 3. Per-task opt-out

`tasks.send_auth_material` (console: "Send authentication material to the model",
off by default, fixed at creation). When it is true, the filter is skipped for
that task's planner, worker and main-agent runs — needed only when a task must
reuse a hash or a ticket (pass-the-hash). The value is carried by
`agent.RunInfo.SendAuthMaterial` into the provider request context.

The read fails closed: a nil store, an unknown task or a database error keeps the
redaction on (the opposite of the coverage switch, which fails open).

## What this does not do

- It is a pattern filter, not a classifier: a secret shape it does not know gets
  through. Short Kerberos session keys (base64 under 400 characters), a
  hand-copied password inside prose, or a hash split across lines are examples.
- It redacts the **provider request**, not the local evidence. Bound evidence
  (ADR-0004) stays untouched, so `report_finding` verification is unaffected:
  the deterministic checker still compares a quote to the stored bytes.
- It does not touch the console, the database or the artifact directories; those
  keep what the operator needs.
- With `send_auth_material=true`, the material reaches the provider and the
  `llm records`. That is the point of the switch, and why it is off by default.

## Verifying

```sh
go test ./redact ./agent -run 'TestRedact|TestRoundTrip|TestCredentialViews' -count=1
```

- `TestRoundTripRedactsAuthMaterialBeforeSend`: an NT hash in the body never
  reaches the provider, and the `llmrec` capture holds the redacted bytes.
- `TestRoundTripSendsAuthMaterialWhenTaskOptedOut`: the opt-out leaves the body
  byte-identical.
- `TestCredentialViewsCarryOnlyAReference`: the worker context carries `ref`,
  never `password`.
