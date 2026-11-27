# ADR-0009: Signed mission manifests for capability MCP servers

Status: accepted (2026-11-27) — issue #14.

## Context

Every capability server added to the general-pentest fork (#15–#27) performs
network operations from its own process. ARTEX's existing target gate
(`guard/guard.go`, `intercept/target_gate.go`) inspects tool calls at the
platform layer, but it depends on PostgreSQL and on heuristic target extraction.
An MCP server cannot import that stack offline, and a bare host name in a typed
argument (`{"domain":"example.com"}`) is not recognised as a target at all.
A server therefore needs its own enforceable, auditable scope decision, made
before its side effect, with the same mission the operator approved.

## Decision

Add a standalone package `scope/` (`github.com/Autumn-27/artex/scope`) and a
signing CLI `cmd/artex-scope`.

- **Format.** `artex.mission/v1`: one manifest per mission and per MCP server
  audience. It carries the validity window, allowed and excluded rules, an
  operation allow-list with per-operation approval/run limits, a signing-time
  budget split, approval mode and cleanup obligations.
- **Signature.** Ed25519 detached signature over the exact manifest bytes
  (canonical JSON produced by `scope.Sign`). Verification uses pinned public keys
  selected by `key_id`; the private key lives outside the repository (for
  example `keys/`, gitignored). HMAC is deliberately not supported: every server
  holding the shared secret could forge a mission.
- **Rules.** Allowed and excluded entries are `domain`, `ip` or `cidr`.
  A domain rule covers its subdomains; wildcards are refused. Exclusions win
  over every allow, regardless of specificity, and a target subnet that overlaps
  an exclusion is refused as a whole.
- **Network safety.** IPv4-mapped IPv6 is unmapped; IPv4 numeric forms are
  canonicalised. A domain target must present the addresses the caller will dial.
  The guard pins the first answer and refuses a later change (`SCOPE_DNS_CHANGED`).
  Each redirect hop is re-evaluated and a cross-host hop must be explicitly
  allowed by name.
- **Budget.** `total_ops` and `per_server` are fixed at signing time and must be
  coherent (the split cannot exceed the total). `MemoryLedger` is the reference
  implementation; a server may never fall back to the mission total. The split
  prevents one server from consuming another's allocation.
- **Fail closed.** `scope.FromEnv()` requires `ARTEX_SCOPE_MANIFEST` and
  `ARTEX_SCOPE_PUBKEY`. The explicit development escape
  `ARTEX_SCOPE_ALLOW_UNSCOPED=1` logs a warning and denies every operation; it
  never silently allows.

## Files

- `scope/target.go` — normalisation and matching primitives.
- `scope/manifest.go` — schema, canonical signing, envelope verification, key loading.
- `scope/guard.go` — `Guard.Check`/`Charge`, DNS pinning, redirects, `FromEnv`.
- `scope/budget.go` — ledger interface and the in-memory reference.
- `scope/scope_test.go` — the #14 acceptance matrix.
- `cmd/artex-scope` — `keygen`, `sign`, `verify`.
- `docs/mission-scope.md` — operator and integrator guide.

## Consequences

- A capability server has a small, dependency-free package to enforce mission
  scope and to report a stable `SCOPE_DENIED` code to the model.
- `intercept` keeps its own target normalisation for now. Moving it onto
  `scope` would be a core change with regression risk and is left as a follow-up
  (it needs its own ADR).
- The ARTEX-side `CoreTool` wrapper proposed in the design note is not part of
  this increment; the server-side check is the authoritative one. Defence in
  depth can be added when the first capability server lands (#15).
- Nothing here is an egress firewall. Native `Bash`, `shell_open`, `shell_send`,
  custom tools and a server that ignores this package bypass it; those remain
  covered by the platform hook and target gate, or by network isolation.
- Budgets are enforced per signed allocation inside each server; cross-server
  reconciliation in PostgreSQL is a follow-up audit feature, not live
  enforcement.

## Validation

`go test ./scope -race` passes the matrix: signature/tamper/audience, out-of-scope
before effect, exclusion under an allowed parent, IPv6, DNS change, redirect,
operation allow-list, run limit, time window, budget split and concurrency.
`cmd/artex-scope` keygen/sign/verify is exercised by hand in the operator guide.
